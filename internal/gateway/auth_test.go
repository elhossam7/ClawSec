package gateway

import (
	"database/sql"
	"encoding/base32"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func setupAuthTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	tables := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			totp_secret TEXT,
			role TEXT NOT NULL DEFAULT 'viewer',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_login DATETIME
		)`,
	}
	for _, stmt := range tables {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("create table: %v", err)
		}
	}
	return db
}

// ---------------------------------------------------------------------------
// AuthManager basics
// ---------------------------------------------------------------------------

func TestEnsureDefaultAdmin(t *testing.T) {
	db := setupAuthTestDB(t)
	am := NewAuthManager(db)

	created, err := am.EnsureDefaultAdmin()
	if err != nil {
		t.Fatalf("EnsureDefaultAdmin: %v", err)
	}
	if !created {
		t.Error("expected default admin to be created")
	}

	// Calling again should not create another.
	created2, err := am.EnsureDefaultAdmin()
	if err != nil {
		t.Fatalf("EnsureDefaultAdmin (2nd): %v", err)
	}
	if created2 {
		t.Error("expected no creation on second call")
	}
}

func TestAuthenticate_ValidCredentials(t *testing.T) {
	db := setupAuthTestDB(t)
	am := NewAuthManager(db)
	am.EnsureDefaultAdmin()

	session, err := am.Authenticate("admin", "sentinel", "127.0.0.1")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if session == nil {
		t.Fatal("expected session, got nil")
	}
	if session.Username != "admin" {
		t.Errorf("Username = %q, want admin", session.Username)
	}
	if session.Token == "" {
		t.Error("expected non-empty token")
	}
	if session.CSRFToken == "" {
		t.Error("expected non-empty CSRF token")
	}
}

func TestAuthenticate_InvalidPassword(t *testing.T) {
	db := setupAuthTestDB(t)
	am := NewAuthManager(db)
	am.EnsureDefaultAdmin()

	_, err := am.Authenticate("admin", "wrongpassword", "127.0.0.1")
	if err == nil {
		t.Error("expected error for wrong password")
	}
}

func TestAuthenticate_InvalidUsername(t *testing.T) {
	db := setupAuthTestDB(t)
	am := NewAuthManager(db)
	am.EnsureDefaultAdmin()

	_, err := am.Authenticate("nonexistent", "sentinel", "127.0.0.1")
	if err == nil {
		t.Error("expected error for nonexistent user")
	}
}

func TestAuthenticate_RateLimiting(t *testing.T) {
	db := setupAuthTestDB(t)
	am := NewAuthManager(db)
	am.maxLoginAttempts = 2
	am.lockoutDuration = 30 * time.Second // Long enough that bcrypt cost won't expire it
	am.EnsureDefaultAdmin()

	// Exhaust rate limit (2 failed attempts to record, then 3rd is blocked).
	for i := 0; i < 2; i++ {
		am.Authenticate("admin", "wrong", "10.0.0.1")
	}

	// Next attempt should be rate limited even with correct password.
	_, err := am.Authenticate("admin", "sentinel", "10.0.0.1")
	if err == nil {
		t.Error("expected rate limit error")
	}

	// Different IP should NOT be rate-limited.
	session, err := am.Authenticate("admin", "sentinel", "10.0.0.2")
	if err != nil {
		t.Fatalf("expected success from different IP: %v", err)
	}
	if session == nil {
		t.Fatal("expected session from different IP")
	}
}

func TestValidateSession(t *testing.T) {
	db := setupAuthTestDB(t)
	am := NewAuthManager(db)
	am.EnsureDefaultAdmin()

	session, _ := am.Authenticate("admin", "sentinel", "127.0.0.1")

	// Valid session.
	s, ok := am.ValidateSession(session.Token)
	if !ok || s == nil {
		t.Error("expected valid session")
	}

	// Invalid token.
	_, ok = am.ValidateSession("nonexistent-token")
	if ok {
		t.Error("expected invalid for nonexistent token")
	}
}

func TestValidateCSRF(t *testing.T) {
	db := setupAuthTestDB(t)
	am := NewAuthManager(db)
	am.EnsureDefaultAdmin()

	session, _ := am.Authenticate("admin", "sentinel", "127.0.0.1")

	if !am.ValidateCSRF(session.Token, session.CSRFToken) {
		t.Error("expected valid CSRF")
	}
	if am.ValidateCSRF(session.Token, "wrong-csrf") {
		t.Error("expected invalid CSRF for wrong token")
	}
	if am.ValidateCSRF("wrong-session", session.CSRFToken) {
		t.Error("expected invalid CSRF for wrong session")
	}
}

func TestDestroySession(t *testing.T) {
	db := setupAuthTestDB(t)
	am := NewAuthManager(db)
	am.EnsureDefaultAdmin()

	session, _ := am.Authenticate("admin", "sentinel", "127.0.0.1")
	am.DestroySession(session.Token)

	_, ok := am.ValidateSession(session.Token)
	if ok {
		t.Error("expected session to be destroyed")
	}
}

func TestChangePassword(t *testing.T) {
	db := setupAuthTestDB(t)
	am := NewAuthManager(db)
	am.EnsureDefaultAdmin()

	// Change password.
	err := am.ChangePassword("admin", "newpassword123")
	if err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	// Old password should fail.
	_, err = am.Authenticate("admin", "sentinel", "127.0.0.1")
	if err == nil {
		t.Error("expected old password to fail")
	}

	// New password should work.
	session, err := am.Authenticate("admin", "newpassword123", "127.0.0.1")
	if err != nil {
		t.Fatalf("Auth with new password: %v", err)
	}
	if session == nil {
		t.Fatal("expected session with new password")
	}
}

func TestChangePassword_TooShort(t *testing.T) {
	db := setupAuthTestDB(t)
	am := NewAuthManager(db)
	am.EnsureDefaultAdmin()

	err := am.ChangePassword("admin", "short")
	if err == nil {
		t.Error("expected error for short password")
	}
}

func TestIsDefaultPassword(t *testing.T) {
	db := setupAuthTestDB(t)
	am := NewAuthManager(db)
	am.EnsureDefaultAdmin()

	if !am.IsDefaultPassword("admin") {
		t.Error("expected default password to be detected")
	}

	am.ChangePassword("admin", "newpassword123")

	if am.IsDefaultPassword("admin") {
		t.Error("expected default password to no longer be detected")
	}
}

// ---------------------------------------------------------------------------
// TOTP 2FA
// ---------------------------------------------------------------------------

func TestGenerateTOTPSecret(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if len(secret) < 20 {
		t.Errorf("expected secret length >= 20, got %d", len(secret))
	}

	// Should be unique.
	secret2, _ := GenerateTOTPSecret()
	if secret == secret2 {
		t.Error("expected unique secrets")
	}
}

func TestGenerateHOTP(t *testing.T) {
	// RFC 4226 Appendix D test vector — secret = "12345678901234567890"
	key := []byte("12345678901234567890")
	expected := []string{
		"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489",
	}

	for i, want := range expected {
		got := generateHOTP(key, uint64(i), 6)
		if got != want {
			t.Errorf("HOTP(counter=%d) = %s, want %s", i, got, want)
		}
	}
}

func TestVerifyTOTP_CurrentCode(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP" // Known test secret
	now := time.Unix(1234567890, 0)

	// Generate a valid code for this exact time.
	code := generateTOTPCode(t, secret, now)

	if !verifyTOTP(secret, code, now, 1) {
		t.Errorf("expected valid TOTP for code %s at time %v", code, now)
	}
}

func TestVerifyTOTP_SkewWindow(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	now := time.Unix(1234567890, 0)

	// Code from 30 seconds ago should still be valid (within skew=1).
	past := now.Add(-30 * time.Second)
	pastCode := generateTOTPCode(t, secret, past)

	if !verifyTOTP(secret, pastCode, now, 1) {
		t.Errorf("expected TOTP from T-30s to be valid with skew=1")
	}

	// Code from 90 seconds ago should be invalid.
	farPast := now.Add(-90 * time.Second)
	farPastCode := generateTOTPCode(t, secret, farPast)

	if verifyTOTP(secret, farPastCode, now, 1) {
		t.Errorf("expected TOTP from T-90s to be invalid with skew=1")
	}
}

func TestVerifyTOTP_InvalidCode(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	if verifyTOTP(secret, "000000", time.Now(), 1) {
		// Extremely unlikely to collide with current code.
		t.Log("warning: 000000 matched (very unlikely)")
	}
	if verifyTOTP(secret, "abc", time.Now(), 1) {
		t.Error("expected invalid for non-numeric code")
	}
}

func TestVerifyTOTP_InvalidSecret(t *testing.T) {
	if verifyTOTP("!!!invalid-base32!!!", "123456", time.Now(), 1) {
		t.Error("expected false for invalid secret")
	}
}

func TestEnableTOTP(t *testing.T) {
	db := setupAuthTestDB(t)
	am := NewAuthManager(db)
	am.EnsureDefaultAdmin()

	secret, uri, err := am.EnableTOTP("admin")
	if err != nil {
		t.Fatalf("EnableTOTP: %v", err)
	}
	if secret == "" {
		t.Error("expected non-empty secret")
	}
	if uri == "" {
		t.Error("expected non-empty URI")
	}
	if !am.HasTOTP("admin") {
		t.Error("expected HasTOTP to return true after enable")
	}
}

func TestDisableTOTP(t *testing.T) {
	db := setupAuthTestDB(t)
	am := NewAuthManager(db)
	am.EnsureDefaultAdmin()

	am.EnableTOTP("admin")
	if err := am.DisableTOTP("admin"); err != nil {
		t.Fatalf("DisableTOTP: %v", err)
	}
	if am.HasTOTP("admin") {
		t.Error("expected HasTOTP to return false after disable")
	}
}

func TestAuthenticateWithTOTP(t *testing.T) {
	db := setupAuthTestDB(t)
	am := NewAuthManager(db)
	am.EnsureDefaultAdmin()

	// Enable TOTP.
	secret, _, _ := am.EnableTOTP("admin")

	// Authenticate without TOTP code should require it.
	_, err := am.AuthenticateWithTOTP("admin", "sentinel", "", "127.0.0.1")
	if err == nil || err.Error() != "totp_required" {
		t.Errorf("expected totp_required, got %v", err)
	}

	// Authenticate with valid TOTP code.
	code := generateTOTPCode(t, secret, time.Now())
	session, err := am.AuthenticateWithTOTP("admin", "sentinel", code, "127.0.0.1")
	if err != nil {
		t.Fatalf("AuthenticateWithTOTP: %v", err)
	}
	if session == nil {
		t.Fatal("expected session")
	}

	// Authenticate with wrong TOTP code.
	_, err = am.AuthenticateWithTOTP("admin", "sentinel", "000000", "127.0.0.2")
	if err == nil {
		t.Error("expected error for wrong TOTP code")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// generateTOTPCode generates the expected TOTP code for a given secret and time.
func generateTOTPCode(t *testing.T, secret string, now time.Time) string {
	t.Helper()

	// Decode base32 secret.
	cleaned := strings.TrimRight(strings.ToUpper(secret), "=")
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(cleaned)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	counter := uint64(now.Unix() / 30)
	return generateHOTP(key, counter, 6)
}
