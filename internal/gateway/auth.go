package gateway

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Session represents an authenticated user session.
type Session struct {
	Token     string
	Username  string
	Role      string
	CSRFToken string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// AuthManager manages user authentication, sessions, and CSRF tokens.
type AuthManager struct {
	db       *sql.DB
	sessions map[string]*Session // token → session
	mu       sync.RWMutex

	// Login rate limiting: IP → (attempts, lastAttempt)
	loginAttempts map[string]*rateLimitEntry
	rateMu        sync.Mutex

	sessionTTL       time.Duration
	maxLoginAttempts int
	lockoutDuration  time.Duration
}

type rateLimitEntry struct {
	attempts    int
	lastAttempt time.Time
}

// NewAuthManager creates a new authentication manager.
func NewAuthManager(db *sql.DB) *AuthManager {
	am := &AuthManager{
		db:               db,
		sessions:         make(map[string]*Session),
		loginAttempts:    make(map[string]*rateLimitEntry),
		sessionTTL:       8 * time.Hour,
		maxLoginAttempts: 5,
		lockoutDuration:  15 * time.Minute,
	}

	// Start session cleanup goroutine.
	go am.cleanupLoop()

	return am
}

// EnsureDefaultAdmin creates the default admin user if no users exist.
// Returns true if a default user was created (first-run scenario).
func (am *AuthManager) EnsureDefaultAdmin() (bool, error) {
	var count int
	if err := am.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return false, fmt.Errorf("checking user count: %w", err)
	}
	if count > 0 {
		return false, nil
	}

	hash, err := bcrypt.GenerateFromPassword([]byte("sentinel"), bcrypt.DefaultCost)
	if err != nil {
		return false, fmt.Errorf("hashing default password: %w", err)
	}

	_, err = am.db.Exec(
		`INSERT INTO users (id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)`,
		"usr_default_admin", "admin", string(hash), "admin", time.Now(),
	)
	if err != nil {
		return false, fmt.Errorf("creating default admin: %w", err)
	}

	return true, nil
}

// Authenticate verifies credentials and returns a session if valid.
func (am *AuthManager) Authenticate(username, password, remoteAddr string) (*Session, error) {
	// Check rate limit.
	if am.isRateLimited(remoteAddr) {
		return nil, fmt.Errorf("too many failed attempts, try again later")
	}

	// Look up user.
	var passwordHash, role string
	err := am.db.QueryRow(
		"SELECT password_hash, role FROM users WHERE username = ?", username,
	).Scan(&passwordHash, &role)
	if err == sql.ErrNoRows {
		am.recordFailedAttempt(remoteAddr)
		return nil, fmt.Errorf("invalid credentials")
	}
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}

	// Verify password.
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		am.recordFailedAttempt(remoteAddr)
		return nil, fmt.Errorf("invalid credentials")
	}

	// Clear rate limit on success.
	am.clearAttempts(remoteAddr)

	// Update last_login.
	am.db.Exec("UPDATE users SET last_login = ? WHERE username = ?", time.Now(), username)

	// Create session.
	session, err := am.createSession(username, role)
	if err != nil {
		return nil, fmt.Errorf("creating session: %w", err)
	}

	return session, nil
}

// ValidateSession checks if a session token is valid and returns the session.
func (am *AuthManager) ValidateSession(token string) (*Session, bool) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	session, ok := am.sessions[token]
	if !ok {
		return nil, false
	}
	if time.Now().After(session.ExpiresAt) {
		return nil, false
	}
	return session, true
}

// ValidateCSRF checks if a CSRF token is valid for the given session.
func (am *AuthManager) ValidateCSRF(sessionToken, csrfToken string) bool {
	am.mu.RLock()
	defer am.mu.RUnlock()

	session, ok := am.sessions[sessionToken]
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(session.CSRFToken), []byte(csrfToken)) == 1
}

// DestroySession removes a session (logout).
func (am *AuthManager) DestroySession(token string) {
	am.mu.Lock()
	defer am.mu.Unlock()
	delete(am.sessions, token)
}

// ChangePassword updates a user's password.
func (am *AuthManager) ChangePassword(username, newPassword string) error {
	if len(newPassword) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	result, err := am.db.Exec("UPDATE users SET password_hash = ? WHERE username = ?", string(hash), username)
	if err != nil {
		return fmt.Errorf("updating password: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("user %q not found", username)
	}
	return nil
}

// IsDefaultPassword checks if the user still has the default "sentinel" password.
func (am *AuthManager) IsDefaultPassword(username string) bool {
	var hash string
	err := am.db.QueryRow("SELECT password_hash FROM users WHERE username = ?", username).Scan(&hash)
	if err != nil {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte("sentinel")) == nil
}

// --- Internal helpers ---

func (am *AuthManager) createSession(username, role string) (*Session, error) {
	token, err := generateToken(32)
	if err != nil {
		return nil, err
	}
	csrfToken, err := generateToken(32)
	if err != nil {
		return nil, err
	}

	session := &Session{
		Token:     token,
		Username:  username,
		Role:      role,
		CSRFToken: csrfToken,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(am.sessionTTL),
	}

	am.mu.Lock()
	am.sessions[token] = session
	am.mu.Unlock()

	return session, nil
}

func (am *AuthManager) isRateLimited(ip string) bool {
	am.rateMu.Lock()
	defer am.rateMu.Unlock()

	entry, ok := am.loginAttempts[ip]
	if !ok {
		return false
	}

	// Reset if lockout period has passed.
	if time.Since(entry.lastAttempt) > am.lockoutDuration {
		delete(am.loginAttempts, ip)
		return false
	}

	return entry.attempts >= am.maxLoginAttempts
}

func (am *AuthManager) recordFailedAttempt(ip string) {
	am.rateMu.Lock()
	defer am.rateMu.Unlock()

	entry, ok := am.loginAttempts[ip]
	if !ok {
		am.loginAttempts[ip] = &rateLimitEntry{attempts: 1, lastAttempt: time.Now()}
		return
	}

	// Reset counter if lockout has expired.
	if time.Since(entry.lastAttempt) > am.lockoutDuration {
		entry.attempts = 1
	} else {
		entry.attempts++
	}
	entry.lastAttempt = time.Now()
}

func (am *AuthManager) clearAttempts(ip string) {
	am.rateMu.Lock()
	defer am.rateMu.Unlock()
	delete(am.loginAttempts, ip)
}

func (am *AuthManager) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		am.mu.Lock()
		now := time.Now()
		for token, session := range am.sessions {
			if now.After(session.ExpiresAt) {
				delete(am.sessions, token)
			}
		}
		am.mu.Unlock()

		// Clean up old rate limit entries.
		am.rateMu.Lock()
		for ip, entry := range am.loginAttempts {
			if time.Since(entry.lastAttempt) > am.lockoutDuration {
				delete(am.loginAttempts, ip)
			}
		}
		am.rateMu.Unlock()
	}
}

// generateToken creates a cryptographically random hex token.
func generateToken(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating random token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// getSessionFromRequest extracts the session from an HTTP request cookie.
func (am *AuthManager) getSessionFromRequest(r *http.Request) (*Session, bool) {
	cookie, err := r.Cookie("session")
	if err != nil {
		return nil, false
	}
	return am.ValidateSession(cookie.Value)
}

// ---------------------------------------------------------------------------
// TOTP 2FA (RFC 6238) — Pure Go Implementation
// ---------------------------------------------------------------------------

// GenerateTOTPSecret creates a new random 160-bit TOTP secret (base32 encoded).
func GenerateTOTPSecret() (string, error) {
	b := make([]byte, 20) // 160 bits
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating TOTP secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// EnableTOTP stores a TOTP secret for a user and returns the provisioning URI.
func (am *AuthManager) EnableTOTP(username string) (secret string, uri string, err error) {
	secret, err = GenerateTOTPSecret()
	if err != nil {
		return "", "", err
	}

	_, err = am.db.Exec("UPDATE users SET totp_secret = ? WHERE username = ?", secret, username)
	if err != nil {
		return "", "", fmt.Errorf("storing TOTP secret: %w", err)
	}

	// otpauth://totp/<issuer>:<account>?secret=<secret>&issuer=<issuer>&algorithm=SHA1&digits=6&period=30
	uri = fmt.Sprintf("otpauth://totp/Sentinel:%s?secret=%s&issuer=Sentinel&algorithm=SHA1&digits=6&period=30",
		username, secret)

	return secret, uri, nil
}

// DisableTOTP removes the TOTP secret for a user.
func (am *AuthManager) DisableTOTP(username string) error {
	_, err := am.db.Exec("UPDATE users SET totp_secret = NULL WHERE username = ?", username)
	return err
}

// HasTOTP checks if a user has TOTP configured.
func (am *AuthManager) HasTOTP(username string) bool {
	var secret sql.NullString
	err := am.db.QueryRow("SELECT totp_secret FROM users WHERE username = ?", username).Scan(&secret)
	return err == nil && secret.Valid && secret.String != ""
}

// ValidateTOTP verifies a TOTP code for a user. It checks the current time
// step and one step in each direction (+/- 30s) to handle clock skew.
func (am *AuthManager) ValidateTOTP(username, code string) bool {
	var secret sql.NullString
	err := am.db.QueryRow("SELECT totp_secret FROM users WHERE username = ?", username).Scan(&secret)
	if err != nil || !secret.Valid || secret.String == "" {
		return false
	}

	return verifyTOTP(secret.String, code, time.Now(), 1)
}

// verifyTOTP validates a TOTP code against a secret with the given skew window.
// skew=1 means check T-1, T, T+1 (total 3 time steps).
func verifyTOTP(secret, code string, now time.Time, skew int) bool {
	// Decode the base32 secret.
	secret = strings.TrimRight(strings.ToUpper(secret), "=")
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return false
	}

	// Time step = floor(unixTime / 30)
	counter := now.Unix() / 30

	for i := -skew; i <= skew; i++ {
		expected := generateHOTP(key, uint64(counter+int64(i)), 6)
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return true
		}
	}

	return false
}

// generateHOTP implements RFC 4226 HOTP with the given key, counter, and digit count.
func generateHOTP(key []byte, counter uint64, digits int) string {
	// Step 1: HMAC-SHA1(key, counter)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	hash := mac.Sum(nil)

	// Step 2: Dynamic Truncation
	offset := hash[len(hash)-1] & 0x0f
	binCode := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff

	// Step 3: Compute HOTP value
	otp := binCode % uint32(math.Pow10(digits))
	return fmt.Sprintf("%0*d", digits, otp)
}

// AuthenticateWithTOTP verifies credentials + TOTP code.
// If the user has TOTP enabled and no code is provided, returns ErrTOTPRequired.
func (am *AuthManager) AuthenticateWithTOTP(username, password, totpCode, remoteAddr string) (*Session, error) {
	// Check rate limit.
	if am.isRateLimited(remoteAddr) {
		return nil, fmt.Errorf("too many failed attempts, try again later")
	}

	// Look up user.
	var passwordHash, role string
	var totpSecret sql.NullString
	err := am.db.QueryRow(
		"SELECT password_hash, role, totp_secret FROM users WHERE username = ?", username,
	).Scan(&passwordHash, &role, &totpSecret)
	if err == sql.ErrNoRows {
		am.recordFailedAttempt(remoteAddr)
		return nil, fmt.Errorf("invalid credentials")
	}
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}

	// Verify password.
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		am.recordFailedAttempt(remoteAddr)
		return nil, fmt.Errorf("invalid credentials")
	}

	// If TOTP is enabled, verify the code.
	if totpSecret.Valid && totpSecret.String != "" {
		if totpCode == "" {
			return nil, fmt.Errorf("totp_required")
		}
		if !verifyTOTP(totpSecret.String, totpCode, time.Now(), 1) {
			am.recordFailedAttempt(remoteAddr)
			return nil, fmt.Errorf("invalid TOTP code")
		}
	}

	// Clear rate limit on success.
	am.clearAttempts(remoteAddr)

	// Update last_login.
	am.db.Exec("UPDATE users SET last_login = ? WHERE username = ?", time.Now(), username)

	// Create session.
	session, err := am.createSession(username, role)
	if err != nil {
		return nil, fmt.Errorf("creating session: %w", err)
	}

	return session, nil
}
