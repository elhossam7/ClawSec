package gateway

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
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
