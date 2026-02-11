package agent

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Memory provides persistent fact storage and retrieval for the agent.
type Memory interface {
	StoreLearning(fact, source string, confidence float64) error
	GetRelevantContext(incidentID, sourceIP, ruleID string) (string, error)
	StoreContext(sessionID string, context string) error
	GetContext(sessionID string) (string, error)
}

// SQLiteMemory implements Memory using the existing SQLite database.
type SQLiteMemory struct {
	db       *sql.DB
	cache    map[string]*cacheEntry
	mu       sync.RWMutex
	cacheTTL time.Duration
}

type cacheEntry struct {
	value     string
	expiresAt time.Time
}

// NewSQLiteMemory creates a memory manager backed by SQLite.
func NewSQLiteMemory(db *sql.DB) (*SQLiteMemory, error) {
	m := &SQLiteMemory{
		db:       db,
		cache:    make(map[string]*cacheEntry),
		cacheTTL: 5 * time.Minute,
	}

	// Start cache cleanup goroutine.
	go m.cleanupCache()

	return m, nil
}

// cacheGet retrieves a value from the in-memory cache. Returns "" if absent or expired.
func (m *SQLiteMemory) cacheGet(key string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	entry, ok := m.cache[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return "", false
	}
	return entry.value, true
}

// cacheSet stores a value in the in-memory cache with TTL.
func (m *SQLiteMemory) cacheSet(key, value string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cache[key] = &cacheEntry{
		value:     value,
		expiresAt: time.Now().Add(m.cacheTTL),
	}
}

// cleanupCache periodically prunes expired entries.
func (m *SQLiteMemory) cleanupCache() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		m.mu.Lock()
		now := time.Now()
		for k, v := range m.cache {
			if now.After(v.expiresAt) {
				delete(m.cache, k)
			}
		}
		m.mu.Unlock()
	}
}

// StoreLearning persists a learned fact (e.g. "10.0.0.5 is Jenkins server").
func (m *SQLiteMemory) StoreLearning(fact, source string, confidence float64) error {
	// Invalidate context caches since a new fact may affect them.
	m.mu.Lock()
	for k := range m.cache {
		if strings.HasPrefix(k, "ctx:") {
			delete(m.cache, k)
		}
	}
	m.mu.Unlock()

	// Deduplicate: update if same fact already exists.
	var existing int
	err := m.db.QueryRow("SELECT COUNT(*) FROM agent_memory WHERE fact = ?", fact).Scan(&existing)
	if err != nil {
		return fmt.Errorf("checking existing fact: %w", err)
	}

	if existing > 0 {
		_, err = m.db.Exec(
			"UPDATE agent_memory SET confidence = ?, last_accessed = CURRENT_TIMESTAMP, access_count = access_count + 1 WHERE fact = ?",
			confidence, fact,
		)
	} else {
		_, err = m.db.Exec(
			"INSERT INTO agent_memory (fact, source, confidence) VALUES (?, ?, ?)",
			fact, source, confidence,
		)
	}
	return err
}

// GetRelevantContext retrieves facts relevant to an incident.
func (m *SQLiteMemory) GetRelevantContext(incidentID, sourceIP, ruleID string) (string, error) {
	// Check cache first.
	cacheKey := "ctx:" + incidentID + ":" + sourceIP + ":" + ruleID
	if cached, ok := m.cacheGet(cacheKey); ok {
		return cached, nil
	}

	var facts []string

	// Search for facts mentioning the source IP.
	if sourceIP != "" {
		rows, err := m.db.Query(
			"SELECT fact FROM agent_memory WHERE fact LIKE ? ORDER BY confidence DESC LIMIT 5",
			"%"+sourceIP+"%",
		)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var f string
				if rows.Scan(&f) == nil {
					facts = append(facts, f)
				}
			}
		}
	}

	// Search for facts mentioning the rule.
	if ruleID != "" {
		rows, err := m.db.Query(
			"SELECT fact FROM agent_memory WHERE fact LIKE ? ORDER BY confidence DESC LIMIT 3",
			"%"+ruleID+"%",
		)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var f string
				if rows.Scan(&f) == nil {
					facts = append(facts, f)
				}
			}
		}
	}

	// Also retrieve last analysis for this IP if any.
	if sourceIP != "" {
		var lastReasoning string
		err := m.db.QueryRow(
			"SELECT reasoning FROM analysis_logs WHERE incident_id IN (SELECT id FROM incidents WHERE source_ip = ?) ORDER BY created_at DESC LIMIT 1",
			sourceIP,
		).Scan(&lastReasoning)
		if err == nil && lastReasoning != "" {
			facts = append(facts, fmt.Sprintf("Previous analysis for %s: %s", sourceIP, lastReasoning))
		}
	}

	if len(facts) == 0 {
		return "", nil
	}

	// Update access timestamps.
	for _, f := range facts {
		m.db.Exec("UPDATE agent_memory SET last_accessed = CURRENT_TIMESTAMP, access_count = access_count + 1 WHERE fact = ?", f)
	}

	result := "Known facts:\n- " + strings.Join(facts, "\n- ")

	// Populate cache.
	m.cacheSet(cacheKey, result)

	return result, nil
}

// StoreContext saves a chat session's context.
func (m *SQLiteMemory) StoreContext(sessionID, context string) error {
	_, err := m.db.Exec(
		`INSERT INTO chat_sessions (session_id, user_id, context, updated_at) 
		 VALUES (?, '', ?, CURRENT_TIMESTAMP)
		 ON CONFLICT(session_id) DO UPDATE SET context = ?, updated_at = CURRENT_TIMESTAMP`,
		sessionID, context, context,
	)
	if err == nil {
		m.cacheSet("session:"+sessionID, context)
	}
	return err
}

// GetContext retrieves a chat session's context.
func (m *SQLiteMemory) GetContext(sessionID string) (string, error) {
	// Check cache first.
	if cached, ok := m.cacheGet("session:" + sessionID); ok {
		return cached, nil
	}

	var ctx string
	err := m.db.QueryRow("SELECT context FROM chat_sessions WHERE session_id = ?", sessionID).Scan(&ctx)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err == nil {
		m.cacheSet("session:"+sessionID, ctx)
	}
	return ctx, err
}
