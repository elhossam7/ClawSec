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
	db    *sql.DB
	cache map[string]*cacheEntry
	mu    sync.RWMutex
}

type cacheEntry struct {
	value     string
	expiresAt time.Time
}

// NewSQLiteMemory creates a memory manager backed by SQLite.
func NewSQLiteMemory(db *sql.DB) (*SQLiteMemory, error) {
	m := &SQLiteMemory{
		db:    db,
		cache: make(map[string]*cacheEntry),
	}
	return m, nil
}

// StoreLearning persists a learned fact (e.g. "10.0.0.5 is Jenkins server").
func (m *SQLiteMemory) StoreLearning(fact, source string, confidence float64) error {
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

	return "Known facts:\n- " + strings.Join(facts, "\n- "), nil
}

// StoreContext saves a chat session's context.
func (m *SQLiteMemory) StoreContext(sessionID, context string) error {
	_, err := m.db.Exec(
		`INSERT INTO chat_sessions (session_id, user_id, context, updated_at) 
		 VALUES (?, '', ?, CURRENT_TIMESTAMP)
		 ON CONFLICT(session_id) DO UPDATE SET context = ?, updated_at = CURRENT_TIMESTAMP`,
		sessionID, context, context,
	)
	return err
}

// GetContext retrieves a chat session's context.
func (m *SQLiteMemory) GetContext(sessionID string) (string, error) {
	var ctx string
	err := m.db.QueryRow("SELECT context FROM chat_sessions WHERE session_id = ?", sessionID).Scan(&ctx)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return ctx, err
}
