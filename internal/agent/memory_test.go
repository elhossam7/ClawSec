package agent

import (
	"database/sql"
	"os"
	"testing"

	_ "modernc.org/sqlite"
)

func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()

	tmpFile, err := os.CreateTemp("", "sentinel-memory-test-*.db")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	tmpFile.Close()
	t.Cleanup(func() { os.Remove(tmpFile.Name()) })

	db, err := sql.Open("sqlite", tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// Create required tables.
	tables := []string{
		`CREATE TABLE IF NOT EXISTS agent_memory (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			fact TEXT NOT NULL,
			source TEXT NOT NULL DEFAULT '',
			confidence REAL NOT NULL DEFAULT 0.5,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_accessed DATETIME DEFAULT CURRENT_TIMESTAMP,
			access_count INTEGER DEFAULT 1
		)`,
		`CREATE TABLE IF NOT EXISTS analysis_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			incident_id TEXT NOT NULL,
			provider TEXT NOT NULL DEFAULT '',
			model TEXT NOT NULL DEFAULT '',
			reasoning TEXT NOT NULL DEFAULT '',
			actions_proposed TEXT NOT NULL DEFAULT '[]',
			confidence REAL NOT NULL DEFAULT 0,
			risk_score INTEGER NOT NULL DEFAULT 0,
			tokens_used INTEGER NOT NULL DEFAULT 0,
			duration_ms INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS chat_sessions (
			session_id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL DEFAULT '',
			context TEXT NOT NULL DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS incidents (
			id TEXT PRIMARY KEY,
			source_ip TEXT
		)`,
	}

	for _, stmt := range tables {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("failed to create table: %v", err)
		}
	}

	return db
}

func TestSQLiteMemory_StoreLearning(t *testing.T) {
	db := setupTestDB(t)
	mem, err := NewSQLiteMemory(db)
	if err != nil {
		t.Fatalf("NewSQLiteMemory error: %v", err)
	}

	// Store a new fact.
	err = mem.StoreLearning("10.0.0.5 is the Jenkins CI server", "asset_scan", 0.95)
	if err != nil {
		t.Fatalf("StoreLearning error: %v", err)
	}

	// Verify insertion.
	var count int
	db.QueryRow("SELECT COUNT(*) FROM agent_memory").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 fact, got %d", count)
	}

	// Store same fact → should update (deduplicate).
	err = mem.StoreLearning("10.0.0.5 is the Jenkins CI server", "asset_scan", 0.99)
	if err != nil {
		t.Fatalf("StoreLearning (update) error: %v", err)
	}

	db.QueryRow("SELECT COUNT(*) FROM agent_memory").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 fact after dedup, got %d", count)
	}

	// Verify confidence was updated.
	var conf float64
	db.QueryRow("SELECT confidence FROM agent_memory WHERE fact LIKE '%Jenkins%'").Scan(&conf)
	if conf != 0.99 {
		t.Errorf("expected confidence 0.99 after update, got %f", conf)
	}
}

func TestSQLiteMemory_GetRelevantContext(t *testing.T) {
	db := setupTestDB(t)
	mem, _ := NewSQLiteMemory(db)

	// Store some facts.
	mem.StoreLearning("10.0.0.5 is Jenkins server", "scan", 0.9)
	mem.StoreLearning("ssh_brute_force seen 3 times from 203.0.113.5", "analysis", 0.8)
	mem.StoreLearning("203.0.113.5 has high abuse score", "threat_intel", 0.95)

	// Query by IP.
	ctx, err := mem.GetRelevantContext("", "203.0.113.5", "")
	if err != nil {
		t.Fatalf("GetRelevantContext error: %v", err)
	}
	if ctx == "" {
		t.Error("expected non-empty context for known IP")
	}

	// Query by rule.
	ctx, err = mem.GetRelevantContext("", "", "ssh_brute_force")
	if err != nil {
		t.Fatalf("GetRelevantContext error: %v", err)
	}
	if ctx == "" {
		t.Error("expected non-empty context for known rule")
	}

	// Query for unknown IP.
	ctx, err = mem.GetRelevantContext("", "1.2.3.4", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx != "" {
		t.Errorf("expected empty context for unknown IP, got: %s", ctx)
	}
}

func TestSQLiteMemory_StoreAndGetContext(t *testing.T) {
	db := setupTestDB(t)
	mem, _ := NewSQLiteMemory(db)

	sessionID := "session_test_1"

	// Get context for non-existent session → empty.
	ctx, err := mem.GetContext(sessionID)
	if err != nil {
		t.Fatalf("GetContext error: %v", err)
	}
	if ctx != "" {
		t.Errorf("expected empty context, got: %s", ctx)
	}

	// Store context.
	err = mem.StoreContext(sessionID, "User asked about 10.0.0.5 incidents")
	if err != nil {
		t.Fatalf("StoreContext error: %v", err)
	}

	// Retrieve.
	ctx, err = mem.GetContext(sessionID)
	if err != nil {
		t.Fatalf("GetContext error: %v", err)
	}
	if ctx != "User asked about 10.0.0.5 incidents" {
		t.Errorf("unexpected context: %s", ctx)
	}

	// Update context (UPSERT).
	err = mem.StoreContext(sessionID, "Updated conversation about firewall rules")
	if err != nil {
		t.Fatalf("StoreContext (update) error: %v", err)
	}

	ctx, err = mem.GetContext(sessionID)
	if err != nil {
		t.Fatalf("GetContext error: %v", err)
	}
	if ctx != "Updated conversation about firewall rules" {
		t.Errorf("expected updated context, got: %s", ctx)
	}
}

func TestSQLiteMemory_AccessCountIncrement(t *testing.T) {
	db := setupTestDB(t)
	mem, _ := NewSQLiteMemory(db)

	mem.StoreLearning("fact about 10.0.0.5", "test", 0.9)

	// Access via GetRelevantContext → should increment access_count.
	mem.GetRelevantContext("", "10.0.0.5", "")

	var accessCount int
	db.QueryRow("SELECT access_count FROM agent_memory WHERE fact LIKE '%10.0.0.5%'").Scan(&accessCount)
	// Initial store sets access_count=1, dedup on StoreLearning increments once,
	// GetRelevantContext increments again.
	if accessCount < 2 {
		t.Errorf("expected access_count >= 2, got %d", accessCount)
	}
}
