// Package storage provides persistent storage for Sentinel using SQLite.
package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
	"github.com/rs/zerolog"
	"github.com/sentinel-agent/sentinel/internal/types"
)

// SQLite implements the storage layer using SQLite3.
type SQLite struct {
	db     *sql.DB
	logger zerolog.Logger
}

// NewSQLite opens or creates a SQLite database.
func NewSQLite(dsn string, logger zerolog.Logger) (*SQLite, error) {
	db, err := sql.Open("sqlite", dsn+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("opening sqlite: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("pinging sqlite: %w", err)
	}

	s := &SQLite{
		db:     db,
		logger: logger.With().Str("component", "storage").Logger(),
	}

	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	return s, nil
}

// Close closes the database connection.
func (s *SQLite) Close() error {
	return s.db.Close()
}

// migrate creates the database schema.
func (s *SQLite) migrate() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS events (
			id TEXT PRIMARY KEY,
			timestamp DATETIME NOT NULL,
			source TEXT NOT NULL,
			category TEXT NOT NULL,
			severity INTEGER NOT NULL,
			hostname TEXT NOT NULL,
			raw TEXT NOT NULL,
			fields TEXT NOT NULL,
			platform TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS incidents (
			id TEXT PRIMARY KEY,
			title TEXT NOT NULL,
			description TEXT,
			severity INTEGER NOT NULL,
			status TEXT NOT NULL DEFAULT 'open',
			rule_id TEXT NOT NULL,
			events TEXT NOT NULL DEFAULT '[]',
			actions TEXT NOT NULL DEFAULT '[]',
			source_ip TEXT,
			target_user TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			resolved_at DATETIME
		)`,
		`CREATE TABLE IF NOT EXISTS actions (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			target TEXT NOT NULL,
			reason TEXT,
			rule_id TEXT,
			incident_id TEXT,
			severity INTEGER NOT NULL,
			evidence TEXT NOT NULL DEFAULT '[]',
			rollback_cmd TEXT,
			approved_by TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME NOT NULL,
			executed_at DATETIME
		)`,
		`CREATE TABLE IF NOT EXISTS audit_log (
			id TEXT PRIMARY KEY,
			action TEXT NOT NULL,
			actor TEXT NOT NULL,
			details TEXT,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			totp_secret TEXT,
			role TEXT NOT NULL DEFAULT 'viewer',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_login DATETIME
		)`,
		`CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_events_category ON events(category)`,
		`CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)`,
		`CREATE INDEX IF NOT EXISTS idx_actions_status ON actions(status)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)`,
	}

	for _, m := range migrations {
		if _, err := s.db.Exec(m); err != nil {
			return fmt.Errorf("migration error: %w\nSQL: %s", err, m)
		}
	}

	s.logger.Info().Msg("database migrations complete")
	return nil
}

// --- Event Storage ---

// SaveEvent persists a log event.
func (s *SQLite) SaveEvent(event *types.LogEvent) error {
	fieldsJSON, _ := json.Marshal(event.Fields)
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO events (id, timestamp, source, category, severity, hostname, raw, fields, platform)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.ID, event.Timestamp, event.Source, event.Category, int(event.Severity),
		event.Hostname, event.Raw, string(fieldsJSON), event.Platform,
	)
	return err
}

// GetRecentEvents returns the most recent events.
func (s *SQLite) GetRecentEvents(limit int) ([]types.LogEvent, error) {
	rows, err := s.db.Query(
		`SELECT id, timestamp, source, category, severity, hostname, raw, fields, platform
		 FROM events ORDER BY timestamp DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanEvents(rows)
}

// --- Incident Storage ---

// SaveIncident persists an incident.
func (s *SQLite) SaveIncident(incident *types.Incident) error {
	eventsJSON, _ := json.Marshal(incident.Events)
	actionsJSON, _ := json.Marshal(incident.Actions)
	_, err := s.db.Exec(
		`INSERT INTO incidents (id, title, description, severity, status, rule_id, events, actions, source_ip, target_user, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		incident.ID, incident.Title, incident.Description, int(incident.Severity),
		string(incident.Status), incident.RuleID, string(eventsJSON), string(actionsJSON),
		incident.SourceIP, incident.TargetUser, incident.CreatedAt, incident.UpdatedAt,
	)
	return err
}

// GetIncident retrieves an incident by ID.
func (s *SQLite) GetIncident(id string) (*types.Incident, error) {
	row := s.db.QueryRow(
		`SELECT id, title, description, severity, status, rule_id, events, actions, source_ip, target_user, created_at, updated_at, resolved_at
		 FROM incidents WHERE id = ?`, id,
	)
	return scanIncident(row)
}

// GetOpenIncidents returns all open incidents.
func (s *SQLite) GetOpenIncidents() ([]types.Incident, error) {
	rows, err := s.db.Query(
		`SELECT id, title, description, severity, status, rule_id, events, actions, source_ip, target_user, created_at, updated_at, resolved_at
		 FROM incidents WHERE status IN ('open', 'acknowledged') ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanIncidents(rows)
}

// GetAllIncidents returns all incidents with a limit.
func (s *SQLite) GetAllIncidents(limit int) ([]types.Incident, error) {
	rows, err := s.db.Query(
		`SELECT id, title, description, severity, status, rule_id, events, actions, source_ip, target_user, created_at, updated_at, resolved_at
		 FROM incidents ORDER BY created_at DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanIncidents(rows)
}

// UpdateIncident updates an incident.
func (s *SQLite) UpdateIncident(incident *types.Incident) error {
	eventsJSON, _ := json.Marshal(incident.Events)
	actionsJSON, _ := json.Marshal(incident.Actions)
	_, err := s.db.Exec(
		`UPDATE incidents SET title=?, description=?, severity=?, status=?, events=?, actions=?, 
		 source_ip=?, target_user=?, updated_at=?, resolved_at=? WHERE id=?`,
		incident.Title, incident.Description, int(incident.Severity), string(incident.Status),
		string(eventsJSON), string(actionsJSON), incident.SourceIP, incident.TargetUser,
		incident.UpdatedAt, incident.ResolvedAt, incident.ID,
	)
	return err
}

// --- Action Storage ---

// SaveAction persists a response action.
func (s *SQLite) SaveAction(action *types.ResponseAction) error {
	evidenceJSON, _ := json.Marshal(action.Evidence)
	_, err := s.db.Exec(
		`INSERT INTO actions (id, type, status, target, reason, rule_id, incident_id, severity, evidence, rollback_cmd, approved_by, created_at, expires_at, executed_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		action.ID, string(action.Type), string(action.Status), action.Target, action.Reason,
		action.RuleID, action.IncidentID, int(action.Severity), string(evidenceJSON),
		action.RollbackCmd, action.ApprovedBy, action.CreatedAt, action.ExpiresAt, action.ExecutedAt,
	)
	return err
}

// GetAction retrieves an action by ID.
func (s *SQLite) GetAction(id string) (*types.ResponseAction, error) {
	row := s.db.QueryRow(
		`SELECT id, type, status, target, reason, rule_id, incident_id, severity, evidence, rollback_cmd, approved_by, created_at, expires_at, executed_at
		 FROM actions WHERE id = ?`, id,
	)
	return scanAction(row)
}

// GetPendingActions returns all pending response actions.
func (s *SQLite) GetPendingActions() ([]types.ResponseAction, error) {
	rows, err := s.db.Query(
		`SELECT id, type, status, target, reason, rule_id, incident_id, severity, evidence, rollback_cmd, approved_by, created_at, expires_at, executed_at
		 FROM actions WHERE status = 'pending' ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanActions(rows)
}

// UpdateAction updates a response action.
func (s *SQLite) UpdateAction(action *types.ResponseAction) error {
	evidenceJSON, _ := json.Marshal(action.Evidence)
	_, err := s.db.Exec(
		`UPDATE actions SET type=?, status=?, target=?, reason=?, rule_id=?, incident_id=?, severity=?, evidence=?, rollback_cmd=?, approved_by=?, expires_at=?, executed_at=? WHERE id=?`,
		string(action.Type), string(action.Status), action.Target, action.Reason,
		action.RuleID, action.IncidentID, int(action.Severity), string(evidenceJSON),
		action.RollbackCmd, action.ApprovedBy, action.ExpiresAt, action.ExecutedAt, action.ID,
	)
	return err
}

// GetRecentActions returns the most recent actions.
func (s *SQLite) GetRecentActions(limit int) ([]types.ResponseAction, error) {
	rows, err := s.db.Query(
		`SELECT id, type, status, target, reason, rule_id, incident_id, severity, evidence, rollback_cmd, approved_by, created_at, expires_at, executed_at
		 FROM actions ORDER BY created_at DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanActions(rows)
}

// --- Audit Log ---

// SaveAuditEntry records an audit entry.
func (s *SQLite) SaveAuditEntry(entry *types.AuditEntry) error {
	_, err := s.db.Exec(
		`INSERT INTO audit_log (id, action, actor, details, timestamp) VALUES (?, ?, ?, ?, ?)`,
		entry.ID, entry.Action, entry.Actor, entry.Details, entry.Timestamp,
	)
	return err
}

// GetAuditLog returns recent audit entries.
func (s *SQLite) GetAuditLog(limit int) ([]types.AuditEntry, error) {
	rows, err := s.db.Query(
		`SELECT id, action, actor, details, timestamp FROM audit_log ORDER BY timestamp DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []types.AuditEntry
	for rows.Next() {
		var e types.AuditEntry
		if err := rows.Scan(&e.ID, &e.Action, &e.Actor, &e.Details, &e.Timestamp); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// --- Stats ---

// EventCount returns the total number of stored events.
func (s *SQLite) EventCount() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM events").Scan(&count)
	return count, err
}

// IncidentCount returns the number of open incidents.
func (s *SQLite) IncidentCount() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM incidents WHERE status IN ('open','acknowledged')").Scan(&count)
	return count, err
}

// PendingActionCount returns the number of pending actions.
func (s *SQLite) PendingActionCount() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM actions WHERE status = 'pending'").Scan(&count)
	return count, err
}

// --- Scan helpers ---

func scanEvents(rows *sql.Rows) ([]types.LogEvent, error) {
	var events []types.LogEvent
	for rows.Next() {
		var e types.LogEvent
		var fieldsJSON string
		var sev int
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Source, &e.Category, &sev, &e.Hostname, &e.Raw, &fieldsJSON, &e.Platform); err != nil {
			return nil, err
		}
		e.Severity = types.Severity(sev)
		json.Unmarshal([]byte(fieldsJSON), &e.Fields)
		events = append(events, e)
	}
	return events, rows.Err()
}

func scanIncident(row *sql.Row) (*types.Incident, error) {
	var i types.Incident
	var sev int
	var eventsJSON, actionsJSON string
	var resolvedAt *time.Time
	if err := row.Scan(&i.ID, &i.Title, &i.Description, &sev, &i.Status, &i.RuleID,
		&eventsJSON, &actionsJSON, &i.SourceIP, &i.TargetUser,
		&i.CreatedAt, &i.UpdatedAt, &resolvedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	i.Severity = types.Severity(sev)
	i.ResolvedAt = resolvedAt
	json.Unmarshal([]byte(eventsJSON), &i.Events)
	json.Unmarshal([]byte(actionsJSON), &i.Actions)
	return &i, nil
}

func scanIncidents(rows *sql.Rows) ([]types.Incident, error) {
	var incidents []types.Incident
	for rows.Next() {
		var i types.Incident
		var sev int
		var eventsJSON, actionsJSON string
		var resolvedAt *time.Time
		if err := rows.Scan(&i.ID, &i.Title, &i.Description, &sev, &i.Status, &i.RuleID,
			&eventsJSON, &actionsJSON, &i.SourceIP, &i.TargetUser,
			&i.CreatedAt, &i.UpdatedAt, &resolvedAt); err != nil {
			return nil, err
		}
		i.Severity = types.Severity(sev)
		i.ResolvedAt = resolvedAt
		json.Unmarshal([]byte(eventsJSON), &i.Events)
		json.Unmarshal([]byte(actionsJSON), &i.Actions)
		incidents = append(incidents, i)
	}
	return incidents, rows.Err()
}

func scanAction(row *sql.Row) (*types.ResponseAction, error) {
	var a types.ResponseAction
	var sev int
	var evidenceJSON string
	var executedAt *time.Time
	if err := row.Scan(&a.ID, &a.Type, &a.Status, &a.Target, &a.Reason, &a.RuleID,
		&a.IncidentID, &sev, &evidenceJSON, &a.RollbackCmd, &a.ApprovedBy,
		&a.CreatedAt, &a.ExpiresAt, &executedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	a.Severity = types.Severity(sev)
	a.ExecutedAt = executedAt
	json.Unmarshal([]byte(evidenceJSON), &a.Evidence)
	return &a, nil
}

func scanActions(rows *sql.Rows) ([]types.ResponseAction, error) {
	var actions []types.ResponseAction
	for rows.Next() {
		var a types.ResponseAction
		var sev int
		var evidenceJSON string
		var executedAt *time.Time
		if err := rows.Scan(&a.ID, &a.Type, &a.Status, &a.Target, &a.Reason, &a.RuleID,
			&a.IncidentID, &sev, &evidenceJSON, &a.RollbackCmd, &a.ApprovedBy,
			&a.CreatedAt, &a.ExpiresAt, &executedAt); err != nil {
			return nil, err
		}
		a.Severity = types.Severity(sev)
		a.ExecutedAt = executedAt
		json.Unmarshal([]byte(evidenceJSON), &a.Evidence)
		actions = append(actions, a)
	}
	return actions, rows.Err()
}
