package storage

import (
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/sentinel-agent/sentinel/internal/types"
	_ "modernc.org/sqlite"
)

// newTestSQLite creates a fresh in-memory SQLite instance for a single test.
// It calls t.Cleanup to close the database when the test finishes.
func newTestSQLite(t *testing.T) *SQLite {
	t.Helper()
	logger := zerolog.Nop()
	store, err := NewSQLite(":memory:", logger)
	if err != nil {
		t.Fatalf("NewSQLite(:memory:): %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// ---------------------------------------------------------------------------
// 1. NewSQLite / migration tests
// ---------------------------------------------------------------------------

func TestNewSQLite_CreatesAllTables(t *testing.T) {
	store := newTestSQLite(t)

	expected := []string{
		"events",
		"incidents",
		"actions",
		"audit_log",
		"users",
		"agent_memory",
		"analysis_logs",
		"tool_executions",
		"chat_sessions",
		"api_keys",
	}

	for _, table := range expected {
		var name string
		err := store.DB().QueryRow(
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?", table,
		).Scan(&name)
		if err != nil {
			t.Errorf("expected table %q to exist, but got error: %v", table, err)
		}
	}
}

func TestNewSQLite_MigrationsAreIdempotent(t *testing.T) {
	logger := zerolog.Nop()
	// Running NewSQLite twice on the same DB should not fail.
	db, err := sql.Open("sqlite", ":memory:?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()

	s1 := &SQLite{db: db, logger: logger}
	if err := s1.migrate(); err != nil {
		t.Fatalf("first migration: %v", err)
	}
	if err := s1.migrate(); err != nil {
		t.Fatalf("second migration (idempotent): %v", err)
	}
}

// ---------------------------------------------------------------------------
// 2. Event CRUD
// ---------------------------------------------------------------------------

func makeEvent(id string, ts time.Time) *types.LogEvent {
	return &types.LogEvent{
		ID:        id,
		Timestamp: ts,
		Source:    "syslog",
		Category:  "auth",
		Severity:  types.SeverityHigh,
		Hostname:  "host1",
		Raw:       "raw log line",
		Fields:    map[string]string{"user": "root"},
		Platform:  "linux",
	}
}

func TestSaveEvent_AndGetRecentEvents(t *testing.T) {
	store := newTestSQLite(t)

	now := time.Now().UTC().Truncate(time.Second)
	e1 := makeEvent("evt-1", now.Add(-2*time.Second))
	e2 := makeEvent("evt-2", now.Add(-1*time.Second))
	e3 := makeEvent("evt-3", now)

	for _, e := range []*types.LogEvent{e1, e2, e3} {
		if err := store.SaveEvent(e); err != nil {
			t.Fatalf("SaveEvent(%s): %v", e.ID, err)
		}
	}

	events, err := store.GetRecentEvents(10)
	if err != nil {
		t.Fatalf("GetRecentEvents: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}
	// Most recent first.
	if events[0].ID != "evt-3" {
		t.Errorf("expected first event to be evt-3, got %s", events[0].ID)
	}
	if events[2].ID != "evt-1" {
		t.Errorf("expected last event to be evt-1, got %s", events[2].ID)
	}
	// Verify fields round-trip.
	if events[0].Fields["user"] != "root" {
		t.Errorf("expected Fields[user]=root, got %q", events[0].Fields["user"])
	}
	if events[0].Severity != types.SeverityHigh {
		t.Errorf("expected SeverityHigh, got %v", events[0].Severity)
	}
}

func TestSaveEvent_InsertOrIgnoreDuplicate(t *testing.T) {
	store := newTestSQLite(t)
	now := time.Now().UTC().Truncate(time.Second)
	e := makeEvent("evt-dup", now)

	if err := store.SaveEvent(e); err != nil {
		t.Fatalf("first SaveEvent: %v", err)
	}
	// Saving again with the same ID should not error (INSERT OR IGNORE).
	if err := store.SaveEvent(e); err != nil {
		t.Fatalf("duplicate SaveEvent: %v", err)
	}
	count, err := store.EventCount()
	if err != nil {
		t.Fatalf("EventCount: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 event after duplicate insert, got %d", count)
	}
}

func TestGetRecentEvents_Limit(t *testing.T) {
	store := newTestSQLite(t)
	now := time.Now().UTC().Truncate(time.Second)

	for i := 0; i < 5; i++ {
		e := makeEvent("evt-lim-"+time.Duration(i).String(), now.Add(time.Duration(i)*time.Second))
		e.ID = "evt-lim-" + string(rune('A'+i))
		if err := store.SaveEvent(e); err != nil {
			t.Fatalf("SaveEvent: %v", err)
		}
	}

	events, err := store.GetRecentEvents(3)
	if err != nil {
		t.Fatalf("GetRecentEvents(3): %v", err)
	}
	if len(events) != 3 {
		t.Errorf("expected 3 events, got %d", len(events))
	}
}

func TestEventCount(t *testing.T) {
	store := newTestSQLite(t)

	count, err := store.EventCount()
	if err != nil {
		t.Fatalf("EventCount: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 events, got %d", count)
	}

	now := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < 4; i++ {
		e := makeEvent("cnt-"+string(rune('A'+i)), now.Add(time.Duration(i)*time.Second))
		if err := store.SaveEvent(e); err != nil {
			t.Fatalf("SaveEvent: %v", err)
		}
	}

	count, err = store.EventCount()
	if err != nil {
		t.Fatalf("EventCount: %v", err)
	}
	if count != 4 {
		t.Errorf("expected 4 events, got %d", count)
	}
}

// ---------------------------------------------------------------------------
// 3. Incident CRUD
// ---------------------------------------------------------------------------

func makeIncident(id string, status types.IncidentStatus) *types.Incident {
	now := time.Now().UTC().Truncate(time.Second)
	return &types.Incident{
		ID:          id,
		Title:       "Test Incident " + id,
		Description: "Description for " + id,
		Severity:    types.SeverityCritical,
		Status:      status,
		RuleID:      "rule-001",
		Events:      []string{"evt-1", "evt-2"},
		Actions:     []string{"act-1"},
		SourceIP:    "10.0.0.1",
		TargetUser:  "admin",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

func TestSaveIncident_AndGetIncident(t *testing.T) {
	store := newTestSQLite(t)

	inc := makeIncident("inc-1", types.IncidentOpen)
	if err := store.SaveIncident(inc); err != nil {
		t.Fatalf("SaveIncident: %v", err)
	}

	got, err := store.GetIncident("inc-1")
	if err != nil {
		t.Fatalf("GetIncident: %v", err)
	}
	if got == nil {
		t.Fatal("GetIncident returned nil for existing incident")
	}
	if got.ID != "inc-1" {
		t.Errorf("expected ID inc-1, got %s", got.ID)
	}
	if got.Title != inc.Title {
		t.Errorf("expected Title %q, got %q", inc.Title, got.Title)
	}
	if got.Severity != types.SeverityCritical {
		t.Errorf("expected SeverityCritical, got %v", got.Severity)
	}
	if got.Status != types.IncidentOpen {
		t.Errorf("expected status open, got %s", got.Status)
	}
	if len(got.Events) != 2 {
		t.Errorf("expected 2 events, got %d", len(got.Events))
	}
	if len(got.Actions) != 1 {
		t.Errorf("expected 1 action, got %d", len(got.Actions))
	}
	if got.SourceIP != "10.0.0.1" {
		t.Errorf("expected SourceIP 10.0.0.1, got %s", got.SourceIP)
	}
	if got.ResolvedAt != nil {
		t.Errorf("expected nil ResolvedAt, got %v", got.ResolvedAt)
	}
}

func TestGetIncident_NotFound(t *testing.T) {
	store := newTestSQLite(t)

	got, err := store.GetIncident("nonexistent")
	if err != nil {
		t.Fatalf("GetIncident(nonexistent): %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for nonexistent incident, got %+v", got)
	}
}

func TestGetOpenIncidents(t *testing.T) {
	store := newTestSQLite(t)

	openInc := makeIncident("inc-open", types.IncidentOpen)
	ackedInc := makeIncident("inc-acked", types.IncidentAcked)
	resolvedInc := makeIncident("inc-resolved", types.IncidentResolved)
	fpInc := makeIncident("inc-fp", types.IncidentFalsePos)

	for _, inc := range []*types.Incident{openInc, ackedInc, resolvedInc, fpInc} {
		if err := store.SaveIncident(inc); err != nil {
			t.Fatalf("SaveIncident(%s): %v", inc.ID, err)
		}
	}

	open, err := store.GetOpenIncidents()
	if err != nil {
		t.Fatalf("GetOpenIncidents: %v", err)
	}
	if len(open) != 2 {
		t.Fatalf("expected 2 open/acknowledged incidents, got %d", len(open))
	}

	ids := map[string]bool{}
	for _, inc := range open {
		ids[inc.ID] = true
	}
	if !ids["inc-open"] {
		t.Error("expected inc-open in open incidents")
	}
	if !ids["inc-acked"] {
		t.Error("expected inc-acked in open incidents")
	}
}

func TestGetAllIncidents(t *testing.T) {
	store := newTestSQLite(t)

	now := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < 5; i++ {
		inc := makeIncident("inc-all-"+string(rune('A'+i)), types.IncidentOpen)
		inc.CreatedAt = now.Add(time.Duration(i) * time.Second)
		if err := store.SaveIncident(inc); err != nil {
			t.Fatalf("SaveIncident: %v", err)
		}
	}

	all, err := store.GetAllIncidents(3)
	if err != nil {
		t.Fatalf("GetAllIncidents(3): %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 incidents, got %d", len(all))
	}
	// Should be most recent first.
	if all[0].ID != "inc-all-E" {
		t.Errorf("expected most recent incident inc-all-E, got %s", all[0].ID)
	}
}

func TestUpdateIncident(t *testing.T) {
	store := newTestSQLite(t)

	inc := makeIncident("inc-update", types.IncidentOpen)
	if err := store.SaveIncident(inc); err != nil {
		t.Fatalf("SaveIncident: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	inc.Status = types.IncidentResolved
	inc.Title = "Updated Title"
	resolvedAt := now
	inc.ResolvedAt = &resolvedAt
	inc.UpdatedAt = now
	inc.Actions = []string{"act-1", "act-2"}

	if err := store.UpdateIncident(inc); err != nil {
		t.Fatalf("UpdateIncident: %v", err)
	}

	got, err := store.GetIncident("inc-update")
	if err != nil {
		t.Fatalf("GetIncident after update: %v", err)
	}
	if got.Status != types.IncidentResolved {
		t.Errorf("expected status resolved, got %s", got.Status)
	}
	if got.Title != "Updated Title" {
		t.Errorf("expected updated Title, got %q", got.Title)
	}
	if got.ResolvedAt == nil {
		t.Error("expected ResolvedAt to be set")
	}
	if len(got.Actions) != 2 {
		t.Errorf("expected 2 actions after update, got %d", len(got.Actions))
	}
}

func TestIncidentCount(t *testing.T) {
	store := newTestSQLite(t)

	count, err := store.IncidentCount()
	if err != nil {
		t.Fatalf("IncidentCount: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 incidents, got %d", count)
	}

	for _, s := range []types.IncidentStatus{types.IncidentOpen, types.IncidentAcked, types.IncidentResolved} {
		inc := makeIncident("inc-cnt-"+string(s), s)
		if err := store.SaveIncident(inc); err != nil {
			t.Fatalf("SaveIncident: %v", err)
		}
	}

	count, err = store.IncidentCount()
	if err != nil {
		t.Fatalf("IncidentCount: %v", err)
	}
	// Only open + acknowledged = 2.
	if count != 2 {
		t.Errorf("expected 2 open/acknowledged incidents, got %d", count)
	}
}

// ---------------------------------------------------------------------------
// 4. Action CRUD
// ---------------------------------------------------------------------------

func makeAction(id string, status types.ActionStatus) *types.ResponseAction {
	now := time.Now().UTC().Truncate(time.Second)
	return &types.ResponseAction{
		ID:          id,
		Type:        types.ActionBlockIP,
		Status:      status,
		Target:      "192.168.1.100",
		Reason:      "Brute force detected",
		RuleID:      "rule-002",
		IncidentID:  "inc-1",
		Severity:    types.SeverityHigh,
		Evidence:    []string{"evt-1", "evt-2"},
		RollbackCmd: "iptables -D INPUT -s 192.168.1.100 -j DROP",
		ApprovedBy:  "",
		CreatedAt:   now,
		ExpiresAt:   now.Add(24 * time.Hour),
	}
}

func TestSaveAction_AndGetAction(t *testing.T) {
	store := newTestSQLite(t)

	action := makeAction("act-1", types.ActionPending)
	if err := store.SaveAction(action); err != nil {
		t.Fatalf("SaveAction: %v", err)
	}

	got, err := store.GetAction("act-1")
	if err != nil {
		t.Fatalf("GetAction: %v", err)
	}
	if got == nil {
		t.Fatal("GetAction returned nil for existing action")
	}
	if got.ID != "act-1" {
		t.Errorf("expected ID act-1, got %s", got.ID)
	}
	if got.Type != types.ActionBlockIP {
		t.Errorf("expected type block_ip, got %s", got.Type)
	}
	if got.Status != types.ActionPending {
		t.Errorf("expected status pending, got %s", got.Status)
	}
	if got.Target != "192.168.1.100" {
		t.Errorf("expected target 192.168.1.100, got %s", got.Target)
	}
	if got.Severity != types.SeverityHigh {
		t.Errorf("expected SeverityHigh, got %v", got.Severity)
	}
	if len(got.Evidence) != 2 {
		t.Errorf("expected 2 evidence items, got %d", len(got.Evidence))
	}
	if got.RollbackCmd != action.RollbackCmd {
		t.Errorf("expected RollbackCmd %q, got %q", action.RollbackCmd, got.RollbackCmd)
	}
	if got.ExecutedAt != nil {
		t.Errorf("expected nil ExecutedAt, got %v", got.ExecutedAt)
	}
}

func TestGetAction_NotFound(t *testing.T) {
	store := newTestSQLite(t)

	got, err := store.GetAction("nonexistent")
	if err != nil {
		t.Fatalf("GetAction(nonexistent): %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for nonexistent action, got %+v", got)
	}
}

func TestGetPendingActions(t *testing.T) {
	store := newTestSQLite(t)

	pending1 := makeAction("act-p1", types.ActionPending)
	pending2 := makeAction("act-p2", types.ActionPending)
	approved := makeAction("act-ap", types.ActionApproved)
	executed := makeAction("act-ex", types.ActionExecuted)

	for _, a := range []*types.ResponseAction{pending1, pending2, approved, executed} {
		if err := store.SaveAction(a); err != nil {
			t.Fatalf("SaveAction(%s): %v", a.ID, err)
		}
	}

	pending, err := store.GetPendingActions()
	if err != nil {
		t.Fatalf("GetPendingActions: %v", err)
	}
	if len(pending) != 2 {
		t.Fatalf("expected 2 pending actions, got %d", len(pending))
	}

	ids := map[string]bool{}
	for _, a := range pending {
		ids[a.ID] = true
	}
	if !ids["act-p1"] {
		t.Error("expected act-p1 in pending actions")
	}
	if !ids["act-p2"] {
		t.Error("expected act-p2 in pending actions")
	}
}

func TestUpdateAction(t *testing.T) {
	store := newTestSQLite(t)

	action := makeAction("act-upd", types.ActionPending)
	if err := store.SaveAction(action); err != nil {
		t.Fatalf("SaveAction: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	action.Status = types.ActionExecuted
	action.ApprovedBy = "webui:admin"
	executedAt := now
	action.ExecutedAt = &executedAt
	action.Evidence = []string{"evt-1", "evt-2", "evt-3"}

	if err := store.UpdateAction(action); err != nil {
		t.Fatalf("UpdateAction: %v", err)
	}

	got, err := store.GetAction("act-upd")
	if err != nil {
		t.Fatalf("GetAction after update: %v", err)
	}
	if got.Status != types.ActionExecuted {
		t.Errorf("expected status executed, got %s", got.Status)
	}
	if got.ApprovedBy != "webui:admin" {
		t.Errorf("expected ApprovedBy webui:admin, got %q", got.ApprovedBy)
	}
	if got.ExecutedAt == nil {
		t.Error("expected ExecutedAt to be set")
	}
	if len(got.Evidence) != 3 {
		t.Errorf("expected 3 evidence items after update, got %d", len(got.Evidence))
	}
}

func TestGetRecentActions(t *testing.T) {
	store := newTestSQLite(t)

	now := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < 5; i++ {
		a := makeAction("act-rec-"+string(rune('A'+i)), types.ActionPending)
		a.CreatedAt = now.Add(time.Duration(i) * time.Second)
		if err := store.SaveAction(a); err != nil {
			t.Fatalf("SaveAction: %v", err)
		}
	}

	recent, err := store.GetRecentActions(3)
	if err != nil {
		t.Fatalf("GetRecentActions(3): %v", err)
	}
	if len(recent) != 3 {
		t.Fatalf("expected 3 actions, got %d", len(recent))
	}
	// Most recent first.
	if recent[0].ID != "act-rec-E" {
		t.Errorf("expected most recent action act-rec-E, got %s", recent[0].ID)
	}
}

func TestPendingActionCount(t *testing.T) {
	store := newTestSQLite(t)

	count, err := store.PendingActionCount()
	if err != nil {
		t.Fatalf("PendingActionCount: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 pending actions, got %d", count)
	}

	for i, status := range []types.ActionStatus{types.ActionPending, types.ActionPending, types.ActionApproved, types.ActionExecuted} {
		a := makeAction(fmt.Sprintf("act-pc-%d", i), status)
		if err := store.SaveAction(a); err != nil {
			t.Fatalf("SaveAction: %v", err)
		}
	}

	count, err = store.PendingActionCount()
	if err != nil {
		t.Fatalf("PendingActionCount: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 pending actions, got %d", count)
	}
}

// ---------------------------------------------------------------------------
// 5. Audit
// ---------------------------------------------------------------------------

func TestSaveAuditEntry_AndGetAuditLog(t *testing.T) {
	store := newTestSQLite(t)

	now := time.Now().UTC().Truncate(time.Second)
	entries := []*types.AuditEntry{
		{ID: "aud-1", Action: "action_approved", Actor: "admin", Details: "Approved block_ip", Timestamp: now.Add(-2 * time.Second)},
		{ID: "aud-2", Action: "rule_enabled", Actor: "system", Details: "Enabled rule-001", Timestamp: now.Add(-1 * time.Second)},
		{ID: "aud-3", Action: "action_executed", Actor: "sentinel", Details: "Executed block_ip", Timestamp: now},
	}

	for _, e := range entries {
		if err := store.SaveAuditEntry(e); err != nil {
			t.Fatalf("SaveAuditEntry(%s): %v", e.ID, err)
		}
	}

	log, err := store.GetAuditLog(10)
	if err != nil {
		t.Fatalf("GetAuditLog: %v", err)
	}
	if len(log) != 3 {
		t.Fatalf("expected 3 audit entries, got %d", len(log))
	}
	// Most recent first.
	if log[0].ID != "aud-3" {
		t.Errorf("expected first entry aud-3, got %s", log[0].ID)
	}
	if log[0].Action != "action_executed" {
		t.Errorf("expected Action action_executed, got %q", log[0].Action)
	}
	if log[0].Actor != "sentinel" {
		t.Errorf("expected Actor sentinel, got %q", log[0].Actor)
	}
}

func TestGetAuditLog_Limit(t *testing.T) {
	store := newTestSQLite(t)

	now := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < 5; i++ {
		entry := &types.AuditEntry{
			ID:        "aud-lim-" + string(rune('A'+i)),
			Action:    "test_action",
			Actor:     "tester",
			Details:   "detail",
			Timestamp: now.Add(time.Duration(i) * time.Second),
		}
		if err := store.SaveAuditEntry(entry); err != nil {
			t.Fatalf("SaveAuditEntry: %v", err)
		}
	}

	log, err := store.GetAuditLog(2)
	if err != nil {
		t.Fatalf("GetAuditLog(2): %v", err)
	}
	if len(log) != 2 {
		t.Errorf("expected 2 audit entries, got %d", len(log))
	}
}

// ---------------------------------------------------------------------------
// 6. AgentStore
// ---------------------------------------------------------------------------

func TestNewAgentStore(t *testing.T) {
	store := newTestSQLite(t)

	agentStore := NewAgentStore(store.DB())
	if agentStore == nil {
		t.Fatal("NewAgentStore returned nil")
	}
}

func TestAgentStore_SaveAnalysisLog_AndGetRecent(t *testing.T) {
	store := newTestSQLite(t)
	agentStore := NewAgentStore(store.DB())

	now := time.Now().UTC().Truncate(time.Second)
	logs := []*AnalysisLogRow{
		{
			ID:          "al-1",
			IncidentID:  "inc-1",
			SessionID:   "sess-1",
			Prompt:      "Analyze this incident",
			Response:    "This appears to be a brute force attack",
			Reasoning:   "Multiple failed logins from same IP",
			Confidence:  0.85,
			ToolsCalled: "whois,netstat",
			Outcome:     "action_proposed",
			CreatedAt:   now.Add(-2 * time.Second),
		},
		{
			ID:          "al-2",
			IncidentID:  "inc-2",
			SessionID:   "sess-1",
			Prompt:      "Analyze DNS anomaly",
			Response:    "Possible DNS tunneling",
			Reasoning:   "High volume of TXT queries to unusual domain",
			Confidence:  0.72,
			ToolsCalled: "dns",
			Outcome:     "escalated",
			CreatedAt:   now.Add(-1 * time.Second),
		},
		{
			ID:          "al-3",
			IncidentID:  "inc-3",
			SessionID:   "sess-2",
			Prompt:      "Check lateral movement",
			Response:    "No lateral movement detected",
			Reasoning:   "Network connections are normal",
			Confidence:  0.95,
			ToolsCalled: "netstat",
			Outcome:     "cleared",
			CreatedAt:   now,
		},
	}

	for _, l := range logs {
		if err := agentStore.SaveAnalysisLog(l); err != nil {
			t.Fatalf("SaveAnalysisLog(%s): %v", l.ID, err)
		}
	}

	recent, err := agentStore.GetRecentAnalyses(10)
	if err != nil {
		t.Fatalf("GetRecentAnalyses: %v", err)
	}
	if len(recent) != 3 {
		t.Fatalf("expected 3 analysis logs, got %d", len(recent))
	}
	// Most recent first.
	if recent[0].ID != "al-3" {
		t.Errorf("expected first analysis al-3, got %s", recent[0].ID)
	}
	if recent[0].IncidentID != "inc-3" {
		t.Errorf("expected IncidentID inc-3, got %s", recent[0].IncidentID)
	}
	if recent[0].Confidence != 0.95 {
		t.Errorf("expected Confidence 0.95, got %f", recent[0].Confidence)
	}
	if recent[0].Outcome != "cleared" {
		t.Errorf("expected Outcome cleared, got %q", recent[0].Outcome)
	}
}

func TestAgentStore_GetRecentAnalyses_Limit(t *testing.T) {
	store := newTestSQLite(t)
	agentStore := NewAgentStore(store.DB())

	now := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < 5; i++ {
		l := &AnalysisLogRow{
			ID:          "al-lim-" + string(rune('A'+i)),
			IncidentID:  "inc-x",
			SessionID:   "sess-x",
			Prompt:      "prompt",
			Response:    "response",
			Reasoning:   "reasoning",
			Confidence:  0.5,
			ToolsCalled: "",
			Outcome:     "ok",
			CreatedAt:   now.Add(time.Duration(i) * time.Second),
		}
		if err := agentStore.SaveAnalysisLog(l); err != nil {
			t.Fatalf("SaveAnalysisLog: %v", err)
		}
	}

	recent, err := agentStore.GetRecentAnalyses(2)
	if err != nil {
		t.Fatalf("GetRecentAnalyses(2): %v", err)
	}
	if len(recent) != 2 {
		t.Errorf("expected 2 analysis logs, got %d", len(recent))
	}
}

func TestAgentStore_SaveToolExecution(t *testing.T) {
	store := newTestSQLite(t)
	agentStore := NewAgentStore(store.DB())

	now := time.Now().UTC().Truncate(time.Second)
	exec := &ToolExecutionRow{
		ID:            "te-1",
		AnalysisLogID: "al-1",
		ToolName:      "whois",
		Parameters:    `{"ip":"10.0.0.1"}`,
		Result:        `{"org":"Example Corp"}`,
		Success:       true,
		Error:         "",
		ExecutedAt:    now,
	}

	if err := agentStore.SaveToolExecution(exec); err != nil {
		t.Fatalf("SaveToolExecution: %v", err)
	}

	// Verify directly via DB query since there is no getter for individual tool executions.
	var id, toolName, params, result, errStr string
	var success bool
	err := store.DB().QueryRow(
		"SELECT id, tool_name, parameters, result, success, error FROM tool_executions WHERE id = ?", "te-1",
	).Scan(&id, &toolName, &params, &result, &success, &errStr)
	if err != nil {
		t.Fatalf("querying tool_executions: %v", err)
	}
	if id != "te-1" {
		t.Errorf("expected id te-1, got %s", id)
	}
	if toolName != "whois" {
		t.Errorf("expected tool_name whois, got %s", toolName)
	}
	if !success {
		t.Error("expected success=true")
	}
}

func TestAgentStore_SaveToolExecution_WithError(t *testing.T) {
	store := newTestSQLite(t)
	agentStore := NewAgentStore(store.DB())

	now := time.Now().UTC().Truncate(time.Second)
	exec := &ToolExecutionRow{
		ID:            "te-fail",
		AnalysisLogID: "al-1",
		ToolName:      "dns",
		Parameters:    `{"domain":"evil.com"}`,
		Result:        "",
		Success:       false,
		Error:         "DNS lookup timed out",
		ExecutedAt:    now,
	}

	if err := agentStore.SaveToolExecution(exec); err != nil {
		t.Fatalf("SaveToolExecution: %v", err)
	}

	var success bool
	var errStr string
	err := store.DB().QueryRow(
		"SELECT success, error FROM tool_executions WHERE id = ?", "te-fail",
	).Scan(&success, &errStr)
	if err != nil {
		t.Fatalf("querying tool_executions: %v", err)
	}
	if success {
		t.Error("expected success=false for failed execution")
	}
	if errStr != "DNS lookup timed out" {
		t.Errorf("expected error 'DNS lookup timed out', got %q", errStr)
	}
}
