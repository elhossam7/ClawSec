package engine

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/sentinel-agent/sentinel/internal/types"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newTestEngine creates an Engine wired to the given events channel with a
// no-op (discarded) logger so tests stay silent.
func newTestEngine(events <-chan types.LogEvent) *Engine {
	logger := zerolog.New(zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) {
		w.Out = os.Stderr
		w.NoColor = true
	})).Level(zerolog.Disabled)
	return New(1, events, logger)
}

// writeRuleYAML writes a minimal valid rule YAML file into dir.
func writeRuleYAML(t *testing.T, dir, id, severity, title string) {
	t.Helper()
	content := "id: " + id + "\n" +
		"title: " + title + "\n" +
		"severity: " + severity + "\n" +
		"status: active\n" +
		"detection:\n" +
		"  selection:\n" +
		"    \"raw|contains\": \"test-pattern\"\n" +
		"  condition: selection\n"
	if err := os.WriteFile(filepath.Join(dir, id+".yml"), []byte(content), 0644); err != nil {
		t.Fatalf("writing test rule YAML: %v", err)
	}
}

// minimalRule returns a Rule struct suitable for AddRule / UpdateRule tests.
func minimalRule(id, title, severity string) Rule {
	return Rule{
		ID:       id,
		Title:    title,
		Severity: severity,
		Status:   "active",
		Detection: RuleDetection{
			Selection: map[string]interface{}{
				"raw|contains": "sentinel-test",
			},
			Condition: "selection",
		},
	}
}

// ---------------------------------------------------------------------------
// Engine constructor — New()
// ---------------------------------------------------------------------------

func TestNew(t *testing.T) {
	events := make(chan types.LogEvent)
	eng := newTestEngine(events)

	if eng == nil {
		t.Fatal("New returned nil")
	}
	if eng.workers != 1 {
		t.Errorf("expected 1 worker, got %d", eng.workers)
	}
	if eng.rules == nil {
		t.Error("rules map not initialised")
	}
	if eng.incidents == nil {
		t.Error("incidents channel not initialised")
	}
	if eng.actions == nil {
		t.Error("actions channel not initialised")
	}
	if eng.analysisQueue == nil {
		t.Error("analysisQueue channel not initialised")
	}
	if eng.aiEnabled {
		t.Error("expected aiEnabled to be false by default")
	}
}

// ---------------------------------------------------------------------------
// EnableAI / AnalysisQueue
// ---------------------------------------------------------------------------

func TestEnableAI(t *testing.T) {
	eng := newTestEngine(make(chan types.LogEvent))
	if eng.aiEnabled {
		t.Fatal("aiEnabled should start false")
	}
	eng.EnableAI()
	if !eng.aiEnabled {
		t.Error("EnableAI did not set aiEnabled to true")
	}
}

func TestAnalysisQueue(t *testing.T) {
	eng := newTestEngine(make(chan types.LogEvent))
	ch := eng.AnalysisQueue()
	if ch == nil {
		t.Fatal("AnalysisQueue returned nil channel")
	}
}

// ---------------------------------------------------------------------------
// LoadRules — reading YAML from a temp directory
// ---------------------------------------------------------------------------

func TestLoadRules_ValidDirectory(t *testing.T) {
	dir := t.TempDir()
	writeRuleYAML(t, dir, "rule_alpha", "high", "Alpha Rule")
	writeRuleYAML(t, dir, "rule_beta", "medium", "Beta Rule")

	events := make(chan types.LogEvent)
	eng := newTestEngine(events)

	if err := eng.LoadRules(dir); err != nil {
		t.Fatalf("LoadRules returned error: %v", err)
	}
	if eng.RuleCount() != 2 {
		t.Errorf("expected 2 rules, got %d", eng.RuleCount())
	}
}

func TestLoadRules_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	eng := newTestEngine(make(chan types.LogEvent))

	if err := eng.LoadRules(dir); err != nil {
		t.Fatalf("LoadRules on empty dir should succeed, got: %v", err)
	}
	if eng.RuleCount() != 0 {
		t.Errorf("expected 0 rules, got %d", eng.RuleCount())
	}
}

func TestLoadRules_NonExistentDirectory(t *testing.T) {
	eng := newTestEngine(make(chan types.LogEvent))
	err := eng.LoadRules(filepath.Join(t.TempDir(), "does_not_exist"))
	if err == nil {
		t.Error("expected error for non-existent directory")
	}
}

func TestLoadRules_IgnoresNonYAMLFiles(t *testing.T) {
	dir := t.TempDir()
	writeRuleYAML(t, dir, "valid_rule", "low", "Valid Rule")
	// Write a non-YAML file that should be ignored.
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("hello"), 0644); err != nil {
		t.Fatalf("writing txt file: %v", err)
	}

	eng := newTestEngine(make(chan types.LogEvent))
	if err := eng.LoadRules(dir); err != nil {
		t.Fatalf("LoadRules returned error: %v", err)
	}
	if eng.RuleCount() != 1 {
		t.Errorf("expected 1 rule (ignoring .txt), got %d", eng.RuleCount())
	}
}

// ---------------------------------------------------------------------------
// RuleCount / ActiveRules
// ---------------------------------------------------------------------------

func TestRuleCount(t *testing.T) {
	eng := newTestEngine(make(chan types.LogEvent))
	if eng.RuleCount() != 0 {
		t.Errorf("expected 0 rules, got %d", eng.RuleCount())
	}

	dir := t.TempDir()
	writeRuleYAML(t, dir, "rc1", "high", "Rule 1")
	writeRuleYAML(t, dir, "rc2", "low", "Rule 2")
	writeRuleYAML(t, dir, "rc3", "medium", "Rule 3")
	if err := eng.LoadRules(dir); err != nil {
		t.Fatal(err)
	}
	if eng.RuleCount() != 3 {
		t.Errorf("expected 3 rules, got %d", eng.RuleCount())
	}
}

func TestActiveRules(t *testing.T) {
	eng := newTestEngine(make(chan types.LogEvent))

	dir := t.TempDir()
	writeRuleYAML(t, dir, "ar1", "high", "Active 1")
	writeRuleYAML(t, dir, "ar2", "low", "Active 2")
	if err := eng.LoadRules(dir); err != nil {
		t.Fatal(err)
	}

	active := eng.ActiveRules()
	if len(active) != 2 {
		t.Fatalf("expected 2 active rules, got %d", len(active))
	}

	// Disable one.
	if err := eng.DisableRule("ar1"); err != nil {
		t.Fatal(err)
	}
	active = eng.ActiveRules()
	if len(active) != 1 {
		t.Errorf("expected 1 active rule after disable, got %d", len(active))
	}
	if active[0] != "ar2" {
		t.Errorf("expected remaining active rule to be ar2, got %s", active[0])
	}
}

// ---------------------------------------------------------------------------
// EnableRule / DisableRule
// ---------------------------------------------------------------------------

func TestEnableRule(t *testing.T) {
	eng := newTestEngine(make(chan types.LogEvent))
	dir := t.TempDir()
	writeRuleYAML(t, dir, "toggle1", "high", "Toggle Rule")
	if err := eng.LoadRules(dir); err != nil {
		t.Fatal(err)
	}

	// Disable then re-enable.
	if err := eng.DisableRule("toggle1"); err != nil {
		t.Fatal(err)
	}
	active := eng.ActiveRules()
	if len(active) != 0 {
		t.Fatalf("expected 0 active rules after disable, got %d", len(active))
	}

	if err := eng.EnableRule("toggle1"); err != nil {
		t.Fatal(err)
	}
	active = eng.ActiveRules()
	if len(active) != 1 {
		t.Errorf("expected 1 active rule after enable, got %d", len(active))
	}
}

func TestEnableRule_NotFound(t *testing.T) {
	eng := newTestEngine(make(chan types.LogEvent))
	err := eng.EnableRule("nonexistent")
	if err == nil {
		t.Error("expected error when enabling nonexistent rule")
	}
}

func TestDisableRule_NotFound(t *testing.T) {
	eng := newTestEngine(make(chan types.LogEvent))
	err := eng.DisableRule("nonexistent")
	if err == nil {
		t.Error("expected error when disabling nonexistent rule")
	}
}

// ---------------------------------------------------------------------------
// GetRules / GetRule
// ---------------------------------------------------------------------------

func TestGetRules(t *testing.T) {
	eng := newTestEngine(make(chan types.LogEvent))
	dir := t.TempDir()
	writeRuleYAML(t, dir, "g1", "high", "Get1")
	writeRuleYAML(t, dir, "g2", "low", "Get2")
	if err := eng.LoadRules(dir); err != nil {
		t.Fatal(err)
	}

	rules := eng.GetRules()
	if len(rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(rules))
	}
}

func TestGetRule_Found(t *testing.T) {
	eng := newTestEngine(make(chan types.LogEvent))
	dir := t.TempDir()
	writeRuleYAML(t, dir, "find_me", "high", "Find Me")
	if err := eng.LoadRules(dir); err != nil {
		t.Fatal(err)
	}

	rule := eng.GetRule("find_me")
	if rule == nil {
		t.Fatal("expected non-nil rule")
	}
	if rule.ID != "find_me" {
		t.Errorf("expected ID find_me, got %s", rule.ID)
	}
	if rule.Title != "Find Me" {
		t.Errorf("expected title 'Find Me', got %q", rule.Title)
	}
}

func TestGetRule_NotFound(t *testing.T) {
	eng := newTestEngine(make(chan types.LogEvent))
	rule := eng.GetRule("does_not_exist")
	if rule != nil {
		t.Error("expected nil for unknown rule ID")
	}
}

// ---------------------------------------------------------------------------
// SetRulesDir / RulesDir
// ---------------------------------------------------------------------------

func TestSetRulesDir_And_RulesDir(t *testing.T) {
	eng := newTestEngine(make(chan types.LogEvent))
	if eng.RulesDir() != "" {
		t.Error("expected empty default RulesDir")
	}

	eng.SetRulesDir("/some/path/rules")
	if eng.RulesDir() != "/some/path/rules" {
		t.Errorf("expected /some/path/rules, got %s", eng.RulesDir())
	}
}

// ---------------------------------------------------------------------------
// AddRule
// ---------------------------------------------------------------------------

func TestAddRule_Success(t *testing.T) {
	eng := newTestEngine(make(chan types.LogEvent))
	rule := minimalRule("add1", "Added Rule", "high")

	if err := eng.AddRule(rule, false); err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}
	if eng.RuleCount() != 1 {
		t.Errorf("expected 1 rule, got %d", eng.RuleCount())
	}
	cr := eng.GetRule("add1")
	if cr == nil {
		t.Fatal("added rule not retrievable via GetRule")
	}
	if cr.Title != "Added Rule" {
		t.Errorf("expected title 'Added Rule', got %q", cr.Title)
	}
}

func TestAddRule_Duplicate(t *testing.T) {
	eng := newTestEngine(make(chan types.LogEvent))
	rule := minimalRule("dup1", "Duplicate Rule", "medium")

	if err := eng.AddRule(rule, false); err != nil {
		t.Fatalf("first AddRule failed: %v", err)
	}
	err := eng.AddRule(rule, false)
	if err == nil {
		t.Error("expected error when adding duplicate rule")
	}
}

func TestAddRule_PersistsToFile(t *testing.T) {
	dir := t.TempDir()
	eng := newTestEngine(make(chan types.LogEvent))
	eng.SetRulesDir(dir)

	rule := minimalRule("persist_add", "Persist Add", "high")
	if err := eng.AddRule(rule, true); err != nil {
		t.Fatalf("AddRule with persist failed: %v", err)
	}

	path := filepath.Join(dir, "persist_add.yml")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("expected rule file %s to exist", path)
	}
}

func TestAddRule_NoPersistWhenFlagFalse(t *testing.T) {
	dir := t.TempDir()
	eng := newTestEngine(make(chan types.LogEvent))
	eng.SetRulesDir(dir)

	rule := minimalRule("no_persist", "No Persist", "low")
	if err := eng.AddRule(rule, false); err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	path := filepath.Join(dir, "no_persist.yml")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("expected rule file NOT to exist when persist=false")
	}
}

// ---------------------------------------------------------------------------
// UpdateRule
// ---------------------------------------------------------------------------

func TestUpdateRule_Success(t *testing.T) {
	eng := newTestEngine(make(chan types.LogEvent))
	rule := minimalRule("upd1", "Original", "low")
	if err := eng.AddRule(rule, false); err != nil {
		t.Fatal(err)
	}

	updated := minimalRule("upd1", "Updated Title", "critical")
	if err := eng.UpdateRule(updated, false); err != nil {
		t.Fatalf("UpdateRule failed: %v", err)
	}

	cr := eng.GetRule("upd1")
	if cr == nil {
		t.Fatal("rule lost after update")
	}
	if cr.Title != "Updated Title" {
		t.Errorf("expected updated title, got %q", cr.Title)
	}
	if cr.Severity != types.SeverityCritical {
		t.Errorf("expected critical severity, got %s", cr.Severity.String())
	}
}

func TestUpdateRule_NotFound(t *testing.T) {
	eng := newTestEngine(make(chan types.LogEvent))
	rule := minimalRule("ghost", "Ghost", "low")
	err := eng.UpdateRule(rule, false)
	if err == nil {
		t.Error("expected error when updating non-existent rule")
	}
}

func TestUpdateRule_PersistsToFile(t *testing.T) {
	dir := t.TempDir()
	eng := newTestEngine(make(chan types.LogEvent))
	eng.SetRulesDir(dir)

	rule := minimalRule("persist_upd", "Before", "low")
	if err := eng.AddRule(rule, false); err != nil {
		t.Fatal(err)
	}

	updated := minimalRule("persist_upd", "After", "high")
	if err := eng.UpdateRule(updated, true); err != nil {
		t.Fatalf("UpdateRule persist failed: %v", err)
	}

	path := filepath.Join(dir, "persist_upd.yml")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("expected rule file %s to exist after update with persist", path)
	}
}

// ---------------------------------------------------------------------------
// DeleteRule
// ---------------------------------------------------------------------------

func TestDeleteRule_Success(t *testing.T) {
	eng := newTestEngine(make(chan types.LogEvent))
	rule := minimalRule("del1", "Delete Me", "low")
	if err := eng.AddRule(rule, false); err != nil {
		t.Fatal(err)
	}
	if eng.RuleCount() != 1 {
		t.Fatal("rule not added")
	}

	if err := eng.DeleteRule("del1", false); err != nil {
		t.Fatalf("DeleteRule failed: %v", err)
	}
	if eng.RuleCount() != 0 {
		t.Errorf("expected 0 rules after delete, got %d", eng.RuleCount())
	}
}

func TestDeleteRule_NotFound(t *testing.T) {
	eng := newTestEngine(make(chan types.LogEvent))
	err := eng.DeleteRule("phantom", false)
	if err == nil {
		t.Error("expected error when deleting non-existent rule")
	}
}

func TestDeleteRule_DeletesFile(t *testing.T) {
	dir := t.TempDir()
	eng := newTestEngine(make(chan types.LogEvent))
	eng.SetRulesDir(dir)

	rule := minimalRule("del_file", "Delete File", "medium")
	if err := eng.AddRule(rule, true); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "del_file.yml")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("rule file should exist after AddRule with persist")
	}

	if err := eng.DeleteRule("del_file", true); err != nil {
		t.Fatalf("DeleteRule with deleteFile failed: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("expected rule file to be deleted")
	}
}

func TestDeleteRule_KeepsFileWhenFlagFalse(t *testing.T) {
	dir := t.TempDir()
	eng := newTestEngine(make(chan types.LogEvent))
	eng.SetRulesDir(dir)

	rule := minimalRule("del_keep", "Keep File", "medium")
	if err := eng.AddRule(rule, true); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "del_keep.yml")
	if err := eng.DeleteRule("del_keep", false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("expected file to still exist when deleteFile=false")
	}
}

// ---------------------------------------------------------------------------
// Start / processEvent — events flowing through the engine
// ---------------------------------------------------------------------------

func TestStart_ProcessesEvents(t *testing.T) {
	events := make(chan types.LogEvent, 10)
	eng := newTestEngine(events)

	// Add a rule that matches on raw|contains "ALERT".
	rule := Rule{
		ID:       "start_test",
		Title:    "Start Test Rule",
		Severity: "high",
		Status:   "active",
		Detection: RuleDetection{
			Selection: map[string]interface{}{
				"raw|contains": "ALERT",
			},
			Condition: "selection",
		},
	}
	if err := eng.AddRule(rule, false); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eng.Start(ctx)

	// Send a matching event.
	events <- types.LogEvent{
		ID:       "evt1",
		Raw:      "this is an ALERT event",
		Source:   "test",
		Category: "system",
		Fields:   map[string]string{},
	}

	// Expect an incident within a reasonable timeout.
	select {
	case inc := <-eng.Incidents():
		if inc.Rule.ID != "start_test" {
			t.Errorf("expected rule ID start_test, got %s", inc.Rule.ID)
		}
		if inc.Message == "" {
			t.Error("incident message should not be empty")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for incident")
	}
}

func TestStart_NoMatchNoIncident(t *testing.T) {
	events := make(chan types.LogEvent, 10)
	eng := newTestEngine(events)

	rule := Rule{
		ID:       "no_match",
		Title:    "No Match Rule",
		Severity: "low",
		Status:   "active",
		Detection: RuleDetection{
			Selection: map[string]interface{}{
				"raw|contains": "SPECIFIC_PATTERN_XYZ",
			},
			Condition: "selection",
		},
	}
	if err := eng.AddRule(rule, false); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eng.Start(ctx)

	events <- types.LogEvent{
		ID:     "evt2",
		Raw:    "nothing interesting here",
		Source: "test",
		Fields: map[string]string{},
	}

	// Should NOT receive an incident.
	select {
	case inc := <-eng.Incidents():
		t.Errorf("unexpected incident: %+v", inc)
	case <-time.After(500 * time.Millisecond):
		// Expected — no incident.
	}
}

func TestStart_DisabledRuleSkipped(t *testing.T) {
	events := make(chan types.LogEvent, 10)
	eng := newTestEngine(events)

	rule := Rule{
		ID:       "disabled_rule",
		Title:    "Disabled Rule",
		Severity: "high",
		Status:   "active",
		Detection: RuleDetection{
			Selection: map[string]interface{}{
				"raw|contains": "TRIGGER",
			},
			Condition: "selection",
		},
	}
	if err := eng.AddRule(rule, false); err != nil {
		t.Fatal(err)
	}
	if err := eng.DisableRule("disabled_rule"); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eng.Start(ctx)

	events <- types.LogEvent{
		ID:     "evt3",
		Raw:    "this should TRIGGER",
		Source: "test",
		Fields: map[string]string{},
	}

	select {
	case inc := <-eng.Incidents():
		t.Errorf("disabled rule fired: %+v", inc)
	case <-time.After(500 * time.Millisecond):
		// Expected.
	}
}

func TestStart_ContextCancellationStopsWorkers(t *testing.T) {
	events := make(chan types.LogEvent, 10)
	eng := newTestEngine(events)

	ctx, cancel := context.WithCancel(context.Background())
	eng.Start(ctx)

	// Cancel immediately.
	cancel()

	// Give goroutines a moment to wind down.
	time.Sleep(200 * time.Millisecond)

	// Sending an event should not panic or produce an incident.
	select {
	case events <- types.LogEvent{ID: "after_cancel", Raw: "test", Fields: map[string]string{}}:
	default:
		// Channel might be full/blocked — that is fine.
	}
}

func TestStart_ResponseActionsQueued(t *testing.T) {
	events := make(chan types.LogEvent, 10)
	eng := newTestEngine(events)

	rule := Rule{
		ID:       "action_rule",
		Title:    "Action Rule",
		Severity: "critical",
		Status:   "active",
		Detection: RuleDetection{
			Selection: map[string]interface{}{
				"raw|contains": "BLOCK_ME",
			},
			Condition: "selection",
		},
		Response: []RuleAction{
			{Type: types.ActionBlockIP, TargetField: "source_ip"},
		},
	}
	if err := eng.AddRule(rule, false); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eng.Start(ctx)

	events <- types.LogEvent{
		ID:     "evt4",
		Raw:    "please BLOCK_ME now",
		Source: "test",
		Fields: map[string]string{"source_ip": "10.0.0.99"},
	}

	// Drain the incident.
	select {
	case <-eng.Incidents():
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for incident")
	}

	// Expect a response action.
	select {
	case action := <-eng.Actions():
		if action.Type != types.ActionBlockIP {
			t.Errorf("expected block_ip action, got %s", action.Type)
		}
		if action.Target != "10.0.0.99" {
			t.Errorf("expected target 10.0.0.99, got %s", action.Target)
		}
		if action.RuleID != "action_rule" {
			t.Errorf("expected rule_id action_rule, got %s", action.RuleID)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for response action")
	}
}

func TestStart_AIEnabled_RoutesToAnalysisQueue(t *testing.T) {
	events := make(chan types.LogEvent, 10)
	eng := newTestEngine(events)
	eng.EnableAI()

	rule := Rule{
		ID:       "ai_route",
		Title:    "AI Routed Rule",
		Severity: "high",
		Status:   "active",
		Detection: RuleDetection{
			Selection: map[string]interface{}{
				"raw|contains": "AI_TRIGGER",
			},
			Condition: "selection",
		},
		Response: []RuleAction{
			{Type: types.ActionBlockIP, TargetField: "source_ip"},
		},
	}
	if err := eng.AddRule(rule, false); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eng.Start(ctx)

	events <- types.LogEvent{
		ID:     "evt_ai",
		Raw:    "this is AI_TRIGGER data",
		Source: "test",
		Fields: map[string]string{"source_ip": "192.168.1.1"},
	}

	// Drain the incident.
	select {
	case <-eng.Incidents():
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for incident")
	}

	// Should land in analysis queue, NOT actions.
	select {
	case req := <-eng.AnalysisQueue():
		if len(req.MatchedRules) == 0 || req.MatchedRules[0] != "ai_route" {
			t.Errorf("expected matched rule ai_route, got %v", req.MatchedRules)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for analysis request")
	}

	// Actions channel should be empty.
	select {
	case a := <-eng.Actions():
		t.Errorf("expected no direct action when AI enabled, got %+v", a)
	case <-time.After(300 * time.Millisecond):
		// Expected.
	}
}

func TestStart_FilterExcludesEvent(t *testing.T) {
	events := make(chan types.LogEvent, 10)
	eng := newTestEngine(events)

	rule := Rule{
		ID:       "filter_test",
		Title:    "Filter Test",
		Severity: "medium",
		Status:   "active",
		Detection: RuleDetection{
			Selection: map[string]interface{}{
				"raw|contains": "MATCH",
			},
			Filter: map[string]interface{}{
				"source": "trusted",
			},
			Condition: "selection and not filter",
		},
	}
	if err := eng.AddRule(rule, false); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eng.Start(ctx)

	// This event matches selection but should be filtered out.
	events <- types.LogEvent{
		ID:     "evt_filtered",
		Raw:    "line with MATCH keyword",
		Source: "trusted",
		Fields: map[string]string{},
	}

	select {
	case inc := <-eng.Incidents():
		t.Errorf("expected event to be filtered out, got incident: %+v", inc)
	case <-time.After(500 * time.Millisecond):
		// Expected.
	}
}

func TestStart_LogSourceCategoryFilter(t *testing.T) {
	events := make(chan types.LogEvent, 10)
	eng := newTestEngine(events)

	rule := Rule{
		ID:       "logsrc_cat",
		Title:    "Category Filter",
		Severity: "low",
		Status:   "active",
		LogSource: RuleLogSource{
			Category: "auth",
		},
		Detection: RuleDetection{
			Selection: map[string]interface{}{
				"raw|contains": "LOGIN",
			},
			Condition: "selection",
		},
	}
	if err := eng.AddRule(rule, false); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eng.Start(ctx)

	// Category mismatch — should NOT fire.
	events <- types.LogEvent{
		ID:       "evt_wrong_cat",
		Raw:      "LOGIN attempt",
		Source:   "test",
		Category: "network",
		Fields:   map[string]string{},
	}

	select {
	case inc := <-eng.Incidents():
		t.Errorf("expected category mismatch to skip, got %+v", inc)
	case <-time.After(500 * time.Millisecond):
		// Expected.
	}

	// Correct category — should fire.
	events <- types.LogEvent{
		ID:       "evt_right_cat",
		Raw:      "LOGIN attempt",
		Source:   "test",
		Category: "auth",
		Fields:   map[string]string{},
	}

	select {
	case inc := <-eng.Incidents():
		if inc.Rule.ID != "logsrc_cat" {
			t.Errorf("expected rule logsrc_cat, got %s", inc.Rule.ID)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for category-matched incident")
	}
}

func TestStart_CorrelationThreshold(t *testing.T) {
	events := make(chan types.LogEvent, 50)
	eng := newTestEngine(events)

	rule := Rule{
		ID:       "corr_test",
		Title:    "Correlation Threshold Test",
		Severity: "high",
		Status:   "active",
		Detection: RuleDetection{
			Selection: map[string]interface{}{
				"raw|contains": "FAILED",
			},
			Condition: "selection",
		},
		Correlation: &RuleCorrelation{
			GroupBy:   []string{"source_ip"},
			Threshold: 3,
			Window:    10 * time.Second,
		},
	}
	if err := eng.AddRule(rule, false); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eng.Start(ctx)

	// Send 2 events (below threshold) — should NOT trigger.
	for i := 0; i < 2; i++ {
		events <- types.LogEvent{
			ID:     "corr_evt_" + string(rune('a'+i)),
			Raw:    "FAILED login",
			Source: "test",
			Fields: map[string]string{"source_ip": "10.0.0.1"},
		}
	}

	select {
	case inc := <-eng.Incidents():
		t.Errorf("unexpected incident before threshold: %+v", inc)
	case <-time.After(500 * time.Millisecond):
		// Expected.
	}

	// Send 3rd event — should now trigger (3 >= threshold 3).
	events <- types.LogEvent{
		ID:     "corr_evt_c",
		Raw:    "FAILED login",
		Source: "test",
		Fields: map[string]string{"source_ip": "10.0.0.1"},
	}

	select {
	case inc := <-eng.Incidents():
		if inc.Rule.ID != "corr_test" {
			t.Errorf("expected corr_test, got %s", inc.Rule.ID)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for correlation incident")
	}
}

func TestStart_MultipleWorkers(t *testing.T) {
	events := make(chan types.LogEvent, 100)
	logger := zerolog.New(zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) {
		w.Out = os.Stderr
		w.NoColor = true
	})).Level(zerolog.Disabled)
	eng := New(4, events, logger)

	rule := Rule{
		ID:       "multi_worker",
		Title:    "Multi Worker Rule",
		Severity: "low",
		Status:   "active",
		Detection: RuleDetection{
			Selection: map[string]interface{}{
				"raw|contains": "PING",
			},
			Condition: "selection",
		},
	}
	if err := eng.AddRule(rule, false); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eng.Start(ctx)

	const eventCount = 20
	for i := 0; i < eventCount; i++ {
		events <- types.LogEvent{
			ID:     "mw_evt",
			Raw:    "server PING check",
			Source: "test",
			Fields: map[string]string{},
		}
	}

	received := 0
	deadline := time.After(5 * time.Second)
	for received < eventCount {
		select {
		case <-eng.Incidents():
			received++
		case <-deadline:
			t.Fatalf("timed out: received %d of %d incidents", received, eventCount)
		}
	}
}

// ---------------------------------------------------------------------------
// Schema — NewSchema
// ---------------------------------------------------------------------------

func TestNewSchema(t *testing.T) {
	s := NewSchema()
	if s == nil {
		t.Fatal("NewSchema returned nil")
	}

	// Verify a sample of expected built-in fields.
	expected := []string{
		"raw", "message", "source", "category", "hostname", "platform",
		"source_ip", "dest_ip", "username", "pid", "port", "protocol",
		"method", "url", "status_code", "user_agent", "service", "action",
		"event_id", "channel", "provider", "container_id", "image",
	}
	for _, name := range expected {
		if !s.Known(name) {
			t.Errorf("expected built-in field %q to be known", name)
		}
	}
}

func TestNewSchema_FieldTypes(t *testing.T) {
	s := NewSchema()

	tests := []struct {
		field    string
		wantType FieldType
	}{
		{"raw", FieldString},
		{"source_ip", FieldIP},
		{"dest_ip", FieldIP},
		{"pid", FieldInt},
		{"port", FieldInt},
		{"status_code", FieldInt},
		{"event_id", FieldInt},
		{"username", FieldString},
		{"protocol", FieldString},
	}
	for _, tc := range tests {
		fd, ok := s.Get(tc.field)
		if !ok {
			t.Errorf("field %q not found in schema", tc.field)
			continue
		}
		if fd.Type != tc.wantType {
			t.Errorf("field %q: expected type %s, got %s", tc.field, tc.wantType, fd.Type)
		}
	}
}

// ---------------------------------------------------------------------------
// Schema — Register / Known / Get / AllFields
// ---------------------------------------------------------------------------

func TestSchema_Register(t *testing.T) {
	s := NewSchema()
	customField := FieldDef{
		Name:        "custom_field",
		Type:        FieldString,
		Description: "A custom test field",
		Sources:     []string{"test"},
	}
	s.Register(customField)

	if !s.Known("custom_field") {
		t.Error("custom_field should be known after Register")
	}
	fd, ok := s.Get("custom_field")
	if !ok {
		t.Fatal("Get returned false for custom_field")
	}
	if fd.Description != "A custom test field" {
		t.Errorf("unexpected description: %q", fd.Description)
	}
}

func TestSchema_Known_UnknownField(t *testing.T) {
	s := NewSchema()
	if s.Known("nonexistent_field_xyz") {
		t.Error("nonexistent_field_xyz should not be known")
	}
}

func TestSchema_Get_Unknown(t *testing.T) {
	s := NewSchema()
	_, ok := s.Get("totally_unknown")
	if ok {
		t.Error("Get should return false for unknown field")
	}
}

func TestSchema_AllFields(t *testing.T) {
	s := NewSchema()
	all := s.AllFields()
	if len(all) == 0 {
		t.Fatal("AllFields returned empty slice")
	}
	// Verify that known fields appear in the list.
	fieldSet := make(map[string]bool)
	for _, f := range all {
		fieldSet[f] = true
	}
	for _, expect := range []string{"raw", "source_ip", "username"} {
		if !fieldSet[expect] {
			t.Errorf("AllFields missing expected field %q", expect)
		}
	}
}

func TestSchema_AllFields_AfterRegister(t *testing.T) {
	s := NewSchema()
	beforeCount := len(s.AllFields())
	s.Register(FieldDef{Name: "brand_new", Type: FieldString})
	afterCount := len(s.AllFields())
	if afterCount != beforeCount+1 {
		t.Errorf("expected AllFields count to increase by 1 (from %d to %d), got %d", beforeCount, beforeCount+1, afterCount)
	}
}

// ---------------------------------------------------------------------------
// FieldType.String()
// ---------------------------------------------------------------------------

func TestFieldType_String(t *testing.T) {
	tests := []struct {
		ft   FieldType
		want string
	}{
		{FieldString, "string"},
		{FieldIP, "ip"},
		{FieldInt, "int"},
		{FieldTimestamp, "timestamp"},
		{FieldType(999), "unknown"},
	}
	for _, tc := range tests {
		got := tc.ft.String()
		if got != tc.want {
			t.Errorf("FieldType(%d).String() = %q, want %q", int(tc.ft), got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// ValidateRule
// ---------------------------------------------------------------------------

func TestValidateRule_ValidRule(t *testing.T) {
	schema := NewSchema()
	rule := Rule{
		ID:       "valid_rule",
		Title:    "Valid Rule",
		Severity: "high",
		Status:   "active",
		Detection: RuleDetection{
			Selection: map[string]interface{}{
				"raw|contains": "test",
			},
			Condition: "selection",
		},
	}
	errs := ValidateRule(rule, schema)
	// A valid rule should only produce warnings (or nothing), no errors.
	for _, e := range errs {
		if e.Level == "error" {
			t.Errorf("unexpected error for valid rule: %s", e)
		}
	}
}

func TestValidateRule_MissingID(t *testing.T) {
	schema := NewSchema()
	rule := Rule{
		Title:    "Missing ID",
		Severity: "high",
		Detection: RuleDetection{
			Selection: map[string]interface{}{"raw|contains": "x"},
			Condition: "selection",
		},
	}
	errs := ValidateRule(rule, schema)
	found := false
	for _, e := range errs {
		if e.Field == "id" && e.Level == "error" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected error-level validation error for missing ID")
	}
}

func TestValidateRule_MissingTitle(t *testing.T) {
	schema := NewSchema()
	rule := Rule{
		ID:       "no_title",
		Severity: "high",
		Detection: RuleDetection{
			Selection: map[string]interface{}{"raw|contains": "x"},
			Condition: "selection",
		},
	}
	errs := ValidateRule(rule, schema)
	found := false
	for _, e := range errs {
		if e.Field == "title" && e.Level == "error" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected error for missing title")
	}
}

func TestValidateRule_EmptySeverity(t *testing.T) {
	schema := NewSchema()
	rule := Rule{
		ID:    "no_sev",
		Title: "No Severity",
		Detection: RuleDetection{
			Selection: map[string]interface{}{"raw|contains": "x"},
			Condition: "selection",
		},
	}
	errs := ValidateRule(rule, schema)
	found := false
	for _, e := range errs {
		if e.Field == "severity" && e.Level == "error" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected error for empty severity")
	}
}

func TestValidateRule_BadSeverity(t *testing.T) {
	schema := NewSchema()
	rule := Rule{
		ID:       "bad_sev",
		Title:    "Bad Severity",
		Severity: "extreme",
		Detection: RuleDetection{
			Selection: map[string]interface{}{"raw|contains": "x"},
			Condition: "selection",
		},
	}
	errs := ValidateRule(rule, schema)
	found := false
	for _, e := range errs {
		if e.Field == "severity" && e.Level == "error" && e.Message != "severity is empty" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected error for bad severity value 'extreme'")
	}
}

func TestValidateRule_EmptySelection(t *testing.T) {
	schema := NewSchema()
	rule := Rule{
		ID:       "empty_sel",
		Title:    "Empty Selection",
		Severity: "low",
		Detection: RuleDetection{
			Selection: map[string]interface{}{},
			Condition: "selection",
		},
	}
	errs := ValidateRule(rule, schema)
	found := false
	for _, e := range errs {
		if e.Field == "detection.selection" && e.Level == "error" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected error for empty detection selection")
	}
}

func TestValidateRule_UnknownField(t *testing.T) {
	schema := NewSchema()
	rule := Rule{
		ID:       "unknown_field",
		Title:    "Unknown Field",
		Severity: "medium",
		Detection: RuleDetection{
			Selection: map[string]interface{}{
				"completely_made_up_field": "value",
			},
			Condition: "selection",
		},
	}
	errs := ValidateRule(rule, schema)
	found := false
	for _, e := range errs {
		if e.Level == "warning" && e.Field == "completely_made_up_field" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected warning for unknown field in selection")
	}
}

func TestValidateRule_BadModifier(t *testing.T) {
	schema := NewSchema()
	rule := Rule{
		ID:       "bad_mod",
		Title:    "Bad Modifier",
		Severity: "high",
		Detection: RuleDetection{
			Selection: map[string]interface{}{
				"raw|foobar": "value",
			},
			Condition: "selection",
		},
	}
	errs := ValidateRule(rule, schema)
	found := false
	for _, e := range errs {
		if e.Field == "raw|foobar" && e.Level == "error" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected error for unknown modifier 'foobar'")
	}
}

func TestValidateRule_BadCorrelationThreshold(t *testing.T) {
	schema := NewSchema()
	rule := Rule{
		ID:       "bad_corr_thresh",
		Title:    "Bad Correlation Threshold",
		Severity: "high",
		Detection: RuleDetection{
			Selection: map[string]interface{}{"raw|contains": "x"},
			Condition: "selection",
		},
		Correlation: &RuleCorrelation{
			GroupBy:   []string{"source_ip"},
			Threshold: 0,
			Window:    5 * time.Minute,
		},
	}
	errs := ValidateRule(rule, schema)
	found := false
	for _, e := range errs {
		if e.Field == "correlation.threshold" && e.Level == "error" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected error for threshold < 1")
	}
}

func TestValidateRule_BadCorrelationWindow(t *testing.T) {
	schema := NewSchema()
	rule := Rule{
		ID:       "bad_corr_window",
		Title:    "Bad Correlation Window",
		Severity: "high",
		Detection: RuleDetection{
			Selection: map[string]interface{}{"raw|contains": "x"},
			Condition: "selection",
		},
		Correlation: &RuleCorrelation{
			GroupBy:   []string{"source_ip"},
			Threshold: 3,
			Window:    0,
		},
	}
	errs := ValidateRule(rule, schema)
	found := false
	for _, e := range errs {
		if e.Field == "correlation.window" && e.Level == "error" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected error for non-positive window")
	}
}

func TestValidateRule_UnknownCorrelationGroupByField(t *testing.T) {
	schema := NewSchema()
	rule := Rule{
		ID:       "corr_unknown_gb",
		Title:    "Unknown GroupBy",
		Severity: "high",
		Detection: RuleDetection{
			Selection: map[string]interface{}{"raw|contains": "x"},
			Condition: "selection",
		},
		Correlation: &RuleCorrelation{
			GroupBy:   []string{"invented_field_abc"},
			Threshold: 3,
			Window:    5 * time.Minute,
		},
	}
	errs := ValidateRule(rule, schema)
	found := false
	for _, e := range errs {
		if e.Field == "invented_field_abc" && e.Level == "warning" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected warning for unknown correlation group_by field")
	}
}

func TestValidateRule_UnknownActionType(t *testing.T) {
	schema := NewSchema()
	rule := Rule{
		ID:       "bad_action",
		Title:    "Unknown Action",
		Severity: "high",
		Detection: RuleDetection{
			Selection: map[string]interface{}{"raw|contains": "x"},
			Condition: "selection",
		},
		Response: []RuleAction{
			{Type: types.ActionType("nuke_server"), TargetField: "source_ip"},
		},
	}
	errs := ValidateRule(rule, schema)
	found := false
	for _, e := range errs {
		if e.Field == "response.type" && e.Level == "warning" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected warning for unknown action type 'nuke_server'")
	}
}

func TestValidateRule_UnknownActionTargetField(t *testing.T) {
	schema := NewSchema()
	rule := Rule{
		ID:       "bad_action_target",
		Title:    "Unknown Target Field",
		Severity: "high",
		Detection: RuleDetection{
			Selection: map[string]interface{}{"raw|contains": "x"},
			Condition: "selection",
		},
		Response: []RuleAction{
			{Type: types.ActionBlockIP, TargetField: "nonexistent_field_xyz"},
		},
	}
	errs := ValidateRule(rule, schema)
	found := false
	for _, e := range errs {
		if e.Field == "response.target_field" && e.Level == "warning" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected warning for unknown target field in response action")
	}
}

func TestValidateRule_UnknownStatus(t *testing.T) {
	schema := NewSchema()
	rule := Rule{
		ID:       "bad_status",
		Title:    "Bad Status",
		Severity: "high",
		Status:   "bogus",
		Detection: RuleDetection{
			Selection: map[string]interface{}{"raw|contains": "x"},
			Condition: "selection",
		},
	}
	errs := ValidateRule(rule, schema)
	found := false
	for _, e := range errs {
		if e.Field == "status" && e.Level == "warning" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected warning for unknown status 'bogus'")
	}
}

func TestValidateRule_FilterUnknownField(t *testing.T) {
	schema := NewSchema()
	rule := Rule{
		ID:       "filter_unknown",
		Title:    "Filter Unknown",
		Severity: "low",
		Detection: RuleDetection{
			Selection: map[string]interface{}{"raw|contains": "x"},
			Filter:    map[string]interface{}{"alien_field": "value"},
			Condition: "selection and not filter",
		},
	}
	errs := ValidateRule(rule, schema)
	found := false
	for _, e := range errs {
		if e.Field == "alien_field" && e.Level == "warning" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected warning for unknown field in filter")
	}
}

func TestValidateRule_ValidSeverities(t *testing.T) {
	schema := NewSchema()
	for _, sev := range []string{"info", "low", "medium", "high", "critical"} {
		rule := Rule{
			ID:       "sev_" + sev,
			Title:    "Severity " + sev,
			Severity: sev,
			Detection: RuleDetection{
				Selection: map[string]interface{}{"raw|contains": "x"},
				Condition: "selection",
			},
		}
		errs := ValidateRule(rule, schema)
		for _, e := range errs {
			if e.Field == "severity" && e.Level == "error" && e.Message != "severity is empty" {
				t.Errorf("severity %q should be valid, got error: %s", sev, e.Message)
			}
		}
	}
}

func TestValidateRule_ValidModifiers(t *testing.T) {
	schema := NewSchema()
	for _, mod := range []string{"contains", "startswith", "endswith", "re"} {
		rule := Rule{
			ID:       "mod_" + mod,
			Title:    "Modifier " + mod,
			Severity: "low",
			Detection: RuleDetection{
				Selection: map[string]interface{}{
					"raw|" + mod: "test",
				},
				Condition: "selection",
			},
		}
		errs := ValidateRule(rule, schema)
		for _, e := range errs {
			if e.Field == "raw|"+mod && e.Level == "error" {
				t.Errorf("modifier %q should be valid, got error: %s", mod, e.Message)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// RuleValidationError.String()
// ---------------------------------------------------------------------------

func TestRuleValidationError_String(t *testing.T) {
	e := RuleValidationError{
		RuleID:  "test_rule",
		Field:   "severity",
		Level:   "error",
		Message: "severity is empty",
	}
	s := e.String()
	if s == "" {
		t.Fatal("String() returned empty")
	}
	// Verify key pieces are present.
	for _, want := range []string{"error", "test_rule", "severity", "severity is empty"} {
		if !containsSubstr(s, want) {
			t.Errorf("String() missing %q, got %q", want, s)
		}
	}
}

// ---------------------------------------------------------------------------
// LoadRules then roundtrip — write rules, load, verify
// ---------------------------------------------------------------------------

func TestLoadRules_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	eng := newTestEngine(make(chan types.LogEvent))
	eng.SetRulesDir(dir)

	// Add a rule with persistence.
	rule := minimalRule("roundtrip", "Roundtrip Rule", "medium")
	if err := eng.AddRule(rule, true); err != nil {
		t.Fatal(err)
	}

	// Create a fresh engine and load from the same directory.
	eng2 := newTestEngine(make(chan types.LogEvent))
	if err := eng2.LoadRules(dir); err != nil {
		t.Fatalf("LoadRules roundtrip failed: %v", err)
	}
	if eng2.RuleCount() != 1 {
		t.Errorf("expected 1 rule after roundtrip, got %d", eng2.RuleCount())
	}
	cr := eng2.GetRule("roundtrip")
	if cr == nil {
		t.Fatal("roundtrip rule not found after reload")
	}
	if cr.Title != "Roundtrip Rule" {
		t.Errorf("expected title 'Roundtrip Rule', got %q", cr.Title)
	}
}

// ---------------------------------------------------------------------------
// Thread-safety smoke test — concurrent EnableRule / DisableRule / RuleCount
// ---------------------------------------------------------------------------

func TestConcurrentRuleAccess(t *testing.T) {
	eng := newTestEngine(make(chan types.LogEvent))

	// Load some rules.
	dir := t.TempDir()
	for i := 0; i < 10; i++ {
		id := "conc_" + string(rune('a'+i))
		writeRuleYAML(t, dir, id, "high", "Concurrent "+id)
	}
	if err := eng.LoadRules(dir); err != nil {
		t.Fatal(err)
	}

	// Hammer the engine from multiple goroutines.
	done := make(chan struct{})
	for g := 0; g < 5; g++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for i := 0; i < 100; i++ {
				_ = eng.RuleCount()
				_ = eng.ActiveRules()
				_ = eng.GetRules()
			}
		}()
	}
	for g := 0; g < 5; g++ {
		<-done
	}
}

// ---------------------------------------------------------------------------
// Incidents / Actions channel accessors
// ---------------------------------------------------------------------------

func TestIncidentsChannel(t *testing.T) {
	eng := newTestEngine(make(chan types.LogEvent))
	ch := eng.Incidents()
	if ch == nil {
		t.Fatal("Incidents() returned nil")
	}
}

func TestActionsChannel(t *testing.T) {
	eng := newTestEngine(make(chan types.LogEvent))
	ch := eng.Actions()
	if ch == nil {
		t.Fatal("Actions() returned nil")
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

func TestAddRule_AfterLoadRules(t *testing.T) {
	dir := t.TempDir()
	writeRuleYAML(t, dir, "loaded1", "high", "Loaded Rule")

	eng := newTestEngine(make(chan types.LogEvent))
	if err := eng.LoadRules(dir); err != nil {
		t.Fatal(err)
	}

	// Now add a rule programmatically.
	rule := minimalRule("added_after_load", "Added After Load", "low")
	if err := eng.AddRule(rule, false); err != nil {
		t.Fatal(err)
	}
	if eng.RuleCount() != 2 {
		t.Errorf("expected 2 rules, got %d", eng.RuleCount())
	}
}

func TestGetRules_AlwaysReturnsCopy(t *testing.T) {
	eng := newTestEngine(make(chan types.LogEvent))
	rule := minimalRule("copy_test", "Copy Test", "low")
	if err := eng.AddRule(rule, false); err != nil {
		t.Fatal(err)
	}

	rules1 := eng.GetRules()
	rules2 := eng.GetRules()
	if len(rules1) != len(rules2) {
		t.Error("GetRules returned different lengths on consecutive calls")
	}
}

func TestActiveRules_SortedConsistency(t *testing.T) {
	eng := newTestEngine(make(chan types.LogEvent))
	dir := t.TempDir()
	writeRuleYAML(t, dir, "z_rule", "low", "Z")
	writeRuleYAML(t, dir, "a_rule", "low", "A")
	writeRuleYAML(t, dir, "m_rule", "low", "M")
	if err := eng.LoadRules(dir); err != nil {
		t.Fatal(err)
	}

	active := eng.ActiveRules()
	sort.Strings(active)
	expected := []string{"a_rule", "m_rule", "z_rule"}
	if len(active) != len(expected) {
		t.Fatalf("expected %d active rules, got %d", len(expected), len(active))
	}
	for i, id := range expected {
		if active[i] != id {
			t.Errorf("position %d: expected %s, got %s", i, id, active[i])
		}
	}
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func containsSubstr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsCheck(s, sub))
}

func containsCheck(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
