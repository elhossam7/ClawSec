package types

import (
	"encoding/json"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Severity.String()
// ---------------------------------------------------------------------------

func TestSeverity_String(t *testing.T) {
	tests := []struct {
		name     string
		severity Severity
		want     string
	}{
		{name: "info", severity: SeverityInfo, want: "info"},
		{name: "low", severity: SeverityLow, want: "low"},
		{name: "medium", severity: SeverityMedium, want: "medium"},
		{name: "high", severity: SeverityHigh, want: "high"},
		{name: "critical", severity: SeverityCritical, want: "critical"},
		{name: "invalid positive", severity: Severity(99), want: "unknown"},
		{name: "invalid negative", severity: Severity(-1), want: "unknown"},
		{name: "boundary above critical", severity: Severity(5), want: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.severity.String()
			if got != tt.want {
				t.Errorf("Severity(%d).String() = %q, want %q", int(tt.severity), got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ParseSeverity()
// ---------------------------------------------------------------------------

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  Severity
	}{
		{name: "info", input: "info", want: SeverityInfo},
		{name: "low", input: "low", want: SeverityLow},
		{name: "medium", input: "medium", want: SeverityMedium},
		{name: "high", input: "high", want: SeverityHigh},
		{name: "critical", input: "critical", want: SeverityCritical},
		{name: "empty string defaults to info", input: "", want: SeverityInfo},
		{name: "unknown string defaults to info", input: "banana", want: SeverityInfo},
		{name: "uppercase INFO defaults to info", input: "INFO", want: SeverityInfo},
		{name: "mixed case High defaults to info", input: "High", want: SeverityInfo},
		{name: "numeric string defaults to info", input: "3", want: SeverityInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseSeverity(tt.input)
			if got != tt.want {
				t.Errorf("ParseSeverity(%q) = %d (%s), want %d (%s)",
					tt.input, int(got), got.String(), int(tt.want), tt.want.String())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Severity round-trip: String -> Parse -> String
// ---------------------------------------------------------------------------

func TestSeverityRoundTrip(t *testing.T) {
	severities := []Severity{
		SeverityInfo,
		SeverityLow,
		SeverityMedium,
		SeverityHigh,
		SeverityCritical,
	}

	for _, sev := range severities {
		t.Run(sev.String(), func(t *testing.T) {
			parsed := ParseSeverity(sev.String())
			if parsed != sev {
				t.Errorf("round-trip failed: started with %d (%s), got %d (%s)",
					int(sev), sev.String(), int(parsed), parsed.String())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Severity iota values
// ---------------------------------------------------------------------------

func TestSeverityIotaValues(t *testing.T) {
	tests := []struct {
		severity Severity
		wantInt  int
	}{
		{SeverityInfo, 0},
		{SeverityLow, 1},
		{SeverityMedium, 2},
		{SeverityHigh, 3},
		{SeverityCritical, 4},
	}

	for _, tt := range tests {
		t.Run(tt.severity.String(), func(t *testing.T) {
			if int(tt.severity) != tt.wantInt {
				t.Errorf("Severity %s = %d, want %d", tt.severity.String(), int(tt.severity), tt.wantInt)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ActionType constants
// ---------------------------------------------------------------------------

func TestActionTypeConstants(t *testing.T) {
	tests := []struct {
		name string
		at   ActionType
		want string
	}{
		{name: "block_ip", at: ActionBlockIP, want: "block_ip"},
		{name: "disable_user", at: ActionDisableUser, want: "disable_user"},
		{name: "kill_process", at: ActionKillProcess, want: "kill_process"},
		{name: "isolate_container", at: ActionIsolateContainer, want: "isolate_container"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.at) != tt.want {
				t.Errorf("ActionType = %q, want %q", string(tt.at), tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ActionStatus constants
// ---------------------------------------------------------------------------

func TestActionStatusConstants(t *testing.T) {
	tests := []struct {
		name string
		as   ActionStatus
		want string
	}{
		{name: "pending", as: ActionPending, want: "pending"},
		{name: "approved", as: ActionApproved, want: "approved"},
		{name: "denied", as: ActionDenied, want: "denied"},
		{name: "executed", as: ActionExecuted, want: "executed"},
		{name: "expired", as: ActionExpired, want: "expired"},
		{name: "rolled_back", as: ActionRolledBack, want: "rolled_back"},
		{name: "failed", as: ActionFailed, want: "failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.as) != tt.want {
				t.Errorf("ActionStatus = %q, want %q", string(tt.as), tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// IncidentStatus constants
// ---------------------------------------------------------------------------

func TestIncidentStatusConstants(t *testing.T) {
	tests := []struct {
		name string
		is   IncidentStatus
		want string
	}{
		{name: "open", is: IncidentOpen, want: "open"},
		{name: "acknowledged", is: IncidentAcked, want: "acknowledged"},
		{name: "resolved", is: IncidentResolved, want: "resolved"},
		{name: "false_positive", is: IncidentFalsePos, want: "false_positive"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.is) != tt.want {
				t.Errorf("IncidentStatus = %q, want %q", string(tt.is), tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// JSON: LogEvent marshal / unmarshal
// ---------------------------------------------------------------------------

func TestLogEvent_JSONRoundTrip(t *testing.T) {
	now := time.Date(2026, 2, 11, 10, 30, 0, 0, time.UTC)

	original := LogEvent{
		ID:        "evt-001",
		Timestamp: now,
		Source:    "syslog",
		Category:  "auth",
		Severity:  SeverityHigh,
		Hostname:  "web-01",
		Raw:       "Feb 11 10:30:00 sshd: Failed password for root",
		Fields:    map[string]string{"user": "root", "ip": "10.0.0.5"},
		Platform:  "linux",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal LogEvent: %v", err)
	}

	var decoded LogEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal LogEvent: %v", err)
	}

	if decoded.ID != original.ID {
		t.Errorf("ID = %q, want %q", decoded.ID, original.ID)
	}
	if !decoded.Timestamp.Equal(original.Timestamp) {
		t.Errorf("Timestamp = %v, want %v", decoded.Timestamp, original.Timestamp)
	}
	if decoded.Source != original.Source {
		t.Errorf("Source = %q, want %q", decoded.Source, original.Source)
	}
	if decoded.Category != original.Category {
		t.Errorf("Category = %q, want %q", decoded.Category, original.Category)
	}
	if decoded.Severity != original.Severity {
		t.Errorf("Severity = %d, want %d", decoded.Severity, original.Severity)
	}
	if decoded.Hostname != original.Hostname {
		t.Errorf("Hostname = %q, want %q", decoded.Hostname, original.Hostname)
	}
	if decoded.Raw != original.Raw {
		t.Errorf("Raw = %q, want %q", decoded.Raw, original.Raw)
	}
	if decoded.Platform != original.Platform {
		t.Errorf("Platform = %q, want %q", decoded.Platform, original.Platform)
	}
	if len(decoded.Fields) != len(original.Fields) {
		t.Fatalf("Fields length = %d, want %d", len(decoded.Fields), len(original.Fields))
	}
	for k, v := range original.Fields {
		if decoded.Fields[k] != v {
			t.Errorf("Fields[%q] = %q, want %q", k, decoded.Fields[k], v)
		}
	}
}

func TestLogEvent_JSONFieldNames(t *testing.T) {
	evt := LogEvent{ID: "evt-002", Source: "nginx"}
	data, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal to map: %v", err)
	}

	expectedKeys := []string{"id", "timestamp", "source", "category", "severity", "hostname", "raw", "fields", "platform"}
	for _, key := range expectedKeys {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q not found in marshaled LogEvent", key)
		}
	}
}

func TestLogEvent_SeverityMarshaledAsInt(t *testing.T) {
	evt := LogEvent{Severity: SeverityCritical}
	data, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal to map: %v", err)
	}

	var sevInt int
	if err := json.Unmarshal(raw["severity"], &sevInt); err != nil {
		t.Fatalf("severity should unmarshal as int: %v", err)
	}
	if sevInt != int(SeverityCritical) {
		t.Errorf("severity JSON value = %d, want %d", sevInt, int(SeverityCritical))
	}
}

func TestLogEvent_NilFields(t *testing.T) {
	evt := LogEvent{ID: "evt-nil"}
	data, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("Marshal with nil Fields: %v", err)
	}

	var decoded LogEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal with nil Fields: %v", err)
	}
	if decoded.ID != "evt-nil" {
		t.Errorf("ID = %q, want %q", decoded.ID, "evt-nil")
	}
}

// ---------------------------------------------------------------------------
// JSON: ResponseAction marshal / unmarshal
// ---------------------------------------------------------------------------

func TestResponseAction_JSONRoundTrip(t *testing.T) {
	now := time.Date(2026, 2, 11, 12, 0, 0, 0, time.UTC)
	expires := now.Add(24 * time.Hour)
	executed := now.Add(1 * time.Hour)

	original := ResponseAction{
		ID:          "act-001",
		Type:        ActionBlockIP,
		Status:      ActionApproved,
		Target:      "192.168.1.100",
		Reason:      "brute force attempt",
		RuleID:      "rule-bf-01",
		IncidentID:  "inc-001",
		Severity:    SeverityHigh,
		Evidence:    []string{"evt-001", "evt-002", "evt-003"},
		RollbackCmd: "iptables -D INPUT -s 192.168.1.100 -j DROP",
		ApprovedBy:  "webui:admin",
		CreatedAt:   now,
		ExpiresAt:   expires,
		ExecutedAt:  &executed,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal ResponseAction: %v", err)
	}

	var decoded ResponseAction
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal ResponseAction: %v", err)
	}

	if decoded.ID != original.ID {
		t.Errorf("ID = %q, want %q", decoded.ID, original.ID)
	}
	if decoded.Type != original.Type {
		t.Errorf("Type = %q, want %q", decoded.Type, original.Type)
	}
	if decoded.Status != original.Status {
		t.Errorf("Status = %q, want %q", decoded.Status, original.Status)
	}
	if decoded.Target != original.Target {
		t.Errorf("Target = %q, want %q", decoded.Target, original.Target)
	}
	if decoded.Reason != original.Reason {
		t.Errorf("Reason = %q, want %q", decoded.Reason, original.Reason)
	}
	if decoded.RuleID != original.RuleID {
		t.Errorf("RuleID = %q, want %q", decoded.RuleID, original.RuleID)
	}
	if decoded.IncidentID != original.IncidentID {
		t.Errorf("IncidentID = %q, want %q", decoded.IncidentID, original.IncidentID)
	}
	if decoded.Severity != original.Severity {
		t.Errorf("Severity = %d, want %d", decoded.Severity, original.Severity)
	}
	if len(decoded.Evidence) != len(original.Evidence) {
		t.Fatalf("Evidence length = %d, want %d", len(decoded.Evidence), len(original.Evidence))
	}
	for i, e := range original.Evidence {
		if decoded.Evidence[i] != e {
			t.Errorf("Evidence[%d] = %q, want %q", i, decoded.Evidence[i], e)
		}
	}
	if decoded.RollbackCmd != original.RollbackCmd {
		t.Errorf("RollbackCmd = %q, want %q", decoded.RollbackCmd, original.RollbackCmd)
	}
	if decoded.ApprovedBy != original.ApprovedBy {
		t.Errorf("ApprovedBy = %q, want %q", decoded.ApprovedBy, original.ApprovedBy)
	}
	if !decoded.CreatedAt.Equal(original.CreatedAt) {
		t.Errorf("CreatedAt = %v, want %v", decoded.CreatedAt, original.CreatedAt)
	}
	if !decoded.ExpiresAt.Equal(original.ExpiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", decoded.ExpiresAt, original.ExpiresAt)
	}
	if decoded.ExecutedAt == nil {
		t.Fatal("ExecutedAt is nil, want non-nil")
	}
	if !decoded.ExecutedAt.Equal(*original.ExecutedAt) {
		t.Errorf("ExecutedAt = %v, want %v", *decoded.ExecutedAt, *original.ExecutedAt)
	}
}

func TestResponseAction_ExecutedAtOmitEmpty(t *testing.T) {
	action := ResponseAction{
		ID:     "act-noexec",
		Type:   ActionKillProcess,
		Status: ActionPending,
	}

	data, err := json.Marshal(action)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal to map: %v", err)
	}

	if _, ok := raw["executed_at"]; ok {
		t.Error("executed_at should be omitted when nil, but it was present")
	}
}

func TestResponseAction_JSONFieldNames(t *testing.T) {
	now := time.Now()
	action := ResponseAction{
		ID:         "act-fields",
		Type:       ActionDisableUser,
		Status:     ActionPending,
		ExecutedAt: &now,
	}
	data, err := json.Marshal(action)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal to map: %v", err)
	}

	expectedKeys := []string{
		"id", "type", "status", "target", "reason", "rule_id",
		"incident_id", "severity", "evidence", "rollback_cmd",
		"approved_by", "created_at", "expires_at", "executed_at",
	}
	for _, key := range expectedKeys {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q not found in marshaled ResponseAction", key)
		}
	}
}

// ---------------------------------------------------------------------------
// JSON: Incident marshal / unmarshal
// ---------------------------------------------------------------------------

func TestIncident_JSONRoundTrip(t *testing.T) {
	now := time.Date(2026, 2, 11, 14, 0, 0, 0, time.UTC)
	updated := now.Add(30 * time.Minute)
	resolved := now.Add(2 * time.Hour)

	original := Incident{
		ID:          "inc-001",
		Title:       "Brute Force SSH Login",
		Description: "Multiple failed SSH login attempts from 10.0.0.5",
		Severity:    SeverityCritical,
		Status:      IncidentOpen,
		RuleID:      "rule-ssh-bf",
		Events:      []string{"evt-001", "evt-002"},
		Actions:     []string{"act-001"},
		SourceIP:    "10.0.0.5",
		TargetUser:  "root",
		CreatedAt:   now,
		UpdatedAt:   updated,
		ResolvedAt:  &resolved,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal Incident: %v", err)
	}

	var decoded Incident
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal Incident: %v", err)
	}

	if decoded.ID != original.ID {
		t.Errorf("ID = %q, want %q", decoded.ID, original.ID)
	}
	if decoded.Title != original.Title {
		t.Errorf("Title = %q, want %q", decoded.Title, original.Title)
	}
	if decoded.Description != original.Description {
		t.Errorf("Description = %q, want %q", decoded.Description, original.Description)
	}
	if decoded.Severity != original.Severity {
		t.Errorf("Severity = %d, want %d", decoded.Severity, original.Severity)
	}
	if decoded.Status != original.Status {
		t.Errorf("Status = %q, want %q", decoded.Status, original.Status)
	}
	if decoded.RuleID != original.RuleID {
		t.Errorf("RuleID = %q, want %q", decoded.RuleID, original.RuleID)
	}
	if len(decoded.Events) != len(original.Events) {
		t.Fatalf("Events length = %d, want %d", len(decoded.Events), len(original.Events))
	}
	for i, e := range original.Events {
		if decoded.Events[i] != e {
			t.Errorf("Events[%d] = %q, want %q", i, decoded.Events[i], e)
		}
	}
	if len(decoded.Actions) != len(original.Actions) {
		t.Fatalf("Actions length = %d, want %d", len(decoded.Actions), len(original.Actions))
	}
	for i, a := range original.Actions {
		if decoded.Actions[i] != a {
			t.Errorf("Actions[%d] = %q, want %q", i, decoded.Actions[i], a)
		}
	}
	if decoded.SourceIP != original.SourceIP {
		t.Errorf("SourceIP = %q, want %q", decoded.SourceIP, original.SourceIP)
	}
	if decoded.TargetUser != original.TargetUser {
		t.Errorf("TargetUser = %q, want %q", decoded.TargetUser, original.TargetUser)
	}
	if !decoded.CreatedAt.Equal(original.CreatedAt) {
		t.Errorf("CreatedAt = %v, want %v", decoded.CreatedAt, original.CreatedAt)
	}
	if !decoded.UpdatedAt.Equal(original.UpdatedAt) {
		t.Errorf("UpdatedAt = %v, want %v", decoded.UpdatedAt, original.UpdatedAt)
	}
	if decoded.ResolvedAt == nil {
		t.Fatal("ResolvedAt is nil, want non-nil")
	}
	if !decoded.ResolvedAt.Equal(*original.ResolvedAt) {
		t.Errorf("ResolvedAt = %v, want %v", *decoded.ResolvedAt, *original.ResolvedAt)
	}
}

func TestIncident_ResolvedAtOmitEmpty(t *testing.T) {
	inc := Incident{
		ID:     "inc-open",
		Status: IncidentOpen,
	}

	data, err := json.Marshal(inc)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal to map: %v", err)
	}

	if _, ok := raw["resolved_at"]; ok {
		t.Error("resolved_at should be omitted when nil, but it was present")
	}
}

func TestIncident_SourceIPOmitEmpty(t *testing.T) {
	inc := Incident{ID: "inc-nosrc"}

	data, err := json.Marshal(inc)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal to map: %v", err)
	}

	if _, ok := raw["source_ip"]; ok {
		t.Error("source_ip should be omitted when empty, but it was present")
	}
}

func TestIncident_TargetUserOmitEmpty(t *testing.T) {
	inc := Incident{ID: "inc-notarget"}

	data, err := json.Marshal(inc)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal to map: %v", err)
	}

	if _, ok := raw["target_user"]; ok {
		t.Error("target_user should be omitted when empty, but it was present")
	}
}

func TestIncident_JSONFieldNames(t *testing.T) {
	now := time.Now()
	inc := Incident{
		ID:         "inc-fields",
		SourceIP:   "1.2.3.4",
		TargetUser: "admin",
		ResolvedAt: &now,
	}
	data, err := json.Marshal(inc)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal to map: %v", err)
	}

	expectedKeys := []string{
		"id", "title", "description", "severity", "status",
		"rule_id", "events", "actions", "source_ip", "target_user",
		"created_at", "updated_at", "resolved_at",
	}
	for _, key := range expectedKeys {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q not found in marshaled Incident", key)
		}
	}
}

func TestIncident_UnmarshalFromJSON(t *testing.T) {
	jsonStr := `{
		"id": "inc-from-json",
		"title": "DNS Tunneling",
		"description": "Unusually high DNS query volume",
		"severity": 4,
		"status": "open",
		"rule_id": "rule-dns-01",
		"events": ["evt-100", "evt-101"],
		"actions": [],
		"source_ip": "172.16.0.10",
		"created_at": "2026-02-11T08:00:00Z",
		"updated_at": "2026-02-11T08:05:00Z"
	}`

	var inc Incident
	if err := json.Unmarshal([]byte(jsonStr), &inc); err != nil {
		t.Fatalf("Unmarshal from raw JSON: %v", err)
	}

	if inc.ID != "inc-from-json" {
		t.Errorf("ID = %q, want %q", inc.ID, "inc-from-json")
	}
	if inc.Severity != SeverityCritical {
		t.Errorf("Severity = %d (%s), want %d (%s)",
			inc.Severity, inc.Severity.String(), SeverityCritical, SeverityCritical.String())
	}
	if inc.Status != IncidentOpen {
		t.Errorf("Status = %q, want %q", inc.Status, IncidentOpen)
	}
	if len(inc.Events) != 2 {
		t.Fatalf("Events length = %d, want 2", len(inc.Events))
	}
	if inc.Events[0] != "evt-100" || inc.Events[1] != "evt-101" {
		t.Errorf("Events = %v, want [evt-100, evt-101]", inc.Events)
	}
	if inc.SourceIP != "172.16.0.10" {
		t.Errorf("SourceIP = %q, want %q", inc.SourceIP, "172.16.0.10")
	}
	if inc.ResolvedAt != nil {
		t.Errorf("ResolvedAt = %v, want nil", inc.ResolvedAt)
	}
}

// ---------------------------------------------------------------------------
// JSON: AuditEntry marshal / unmarshal
// ---------------------------------------------------------------------------

func TestAuditEntry_JSONRoundTrip(t *testing.T) {
	now := time.Date(2026, 2, 11, 16, 0, 0, 0, time.UTC)

	original := AuditEntry{
		ID:        "audit-001",
		Action:    "action_approved",
		Actor:     "webui:admin",
		Details:   "Approved block_ip for 192.168.1.100",
		Timestamp: now,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal AuditEntry: %v", err)
	}

	var decoded AuditEntry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal AuditEntry: %v", err)
	}

	if decoded.ID != original.ID {
		t.Errorf("ID = %q, want %q", decoded.ID, original.ID)
	}
	if decoded.Action != original.Action {
		t.Errorf("Action = %q, want %q", decoded.Action, original.Action)
	}
	if decoded.Actor != original.Actor {
		t.Errorf("Actor = %q, want %q", decoded.Actor, original.Actor)
	}
	if decoded.Details != original.Details {
		t.Errorf("Details = %q, want %q", decoded.Details, original.Details)
	}
	if !decoded.Timestamp.Equal(original.Timestamp) {
		t.Errorf("Timestamp = %v, want %v", decoded.Timestamp, original.Timestamp)
	}
}

// ---------------------------------------------------------------------------
// JSON: ToolResult marshal / unmarshal (omitempty fields)
// ---------------------------------------------------------------------------

func TestToolResult_JSONOmitEmpty(t *testing.T) {
	tr := ToolResult{
		Success: true,
		Output:  "scan complete",
	}

	data, err := json.Marshal(tr)
	if err != nil {
		t.Fatalf("Marshal ToolResult: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal to map: %v", err)
	}

	if _, ok := raw["data"]; ok {
		t.Error("data should be omitted when nil, but it was present")
	}
	if _, ok := raw["error"]; ok {
		t.Error("error should be omitted when empty, but it was present")
	}
}

func TestToolResult_JSONWithAllFields(t *testing.T) {
	tr := ToolResult{
		Success: false,
		Output:  "lookup failed",
		Data:    map[string]interface{}{"ip": "10.0.0.1"},
		Error:   "connection timeout",
	}

	data, err := json.Marshal(tr)
	if err != nil {
		t.Fatalf("Marshal ToolResult: %v", err)
	}

	var decoded ToolResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal ToolResult: %v", err)
	}

	if decoded.Success != tr.Success {
		t.Errorf("Success = %v, want %v", decoded.Success, tr.Success)
	}
	if decoded.Output != tr.Output {
		t.Errorf("Output = %q, want %q", decoded.Output, tr.Output)
	}
	if decoded.Error != tr.Error {
		t.Errorf("Error = %q, want %q", decoded.Error, tr.Error)
	}
	if decoded.Data["ip"] != tr.Data["ip"] {
		t.Errorf("Data[ip] = %v, want %v", decoded.Data["ip"], tr.Data["ip"])
	}
}

// ---------------------------------------------------------------------------
// JSON: ChatMessage marshal / unmarshal
// ---------------------------------------------------------------------------

func TestChatMessage_JSONRoundTrip(t *testing.T) {
	now := time.Date(2026, 2, 11, 18, 0, 0, 0, time.UTC)

	original := ChatMessage{
		Role:    "assistant",
		Content: "I have analyzed the incident and recommend blocking the IP.",
		ToolCalls: []ToolCall{
			{
				ToolName:   "whois",
				Parameters: map[string]interface{}{"ip": "10.0.0.5"},
				Timestamp:  now,
			},
		},
		Timestamp: now,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal ChatMessage: %v", err)
	}

	var decoded ChatMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal ChatMessage: %v", err)
	}

	if decoded.Role != original.Role {
		t.Errorf("Role = %q, want %q", decoded.Role, original.Role)
	}
	if decoded.Content != original.Content {
		t.Errorf("Content = %q, want %q", decoded.Content, original.Content)
	}
	if len(decoded.ToolCalls) != 1 {
		t.Fatalf("ToolCalls length = %d, want 1", len(decoded.ToolCalls))
	}
	if decoded.ToolCalls[0].ToolName != "whois" {
		t.Errorf("ToolCalls[0].ToolName = %q, want %q", decoded.ToolCalls[0].ToolName, "whois")
	}
}

func TestChatMessage_ToolCallsOmitEmpty(t *testing.T) {
	msg := ChatMessage{
		Role:    "user",
		Content: "What happened?",
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal to map: %v", err)
	}

	if _, ok := raw["tool_calls"]; ok {
		t.Error("tool_calls should be omitted when nil, but it was present")
	}
}

// ---------------------------------------------------------------------------
// JSON: Identity marshal / unmarshal
// ---------------------------------------------------------------------------

func TestIdentity_JSONRoundTrip(t *testing.T) {
	original := Identity{
		UserID:      "usr-001",
		Username:    "admin",
		Roles:       []string{"admin", "analyst"},
		Permissions: []string{"approve_actions", "view_incidents", "manage_rules"},
		IPAddress:   "10.0.0.50",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal Identity: %v", err)
	}

	var decoded Identity
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal Identity: %v", err)
	}

	if decoded.UserID != original.UserID {
		t.Errorf("UserID = %q, want %q", decoded.UserID, original.UserID)
	}
	if decoded.Username != original.Username {
		t.Errorf("Username = %q, want %q", decoded.Username, original.Username)
	}
	if len(decoded.Roles) != len(original.Roles) {
		t.Fatalf("Roles length = %d, want %d", len(decoded.Roles), len(original.Roles))
	}
	for i, r := range original.Roles {
		if decoded.Roles[i] != r {
			t.Errorf("Roles[%d] = %q, want %q", i, decoded.Roles[i], r)
		}
	}
	if len(decoded.Permissions) != len(original.Permissions) {
		t.Fatalf("Permissions length = %d, want %d", len(decoded.Permissions), len(original.Permissions))
	}
	for i, p := range original.Permissions {
		if decoded.Permissions[i] != p {
			t.Errorf("Permissions[%d] = %q, want %q", i, decoded.Permissions[i], p)
		}
	}
	if decoded.IPAddress != original.IPAddress {
		t.Errorf("IPAddress = %q, want %q", decoded.IPAddress, original.IPAddress)
	}
}

// ---------------------------------------------------------------------------
// JSON: AnalysisResult marshal / unmarshal
// ---------------------------------------------------------------------------

func TestAnalysisResult_JSONRoundTrip(t *testing.T) {
	now := time.Date(2026, 2, 11, 20, 0, 0, 0, time.UTC)

	original := AnalysisResult{
		IncidentID:    "inc-001",
		Summary:       "High-confidence brute force attack detected",
		Reasoning:     "Multiple failed SSH logins from single IP within 60 seconds",
		Confidence:    0.95,
		RiskScore:     9,
		RequiresHuman: true,
		CreatedAt:     now,
		ProposedActions: []ActionProposal{
			{
				Reasoning:  "Block source IP to prevent further attempts",
				Confidence: 0.92,
				RiskScore:  3,
				Action: ResponseAction{
					ID:   "act-prop-001",
					Type: ActionBlockIP,
				},
			},
		},
		ToolCalls: []ToolCall{
			{
				ToolName:   "whois",
				Parameters: map[string]interface{}{"ip": "10.0.0.5"},
				Timestamp:  now,
			},
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal AnalysisResult: %v", err)
	}

	var decoded AnalysisResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal AnalysisResult: %v", err)
	}

	if decoded.IncidentID != original.IncidentID {
		t.Errorf("IncidentID = %q, want %q", decoded.IncidentID, original.IncidentID)
	}
	if decoded.Summary != original.Summary {
		t.Errorf("Summary = %q, want %q", decoded.Summary, original.Summary)
	}
	if decoded.Confidence != original.Confidence {
		t.Errorf("Confidence = %f, want %f", decoded.Confidence, original.Confidence)
	}
	if decoded.RiskScore != original.RiskScore {
		t.Errorf("RiskScore = %d, want %d", decoded.RiskScore, original.RiskScore)
	}
	if decoded.RequiresHuman != original.RequiresHuman {
		t.Errorf("RequiresHuman = %v, want %v", decoded.RequiresHuman, original.RequiresHuman)
	}
	if len(decoded.ProposedActions) != 1 {
		t.Fatalf("ProposedActions length = %d, want 1", len(decoded.ProposedActions))
	}
	if decoded.ProposedActions[0].Action.Type != ActionBlockIP {
		t.Errorf("ProposedActions[0].Action.Type = %q, want %q",
			decoded.ProposedActions[0].Action.Type, ActionBlockIP)
	}
	if len(decoded.ToolCalls) != 1 {
		t.Fatalf("ToolCalls length = %d, want 1", len(decoded.ToolCalls))
	}
	if decoded.ToolCalls[0].ToolName != "whois" {
		t.Errorf("ToolCalls[0].ToolName = %q, want %q", decoded.ToolCalls[0].ToolName, "whois")
	}
}

// ---------------------------------------------------------------------------
// JSON: Zero-value structs should not panic during marshal
// ---------------------------------------------------------------------------

func TestZeroValueStructs_MarshalDoesNotPanic(t *testing.T) {
	structs := []struct {
		name string
		val  interface{}
	}{
		{"LogEvent", LogEvent{}},
		{"ResponseAction", ResponseAction{}},
		{"Incident", Incident{}},
		{"AuditEntry", AuditEntry{}},
		{"SystemHealth", SystemHealth{}},
		{"ToolDefinition", ToolDefinition{}},
		{"AnalysisRequest", AnalysisRequest{}},
		{"AnalysisResult", AnalysisResult{}},
		{"ActionProposal", ActionProposal{}},
		{"ToolCall", ToolCall{}},
		{"ToolResult", ToolResult{}},
		{"Identity", Identity{}},
		{"ChatMessage", ChatMessage{}},
	}

	for _, tt := range structs {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.val)
			if err != nil {
				t.Fatalf("Marshal zero-value %s: %v", tt.name, err)
			}
			if len(data) == 0 {
				t.Errorf("Marshal zero-value %s produced empty output", tt.name)
			}
		})
	}
}
