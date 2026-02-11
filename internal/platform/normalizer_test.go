package platform

import (
	"net"
	"testing"
	"time"

	"github.com/sentinel-agent/sentinel/internal/types"
)

func TestNormalizer_CommonMappings(t *testing.T) {
	norm := NewNormalizer()

	event := &types.LogEvent{
		Timestamp: time.Now(),
		Source:    "generic",
		Fields: map[string]string{
			"src_ip": "10.0.0.5",
			"user":   "admin",
			"proto":  "tcp",
		},
	}

	norm.Normalize(event)

	tests := []struct {
		field string
		want  string
	}{
		{"source_ip", "10.0.0.5"},
		{"username", "admin"},
		{"protocol", "tcp"},
	}

	for _, tt := range tests {
		got, ok := event.Fields[tt.field]
		if !ok {
			t.Errorf("expected field %q to exist", tt.field)
			continue
		}
		if got != tt.want {
			t.Errorf("field %q = %q, want %q", tt.field, got, tt.want)
		}
	}
}

func TestNormalizer_EventLogMappings(t *testing.T) {
	norm := NewNormalizer()

	event := &types.LogEvent{
		Timestamp: time.Now(),
		Source:    "eventlog:Security",
		Fields: map[string]string{
			"event_id":               "4625",
			"source_network_address": "192.168.1.100",
			"target_user_name":       "Administrator",
		},
	}

	norm.Normalize(event)

	if event.Fields["source_ip"] != "192.168.1.100" {
		t.Errorf("source_ip = %q, want 192.168.1.100", event.Fields["source_ip"])
	}
	if event.Fields["username"] != "Administrator" {
		t.Errorf("username = %q, want Administrator", event.Fields["username"])
	}
}

func TestNormalizer_JournaldMappings(t *testing.T) {
	norm := NewNormalizer()

	event := &types.LogEvent{
		Timestamp: time.Now(),
		Source:    "journald",
		Fields: map[string]string{
			"_COMM": "sshd",
			"_PID":  "12345",
		},
	}

	norm.Normalize(event)

	if event.Fields["process.name"] != "sshd" {
		t.Errorf("process.name = %q, want sshd", event.Fields["process.name"])
	}
	// Should also create flat form.
	if event.Fields["process_name"] != "sshd" {
		t.Errorf("process_name = %q, want sshd", event.Fields["process_name"])
	}
	if event.Fields["pid"] != "12345" {
		t.Errorf("pid = %q, want 12345", event.Fields["pid"])
	}
}

func TestNormalizer_DerivedFields_InternalIP(t *testing.T) {
	norm := NewNormalizer()

	event := &types.LogEvent{
		Source: "test",
		Fields: map[string]string{
			"source_ip": "192.168.1.10",
		},
	}

	norm.Normalize(event)

	if event.Fields["source_ip_type"] != "internal" {
		t.Errorf("source_ip_type = %q, want internal", event.Fields["source_ip_type"])
	}
}

func TestNormalizer_DerivedFields_ExternalIP(t *testing.T) {
	norm := NewNormalizer()

	event := &types.LogEvent{
		Source: "test",
		Fields: map[string]string{
			"source_ip": "203.0.113.5",
		},
	}

	norm.Normalize(event)

	if event.Fields["source_ip_type"] != "external" {
		t.Errorf("source_ip_type = %q, want external", event.Fields["source_ip_type"])
	}
}

func TestNormalizer_NilFields(t *testing.T) {
	norm := NewNormalizer()

	event := &types.LogEvent{
		Source: "test",
		Fields: nil,
	}

	// Should not panic.
	norm.Normalize(event)

	if event.Fields == nil {
		t.Error("expected Fields to be initialized")
	}
}

func TestNormalizer_AddCustomMapping(t *testing.T) {
	norm := NewNormalizer()
	norm.AddMapping("custom", "my_field", "canonical_field")

	event := &types.LogEvent{
		Source: "custom",
		Fields: map[string]string{
			"my_field": "test_value",
		},
	}

	// Won't apply since source detection doesn't know "custom".
	// But if we manually trigger with the right source type, it should work.
	// Let's test via the mapping infrastructure directly.
	norm.applyMappings(event, "custom")

	if event.Fields["canonical_field"] != "test_value" {
		t.Errorf("custom mapping not applied, got %v", event.Fields)
	}
}

func TestNormalizer_NoOverwriteExisting(t *testing.T) {
	norm := NewNormalizer()

	event := &types.LogEvent{
		Source: "test",
		Fields: map[string]string{
			"src_ip":    "10.0.0.1",
			"source_ip": "already_set",
		},
	}

	norm.Normalize(event)

	// Should not overwrite existing source_ip.
	if event.Fields["source_ip"] != "already_set" {
		t.Errorf("existing field should not be overwritten, got %q", event.Fields["source_ip"])
	}
}

// ---------------------------------------------------------------------------
// LookupField
// ---------------------------------------------------------------------------

func TestLookupField_Direct(t *testing.T) {
	fields := map[string]string{"username": "admin"}
	val, ok := LookupField(fields, "username")
	if !ok || val != "admin" {
		t.Errorf("LookupField(username) = (%q, %v), want (admin, true)", val, ok)
	}
}

func TestLookupField_DottedToUnderscore(t *testing.T) {
	fields := map[string]string{"process_name": "sshd"}
	val, ok := LookupField(fields, "process.name")
	if !ok || val != "sshd" {
		t.Errorf("LookupField(process.name) = (%q, %v), want (sshd, true)", val, ok)
	}
}

func TestLookupField_UnderscoreToDotted(t *testing.T) {
	fields := map[string]string{"process.name": "sshd"}
	val, ok := LookupField(fields, "process_name")
	if !ok || val != "sshd" {
		t.Errorf("LookupField(process_name) = (%q, %v), want (sshd, true)", val, ok)
	}
}

func TestLookupField_NotFound(t *testing.T) {
	fields := map[string]string{"username": "admin"}
	_, ok := LookupField(fields, "nonexistent")
	if ok {
		t.Error("expected not found for nonexistent field")
	}
}

// ---------------------------------------------------------------------------
// isPrivateIP
// ---------------------------------------------------------------------------

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip      string
		private bool
	}{
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"127.0.0.1", true},
		{"8.8.8.8", false},
		{"203.0.113.5", false},
		{"1.1.1.1", false},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		got := isPrivateIP(ip)
		if got != tt.private {
			t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, got, tt.private)
		}
	}
}
