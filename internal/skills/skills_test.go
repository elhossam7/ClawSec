package skills

import (
	"context"
	"testing"

	"github.com/rs/zerolog"
)

func TestFirewallSkill_ValidateIP(t *testing.T) {
	skill := NewFirewallSkill(nil, zerolog.Nop())

	tests := []struct {
		name   string
		params map[string]interface{}
		ok     bool
	}{
		{
			name:   "valid external IP",
			params: map[string]interface{}{"ip": "203.0.113.5", "reason": "brute force", "duration": 3600},
			ok:     true,
		},
		{
			name:   "private IP rejected",
			params: map[string]interface{}{"ip": "10.0.0.1", "reason": "test"},
			ok:     false,
		},
		{
			name:   "loopback rejected",
			params: map[string]interface{}{"ip": "127.0.0.1", "reason": "test"},
			ok:     false,
		},
		{
			name:   "172.16.x.x rejected",
			params: map[string]interface{}{"ip": "172.16.0.1", "reason": "test"},
			ok:     false,
		},
		{
			name:   "192.168.x.x rejected",
			params: map[string]interface{}{"ip": "192.168.1.100", "reason": "test"},
			ok:     false,
		},
		{
			name:   "invalid IP format",
			params: map[string]interface{}{"ip": "not-an-ip", "reason": "test"},
			ok:     false,
		},
		{
			name:   "missing IP param",
			params: map[string]interface{}{"reason": "test"},
			ok:     false,
		},
		{
			name:   "duration too large",
			params: map[string]interface{}{"ip": "203.0.113.5", "reason": "test", "duration": 100000},
			ok:     false,
		},
		{
			name:   "negative duration",
			params: map[string]interface{}{"ip": "203.0.113.5", "reason": "test", "duration": -1},
			ok:     false,
		},
		{
			name:   "zero duration OK (permanent)",
			params: map[string]interface{}{"ip": "203.0.113.5", "reason": "test", "duration": 0},
			ok:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := skill.Validate(tt.params)
			if tt.ok && err != nil {
				t.Errorf("expected valid, got error: %v", err)
			}
			if !tt.ok && err == nil {
				t.Error("expected validation error, got nil")
			}
		})
	}
}

func TestFirewallSkill_CustomProtectedRanges(t *testing.T) {
	custom := []string{"198.51.100.0/24"}
	skill := NewFirewallSkill(custom, zerolog.Nop())

	// Should block IP in custom range.
	err := skill.Validate(map[string]interface{}{"ip": "198.51.100.10", "reason": "test"})
	if err == nil {
		t.Error("expected rejection for custom protected range")
	}

	// Should allow IP NOT in custom range (10.x no longer protected).
	err = skill.Validate(map[string]interface{}{"ip": "10.0.0.1", "reason": "test"})
	if err != nil {
		t.Errorf("expected 10.0.0.1 to be allowed (not in custom ranges): %v", err)
	}
}

func TestRegistry_RegisterAndGet(t *testing.T) {
	r := NewRegistry(zerolog.Nop())

	skill := NewFirewallSkill(nil, zerolog.Nop())
	r.Register(skill)

	got, err := r.GetTool("block_ip")
	if err != nil {
		t.Fatalf("expected to find block_ip: %v", err)
	}
	if got.Name() != "block_ip" {
		t.Errorf("expected name block_ip, got %s", got.Name())
	}

	_, err = r.GetTool("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent tool")
	}
}

func TestRegistry_ListTools(t *testing.T) {
	r := NewRegistry(zerolog.Nop())
	r.Register(NewFirewallSkill(nil, zerolog.Nop()))

	tools := r.ListTools()
	if len(tools) != 1 {
		t.Errorf("expected 1 tool, got %d", len(tools))
	}
}

func TestRegistry_ToLLMTools(t *testing.T) {
	r := NewRegistry(zerolog.Nop())
	r.Register(NewFirewallSkill(nil, zerolog.Nop()))

	defs := r.ToLLMTools()
	if len(defs) != 1 {
		t.Fatalf("expected 1 definition, got %d", len(defs))
	}
	if defs[0].Name != "block_ip" {
		t.Errorf("expected name block_ip, got %s", defs[0].Name)
	}
	if defs[0].Parameters == nil {
		t.Error("expected non-nil parameters schema")
	}
}

func TestIsIPInCIDR(t *testing.T) {
	tests := []struct {
		ip     string
		cidr   string
		result bool
	}{
		{"10.0.0.1", "10.0.0.0/8", true},
		{"192.168.1.100", "192.168.0.0/16", true},
		{"203.0.113.5", "10.0.0.0/8", false},
		{"invalid", "10.0.0.0/8", false},
		{"10.0.0.1", "invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip+"_"+tt.cidr, func(t *testing.T) {
			got := IsIPInCIDR(tt.ip, tt.cidr)
			if got != tt.result {
				t.Errorf("IsIPInCIDR(%s, %s) = %v, want %v", tt.ip, tt.cidr, got, tt.result)
			}
		})
	}
}

func TestValidateIP(t *testing.T) {
	if err := ValidateIP("192.168.1.1"); err != nil {
		t.Errorf("expected valid IP: %v", err)
	}
	if err := ValidateIP("not-an-ip"); err == nil {
		t.Error("expected error for invalid IP")
	}
	if err := ValidateIP(""); err == nil {
		t.Error("expected error for empty IP")
	}
}

func TestGetStringParam(t *testing.T) {
	params := map[string]interface{}{"key": "value", "num": 42}

	v, err := GetStringParam(params, "key")
	if err != nil || v != "value" {
		t.Errorf("expected 'value', got %q, err=%v", v, err)
	}

	_, err = GetStringParam(params, "missing")
	if err == nil {
		t.Error("expected error for missing param")
	}
}

func TestGetIntParam(t *testing.T) {
	params := map[string]interface{}{"dur": 3600, "dur_float": 7200.0}

	if v := GetIntParam(params, "dur", 0); v != 3600 {
		t.Errorf("expected 3600, got %d", v)
	}
	if v := GetIntParam(params, "dur_float", 0); v != 7200 {
		t.Errorf("expected 7200 (from float64), got %d", v)
	}
	if v := GetIntParam(params, "missing", 99); v != 99 {
		t.Errorf("expected default 99, got %d", v)
	}
}

// Test ForensicsSkill: check_if_internal
func TestCheckInternalSkill(t *testing.T) {
	skill := NewCheckInternalSkill(nil, zerolog.Nop())

	tests := []struct {
		ip       string
		internal bool
	}{
		{"10.0.0.5", true},
		{"172.16.100.1", true},
		{"192.168.1.1", true},
		{"203.0.113.5", false},
		{"8.8.8.8", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			result, err := skill.Execute(context.Background(), map[string]interface{}{"ip": tt.ip})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Success != true {
				t.Fatalf("expected success=true")
			}
			// Output should indicate internal status.
			output := result.Output
			if tt.internal && !contains(output, "INTERNAL") {
				t.Errorf("IP %s: expected output to indicate INTERNAL, got: %s", tt.ip, output)
			}
			if !tt.internal && !contains(output, "EXTERNAL") {
				t.Errorf("IP %s: expected output to indicate EXTERNAL, got: %s", tt.ip, output)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchStr(s, substr)
}

func searchStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
