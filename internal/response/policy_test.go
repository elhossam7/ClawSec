package response

import (
	"testing"
	"time"
)

func TestNewPolicyEngine_Defaults(t *testing.T) {
	pe := NewPolicyEngine()

	// Should have default rate limits.
	expectedLimits := []string{"block_ip", "kill_process", "disable_user", "llm_api_call"}
	for _, name := range expectedLimits {
		if _, exists := pe.limits[name]; !exists {
			t.Errorf("missing default rate limit for %s", name)
		}
	}

	// Should have default allow list for block_ip.
	allowList := pe.GetAllowList("block_ip")
	if len(allowList) == 0 {
		t.Error("expected non-empty allow list for block_ip")
	}
}

func TestCheckRateLimit_UnderLimit(t *testing.T) {
	pe := NewPolicyEngine()
	pe.SetRateLimit("test_action", 3, time.Hour)

	for i := 0; i < 3; i++ {
		if err := pe.CheckRateLimit("test_action"); err != nil {
			t.Fatalf("action %d should be within limit: %v", i+1, err)
		}
	}
}

func TestCheckRateLimit_ExceedsLimit(t *testing.T) {
	pe := NewPolicyEngine()
	pe.SetRateLimit("test_action", 2, time.Hour)

	// Consume the limit.
	pe.CheckRateLimit("test_action")
	pe.CheckRateLimit("test_action")

	// Third should fail.
	err := pe.CheckRateLimit("test_action")
	if err == nil {
		t.Error("expected rate limit error, got nil")
	}
}

func TestCheckRateLimit_WindowReset(t *testing.T) {
	pe := NewPolicyEngine()
	pe.SetRateLimit("fast_action", 1, 50*time.Millisecond)

	// First: OK.
	if err := pe.CheckRateLimit("fast_action"); err != nil {
		t.Fatalf("first action should succeed: %v", err)
	}

	// Second: fail (limit 1).
	if err := pe.CheckRateLimit("fast_action"); err == nil {
		t.Fatal("second action should fail")
	}

	// Wait for window reset.
	time.Sleep(100 * time.Millisecond)

	// Third: should succeed after reset.
	if err := pe.CheckRateLimit("fast_action"); err != nil {
		t.Fatalf("action after reset should succeed: %v", err)
	}
}

func TestCheckRateLimit_UnknownAction(t *testing.T) {
	pe := NewPolicyEngine()
	// Unknown actions have no rate limit → should pass.
	if err := pe.CheckRateLimit("unknown_action"); err != nil {
		t.Errorf("unknown action should not be rate limited: %v", err)
	}
}

func TestSetAllowList(t *testing.T) {
	pe := NewPolicyEngine()
	pe.SetAllowList("block_ip", []string{"192.168.0.0/16"})

	list := pe.GetAllowList("block_ip")
	if len(list) != 1 || list[0] != "192.168.0.0/16" {
		t.Errorf("expected custom allow list, got %v", list)
	}
}

func TestValidateAction_RateLimited(t *testing.T) {
	pe := NewPolicyEngine()
	pe.SetRateLimit("risky_action", 1, time.Hour)

	// First should pass.
	if err := pe.ValidateAction("risky_action", nil); err != nil {
		t.Fatalf("first action should pass: %v", err)
	}

	// Second should be rate limited.
	if err := pe.ValidateAction("risky_action", nil); err == nil {
		t.Error("second action should be rate limited")
	}
}

func TestConcurrentRateLimits(t *testing.T) {
	pe := NewPolicyEngine()
	pe.SetRateLimit("concurrent_action", 100, time.Hour)

	errs := make(chan error, 200)
	done := make(chan struct{})

	go func() {
		for i := 0; i < 100; i++ {
			errs <- pe.CheckRateLimit("concurrent_action")
		}
		close(done)
	}()

	<-done
	close(errs)

	var errCount int
	for err := range errs {
		if err != nil {
			errCount++
		}
	}

	if errCount != 0 {
		t.Errorf("expected 0 errors within limit, got %d", errCount)
	}
}

// ---------------------------------------------------------------------------
// Allow-list enforcement (CIDR check for block_ip)
// ---------------------------------------------------------------------------

func TestValidateAction_BlockIP_ProtectedCIDR(t *testing.T) {
	pe := NewPolicyEngine()
	// Reset rate limit to high value so it doesn't interfere.
	pe.SetRateLimit("block_ip", 1000, time.Hour)

	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{"private 10.x.x.x blocked", "10.0.0.1", true},
		{"private 172.16.x.x blocked", "172.16.5.10", true},
		{"private 192.168.x.x blocked", "192.168.1.1", true},
		{"loopback blocked", "127.0.0.1", true},
		{"public IP allowed", "203.0.113.5", false},
		{"another public IP allowed", "8.8.8.8", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pe.ValidateAction("block_ip", map[string]interface{}{"target": tt.target})
			if tt.wantErr && err == nil {
				t.Error("expected policy violation, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

func TestValidateAction_BlockIP_NoTargetParam(t *testing.T) {
	pe := NewPolicyEngine()
	pe.SetRateLimit("block_ip", 1000, time.Hour)

	// Missing target param should pass (no CIDR check).
	err := pe.ValidateAction("block_ip", map[string]interface{}{})
	if err != nil {
		t.Errorf("expected no error for missing target, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Deny-list enforcement (protected users for disable_user)
// ---------------------------------------------------------------------------

func TestValidateAction_DisableUser_ProtectedUser(t *testing.T) {
	pe := NewPolicyEngine()
	pe.SetRateLimit("disable_user", 1000, time.Hour)

	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{"root is protected", "root", true},
		{"Root case-insensitive", "Root", true},
		{"Administrator protected", "Administrator", true},
		{"SYSTEM protected", "SYSTEM", true},
		{"LocalSystem protected", "LocalSystem", true},
		{"regular user allowed", "jdoe", false},
		{"another regular user", "alice", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pe.ValidateAction("disable_user", map[string]interface{}{"target": tt.target})
			if tt.wantErr && err == nil {
				t.Error("expected policy violation, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

func TestSetDenyList(t *testing.T) {
	pe := NewPolicyEngine()
	pe.SetDenyList("disable_user", []string{"svc_account", "backup_admin"})

	list := pe.GetDenyList("disable_user")
	if len(list) != 2 || list[0] != "svc_account" {
		t.Errorf("expected custom deny list, got %v", list)
	}

	// Should now block svc_account.
	pe.SetRateLimit("disable_user", 1000, time.Hour)
	err := pe.ValidateAction("disable_user", map[string]interface{}{"target": "svc_account"})
	if err == nil {
		t.Error("expected deny list violation for svc_account")
	}
}

func TestValidateAction_UnrelatedAction_NoChecks(t *testing.T) {
	pe := NewPolicyEngine()
	// Generic action without allow/deny lists should pass.
	err := pe.ValidateAction("some_other_action", map[string]interface{}{"target": "anything"})
	if err != nil {
		t.Errorf("expected no error for unrelated action, got %v", err)
	}
}
