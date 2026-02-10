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
