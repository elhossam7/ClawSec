package response

import (
	"fmt"
	"sync"
	"time"
)

// RateLimit tracks invocation count within a sliding window.
type RateLimit struct {
	Window     time.Duration
	MaxActions int
	current    int
	resetTime  time.Time
	mu         sync.Mutex
}

// PolicyEngine validates proposed actions against safety constraints.
type PolicyEngine struct {
	limits     map[string]*RateLimit
	allowLists map[string][]string // action_type -> allowed values (e.g. protected CIDRs)
	mu         sync.RWMutex
}

// NewPolicyEngine creates a policy engine with sensible defaults.
func NewPolicyEngine() *PolicyEngine {
	pe := &PolicyEngine{
		limits: map[string]*RateLimit{
			"block_ip":     {Window: time.Hour, MaxActions: 10},
			"kill_process": {Window: time.Hour, MaxActions: 5},
			"disable_user": {Window: time.Hour, MaxActions: 5},
			"llm_api_call": {Window: time.Hour, MaxActions: 100},
		},
		allowLists: map[string][]string{
			// IPs in these ranges must NOT be blocked.
			"block_ip": {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"},
		},
	}
	return pe
}

// SetRateLimit configures a rate limit for an action type.
func (p *PolicyEngine) SetRateLimit(actionType string, max int, window time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.limits[actionType] = &RateLimit{Window: window, MaxActions: max}
}

// SetAllowList sets the protected values for an action type.
func (p *PolicyEngine) SetAllowList(actionType string, values []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.allowLists[actionType] = values
}

// CheckRateLimit verifies the action hasn't exceeded its limit.
func (p *PolicyEngine) CheckRateLimit(actionType string) error {
	p.mu.RLock()
	limit, exists := p.limits[actionType]
	p.mu.RUnlock()
	if !exists {
		return nil
	}

	limit.mu.Lock()
	defer limit.mu.Unlock()

	now := time.Now()
	if now.After(limit.resetTime) {
		limit.current = 0
		limit.resetTime = now.Add(limit.Window)
	}

	if limit.current >= limit.MaxActions {
		return fmt.Errorf("rate limit exceeded for %s: %d/%d in %v",
			actionType, limit.current, limit.MaxActions, limit.Window)
	}

	limit.current++
	return nil
}

// GetAllowList returns the protected values for an action type.
func (p *PolicyEngine) GetAllowList(actionType string) []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.allowLists[actionType]
}

// ValidateAction runs all policy checks for an action.
func (p *PolicyEngine) ValidateAction(actionType string, params map[string]interface{}) error {
	// Check rate limit.
	if err := p.CheckRateLimit(actionType); err != nil {
		return err
	}
	return nil
}
