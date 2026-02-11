package response

import (
	"fmt"
	"net"
	"regexp"
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
	denyLists  map[string][]string // action_type -> protected values that must NOT be targeted
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
		denyLists: map[string][]string{
			// Users that must never be disabled.
			"disable_user": {"root", "Administrator", "SYSTEM", "LocalSystem"},
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

// SetDenyList sets the protected values that must not be targeted.
func (p *PolicyEngine) SetDenyList(actionType string, values []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.denyLists[actionType] = values
}

// GetDenyList returns the deny list for an action type.
func (p *PolicyEngine) GetDenyList(actionType string) []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.denyLists[actionType]
}

// ValidateAction runs all policy checks for an action.
func (p *PolicyEngine) ValidateAction(actionType string, params map[string]interface{}) error {
	// Check rate limit.
	if err := p.CheckRateLimit(actionType); err != nil {
		return err
	}

	// Check CIDR allow-list for block_ip — protected IPs must not be blocked.
	if actionType == "block_ip" {
		if target, ok := params["target"]; ok {
			if targetStr, ok := target.(string); ok {
				if err := p.checkCIDRAllowList(actionType, targetStr); err != nil {
					return err
				}
			}
		}
	}

	// Check deny-list for disable_user — protected users must not be disabled.
	if actionType == "disable_user" {
		if target, ok := params["target"]; ok {
			if targetStr, ok := target.(string); ok {
				if err := p.checkDenyList(actionType, targetStr); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// checkCIDRAllowList verifies that the target IP does not fall within a protected CIDR range.
func (p *PolicyEngine) checkCIDRAllowList(actionType, targetIP string) error {
	p.mu.RLock()
	cidrs := p.allowLists[actionType]
	p.mu.RUnlock()

	ip := net.ParseIP(targetIP)
	if ip == nil {
		return nil // Not a valid IP — let other validators catch it.
	}

	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return fmt.Errorf("policy violation: %s is in protected range %s", targetIP, cidr)
		}
	}

	return nil
}

// checkDenyList verifies that the target does not match a protected value.
func (p *PolicyEngine) checkDenyList(actionType, target string) error {
	p.mu.RLock()
	protected := p.denyLists[actionType]
	p.mu.RUnlock()

	// Case-insensitive match using regex for safety.
	for _, entry := range protected {
		pattern := "(?i)^" + regexp.QuoteMeta(entry) + "$"
		if matched, _ := regexp.MatchString(pattern, target); matched {
			return fmt.Errorf("policy violation: %q is a protected %s target", target, actionType)
		}
	}

	return nil
}
