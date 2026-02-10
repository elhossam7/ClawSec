// Package skills implements the tool/skill abstraction layer.
// Each skill is a self-contained security capability with validation and audit.
package skills

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/rs/zerolog"
	"github.com/sentinel-agent/sentinel/internal/types"
)

// Tool is the interface every skill must implement.
type Tool interface {
	Name() string
	Description() string
	ParametersSchema() map[string]interface{}
	Validate(params map[string]interface{}) error
	Execute(ctx context.Context, params map[string]interface{}) (*types.ToolResult, error)
}

// Registry holds all registered tools and converts them for LLM consumption.
type Registry struct {
	tools  map[string]Tool
	mu     sync.RWMutex
	logger zerolog.Logger
}

// NewRegistry creates an empty tool registry.
func NewRegistry(logger zerolog.Logger) *Registry {
	return &Registry{
		tools:  make(map[string]Tool),
		logger: logger.With().Str("component", "skills").Logger(),
	}
}

// Register adds a tool to the registry.
func (r *Registry) Register(t Tool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[t.Name()] = t
	r.logger.Info().Str("tool", t.Name()).Msg("registered skill")
}

// GetTool returns a tool by name.
func (r *Registry) GetTool(name string) (Tool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[name]
	if !ok {
		return nil, fmt.Errorf("tool %q not found", name)
	}
	return t, nil
}

// ListTools returns all registered tools.
func (r *Registry) ListTools() []Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Tool, 0, len(r.tools))
	for _, t := range r.tools {
		result = append(result, t)
	}
	return result
}

// ToLLMTools converts tools to LLM-compatible definitions.
func (r *Registry) ToLLMTools() []types.ToolDefinition {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var defs []types.ToolDefinition
	for _, t := range r.tools {
		defs = append(defs, types.ToolDefinition{
			Name:        t.Name(),
			Description: t.Description(),
			Parameters:  t.ParametersSchema(),
		})
	}
	return defs
}

// ---------------------------------------------------------------------------
// Shared validation helpers
// ---------------------------------------------------------------------------

// IsIPInCIDR checks if an IP address falls within a CIDR range.
func IsIPInCIDR(ipStr, cidr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return network.Contains(ip)
}

// ValidateIP checks basic IP format validity.
func ValidateIP(ip string) error {
	if ip == "" {
		return fmt.Errorf("empty IP address")
	}
	if strings.ContainsAny(ip, ";|&$`") {
		return fmt.Errorf("invalid characters in IP: %s", ip)
	}
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	return nil
}

// GetStringParam extracts a required string parameter.
func GetStringParam(params map[string]interface{}, key string) (string, error) {
	v, ok := params[key]
	if !ok {
		return "", fmt.Errorf("missing required parameter: %s", key)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("parameter %s must be a string", key)
	}
	return s, nil
}

// GetIntParam extracts an optional int parameter (returns default if absent).
func GetIntParam(params map[string]interface{}, key string, def int) int {
	v, ok := params[key]
	if !ok {
		return def
	}
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	default:
		return def
	}
}
