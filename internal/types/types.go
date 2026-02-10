// Package types defines core data structures used across Sentinel.
package types

import (
	"time"
)

// Severity levels for events and incidents.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// ParseSeverity converts a string severity to the enum.
func ParseSeverity(s string) Severity {
	switch s {
	case "info":
		return SeverityInfo
	case "low":
		return SeverityLow
	case "medium":
		return SeverityMedium
	case "high":
		return SeverityHigh
	case "critical":
		return SeverityCritical
	default:
		return SeverityInfo
	}
}

// LogEvent represents a single normalized log entry from any source.
type LogEvent struct {
	ID        string            `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	Source    string            `json:"source"`    // e.g., "syslog", "eventlog", "nginx"
	Category string            `json:"category"`  // e.g., "auth", "network", "web"
	Severity Severity          `json:"severity"`
	Hostname string            `json:"hostname"`
	Raw      string            `json:"raw"`
	Fields   map[string]string `json:"fields"`    // Parsed key-value fields
	Platform string            `json:"platform"`  // "linux", "windows", "docker"
}

// ActionType defines the kind of response action.
type ActionType string

const (
	ActionBlockIP         ActionType = "block_ip"
	ActionDisableUser     ActionType = "disable_user"
	ActionKillProcess     ActionType = "kill_process"
	ActionIsolateContainer ActionType = "isolate_container"
)

// ActionStatus tracks the approval state of a response action.
type ActionStatus string

const (
	ActionPending  ActionStatus = "pending"
	ActionApproved ActionStatus = "approved"
	ActionDenied   ActionStatus = "denied"
	ActionExecuted ActionStatus = "executed"
	ActionExpired  ActionStatus = "expired"
	ActionRolledBack ActionStatus = "rolled_back"
	ActionFailed   ActionStatus = "failed"
)

// ResponseAction represents a defensive action awaiting approval or already executed.
type ResponseAction struct {
	ID          string       `json:"id"`
	Type        ActionType   `json:"type"`
	Status      ActionStatus `json:"status"`
	Target      string       `json:"target"`      // IP, username, PID, container ID
	Reason      string       `json:"reason"`
	RuleID      string       `json:"rule_id"`
	IncidentID  string       `json:"incident_id"`
	Severity    Severity     `json:"severity"`
	Evidence    []string     `json:"evidence"`     // Related log event IDs
	RollbackCmd string       `json:"rollback_cmd"` // Command to reverse this action
	ApprovedBy  string       `json:"approved_by"`  // "telegram:<user>" or "webui:<user>"
	CreatedAt   time.Time    `json:"created_at"`
	ExpiresAt   time.Time    `json:"expires_at"`
	ExecutedAt  *time.Time   `json:"executed_at,omitempty"`
}

// Incident groups related events and actions for a single security incident.
type Incident struct {
	ID          string           `json:"id"`
	Title       string           `json:"title"`
	Description string           `json:"description"`
	Severity    Severity         `json:"severity"`
	Status      IncidentStatus   `json:"status"`
	RuleID      string           `json:"rule_id"`
	Events      []string         `json:"events"`  // LogEvent IDs
	Actions     []string         `json:"actions"` // ResponseAction IDs
	SourceIP    string           `json:"source_ip,omitempty"`
	TargetUser  string           `json:"target_user,omitempty"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
	ResolvedAt  *time.Time       `json:"resolved_at,omitempty"`
}

// IncidentStatus tracks the lifecycle of an incident.
type IncidentStatus string

const (
	IncidentOpen     IncidentStatus = "open"
	IncidentAcked    IncidentStatus = "acknowledged"
	IncidentResolved IncidentStatus = "resolved"
	IncidentFalsePos IncidentStatus = "false_positive"
)

// AuditEntry records every action taken by Sentinel for accountability.
type AuditEntry struct {
	ID        string    `json:"id"`
	Action    string    `json:"action"` // "action_approved", "action_executed", "rule_enabled", etc.
	Actor     string    `json:"actor"`  // Who performed it
	Details   string    `json:"details"`
	Timestamp time.Time `json:"timestamp"`
}

// SystemHealth exposes current agent health metrics.
type SystemHealth struct {
	Uptime       time.Duration `json:"uptime"`
	EventsPerSec float64       `json:"events_per_sec"`
	ActiveRules  int           `json:"active_rules"`
	PendingQueue int           `json:"pending_queue"`
	OpenIncidents int          `json:"open_incidents"`
	LogSources   []string      `json:"log_sources"`
	Platform     string        `json:"platform"`
	Version      string        `json:"version"`
}

// ---------------------------------------------------------------------------
// AI Agent Types
// ---------------------------------------------------------------------------

// ToolDefinition describes a skill/tool for the LLM.
type ToolDefinition struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"` // JSON Schema
}

// AnalysisRequest is sent from the detection engine to the agent runtime.
type AnalysisRequest struct {
	Incident     Incident               `json:"incident"`
	MatchedRules []string               `json:"matched_rules"` // Rule IDs
	Context      map[string]interface{} `json:"context,omitempty"`
	Timestamp    time.Time              `json:"timestamp"`
}

// AnalysisResult is the agent's structured output after analysing an incident.
type AnalysisResult struct {
	IncidentID      string           `json:"incident_id"`
	Summary         string           `json:"summary"`
	Reasoning       string           `json:"reasoning"`
	Confidence      float64          `json:"confidence"`
	RiskScore       int              `json:"risk_score"` // 1-10
	ProposedActions []ActionProposal `json:"proposed_actions"`
	ToolCalls       []ToolCall       `json:"tool_calls"`
	RequiresHuman   bool             `json:"requires_human"`
	CreatedAt       time.Time        `json:"created_at"`
}

// ActionProposal is an AI-suggested action with reasoning metadata.
type ActionProposal struct {
	Action       ResponseAction   `json:"action"`
	Reasoning    string           `json:"reasoning"`
	Confidence   float64          `json:"confidence"`
	RiskScore    int              `json:"risk_score"`
	Alternatives []ResponseAction `json:"alternatives,omitempty"`
}

// ToolCall records a single tool invocation by the agent.
type ToolCall struct {
	ToolName   string                 `json:"tool_name"`
	Parameters map[string]interface{} `json:"parameters"`
	Result     *ToolResult            `json:"result,omitempty"`
	Timestamp  time.Time              `json:"timestamp"`
}

// ToolResult is the output of a skill execution.
type ToolResult struct {
	Success bool                   `json:"success"`
	Output  string                 `json:"output"`
	Data    map[string]interface{} `json:"data,omitempty"`
	Error   string                 `json:"error,omitempty"`
}

// Identity carries rich auth context through the approval workflow.
type Identity struct {
	UserID      string   `json:"user_id"`
	Username    string   `json:"username"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	IPAddress   string   `json:"ip_address"`
}

// ChatMessage represents a single turn in an agent conversation.
type ChatMessage struct {
	Role      string    `json:"role"` // "user", "assistant", "system", "tool"
	Content   string    `json:"content"`
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}
