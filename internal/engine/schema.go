package engine

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog"
)

// FieldType represents the expected type of a schema field.
type FieldType int

const (
	FieldString FieldType = iota
	FieldIP
	FieldInt
	FieldTimestamp
)

func (ft FieldType) String() string {
	switch ft {
	case FieldString:
		return "string"
	case FieldIP:
		return "ip"
	case FieldInt:
		return "int"
	case FieldTimestamp:
		return "timestamp"
	default:
		return "unknown"
	}
}

// FieldDef describes a known event field.
type FieldDef struct {
	Name        string
	Type        FieldType
	Description string
	Sources     []string // Log sources that typically produce this field.
}

// Schema is a registry of known event field names.
type Schema struct {
	fields map[string]FieldDef
}

// NewSchema creates a Schema pre-populated with all standard Sentinel fields.
func NewSchema() *Schema {
	s := &Schema{fields: make(map[string]FieldDef)}

	// Built-in LogEvent fields (always available).
	s.Register(FieldDef{Name: "raw", Type: FieldString, Description: "Raw log line", Sources: []string{"all"}})
	s.Register(FieldDef{Name: "message", Type: FieldString, Description: "Alias for raw log line", Sources: []string{"all"}})
	s.Register(FieldDef{Name: "source", Type: FieldString, Description: "Log source name", Sources: []string{"all"}})
	s.Register(FieldDef{Name: "category", Type: FieldString, Description: "Event category (auth, web, network, system)", Sources: []string{"all"}})
	s.Register(FieldDef{Name: "hostname", Type: FieldString, Description: "Originating hostname", Sources: []string{"all"}})
	s.Register(FieldDef{Name: "platform", Type: FieldString, Description: "Platform (linux, windows, docker)", Sources: []string{"all"}})

	// Common parsed fields from log sources.
	s.Register(FieldDef{Name: "source_ip", Type: FieldIP, Description: "Source IP address", Sources: []string{"auth", "web", "network"}})
	s.Register(FieldDef{Name: "dest_ip", Type: FieldIP, Description: "Destination IP address", Sources: []string{"network", "web"}})
	s.Register(FieldDef{Name: "username", Type: FieldString, Description: "Username involved", Sources: []string{"auth"}})
	s.Register(FieldDef{Name: "pid", Type: FieldInt, Description: "Process ID", Sources: []string{"system"}})
	s.Register(FieldDef{Name: "port", Type: FieldInt, Description: "Port number", Sources: []string{"network", "web"}})
	s.Register(FieldDef{Name: "protocol", Type: FieldString, Description: "Network protocol", Sources: []string{"network"}})
	s.Register(FieldDef{Name: "method", Type: FieldString, Description: "HTTP method", Sources: []string{"web"}})
	s.Register(FieldDef{Name: "url", Type: FieldString, Description: "Request URL", Sources: []string{"web"}})
	s.Register(FieldDef{Name: "status_code", Type: FieldInt, Description: "HTTP status code", Sources: []string{"web"}})
	s.Register(FieldDef{Name: "user_agent", Type: FieldString, Description: "HTTP user-agent", Sources: []string{"web"}})
	s.Register(FieldDef{Name: "service", Type: FieldString, Description: "Service name (sshd, nginx, etc.)", Sources: []string{"system", "auth"}})
	s.Register(FieldDef{Name: "action", Type: FieldString, Description: "Action performed (login, logout, deny)", Sources: []string{"auth", "system"}})
	s.Register(FieldDef{Name: "event_id", Type: FieldInt, Description: "Windows Event ID", Sources: []string{"eventlog"}})
	s.Register(FieldDef{Name: "channel", Type: FieldString, Description: "Windows Event Log channel", Sources: []string{"eventlog"}})
	s.Register(FieldDef{Name: "provider", Type: FieldString, Description: "Windows Event Log provider", Sources: []string{"eventlog"}})
	s.Register(FieldDef{Name: "container_id", Type: FieldString, Description: "Docker container ID", Sources: []string{"docker"}})
	s.Register(FieldDef{Name: "image", Type: FieldString, Description: "Docker image name", Sources: []string{"docker"}})

	return s
}

// Register adds or updates a field definition in the schema.
func (s *Schema) Register(def FieldDef) {
	s.fields[def.Name] = def
}

// Known returns true if the field name is recognized.
func (s *Schema) Known(name string) bool {
	_, ok := s.fields[name]
	return ok
}

// Get returns the field definition, if it exists.
func (s *Schema) Get(name string) (FieldDef, bool) {
	fd, ok := s.fields[name]
	return fd, ok
}

// AllFields returns all registered field names.
func (s *Schema) AllFields() []string {
	names := make([]string, 0, len(s.fields))
	for n := range s.fields {
		names = append(names, n)
	}
	return names
}

// RuleValidationError represents a single validation problem in a rule.
type RuleValidationError struct {
	RuleID  string
	Field   string
	Level   string // "error" or "warning"
	Message string
}

func (e RuleValidationError) String() string {
	return fmt.Sprintf("[%s] rule %q field %q: %s", e.Level, e.RuleID, e.Field, e.Message)
}

// ValidateRule checks a single rule against the schema and returns any issues.
func ValidateRule(rule Rule, schema *Schema) []RuleValidationError {
	var errs []RuleValidationError

	// Validate required fields.
	if rule.ID == "" {
		errs = append(errs, RuleValidationError{RuleID: "(unknown)", Field: "id", Level: "error", Message: "rule ID is empty"})
	}
	if rule.Title == "" {
		errs = append(errs, RuleValidationError{RuleID: rule.ID, Field: "title", Level: "error", Message: "rule title is empty"})
	}
	if rule.Severity == "" {
		errs = append(errs, RuleValidationError{RuleID: rule.ID, Field: "severity", Level: "error", Message: "severity is empty"})
	}

	// Validate severity value.
	validSeverities := map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}
	if rule.Severity != "" && !validSeverities[rule.Severity] {
		errs = append(errs, RuleValidationError{RuleID: rule.ID, Field: "severity", Level: "error", Message: fmt.Sprintf("unknown severity %q", rule.Severity)})
	}

	// Validate status.
	validStatuses := map[string]bool{"active": true, "test": true, "disabled": true, "": true}
	if !validStatuses[rule.Status] {
		errs = append(errs, RuleValidationError{RuleID: rule.ID, Field: "status", Level: "warning", Message: fmt.Sprintf("unknown status %q", rule.Status)})
	}

	// Validate detection selection fields against schema.
	if len(rule.Detection.Selection) == 0 {
		errs = append(errs, RuleValidationError{RuleID: rule.ID, Field: "detection.selection", Level: "error", Message: "detection selection is empty"})
	}

	for field := range rule.Detection.Selection {
		fieldName := field
		// Strip modifier (e.g., "raw|contains" → "raw").
		if idx := strings.Index(field, "|"); idx >= 0 {
			fieldName = field[:idx]

			// Validate modifier.
			modifier := field[idx+1:]
			validMods := map[string]bool{"contains": true, "startswith": true, "endswith": true, "re": true}
			if !validMods[modifier] {
				errs = append(errs, RuleValidationError{RuleID: rule.ID, Field: field, Level: "error", Message: fmt.Sprintf("unknown modifier %q", modifier)})
			}
		}

		if !schema.Known(fieldName) {
			errs = append(errs, RuleValidationError{RuleID: rule.ID, Field: field, Level: "warning", Message: fmt.Sprintf("field %q is not in the known schema — rule may never match", fieldName)})
		}
	}

	// Validate filter fields.
	for field := range rule.Detection.Filter {
		fieldName := field
		if idx := strings.Index(field, "|"); idx >= 0 {
			fieldName = field[:idx]
		}
		if !schema.Known(fieldName) {
			errs = append(errs, RuleValidationError{RuleID: rule.ID, Field: field, Level: "warning", Message: fmt.Sprintf("filter field %q is not in the known schema", fieldName)})
		}
	}

	// Validate correlation fields.
	if rule.Correlation != nil {
		for _, gf := range rule.Correlation.GroupBy {
			if !schema.Known(gf) {
				errs = append(errs, RuleValidationError{RuleID: rule.ID, Field: gf, Level: "warning", Message: fmt.Sprintf("correlation group_by field %q is not in the known schema", gf)})
			}
		}
		if rule.Correlation.Threshold < 1 {
			errs = append(errs, RuleValidationError{RuleID: rule.ID, Field: "correlation.threshold", Level: "error", Message: "threshold must be >= 1"})
		}
		if rule.Correlation.Window <= 0 {
			errs = append(errs, RuleValidationError{RuleID: rule.ID, Field: "correlation.window", Level: "error", Message: "window must be positive"})
		}
	}

	// Validate response actions.
	validActionTypes := map[string]bool{"block_ip": true, "disable_user": true, "kill_process": true, "isolate_container": true, "alert_admin": true}
	for _, action := range rule.Response {
		if !validActionTypes[string(action.Type)] {
			errs = append(errs, RuleValidationError{RuleID: rule.ID, Field: "response.type", Level: "warning", Message: fmt.Sprintf("unknown action type %q", action.Type)})
		}
		if action.TargetField != "" && !schema.Known(action.TargetField) {
			errs = append(errs, RuleValidationError{RuleID: rule.ID, Field: "response.target_field", Level: "warning", Message: fmt.Sprintf("target field %q is not in the known schema", action.TargetField)})
		}
	}

	// Try to compile the rule to catch regex errors, etc.
	if _, err := CompileRule(rule); err != nil {
		errs = append(errs, RuleValidationError{RuleID: rule.ID, Field: "detection", Level: "error", Message: fmt.Sprintf("compilation failed: %v", err)})
	}

	return errs
}

// ValidateAllRules validates all rules in a directory and returns all issues.
func ValidateAllRules(dir string, schema *Schema, logger zerolog.Logger) ([]RuleValidationError, error) {
	rules, err := LoadRulesFromDir(dir)
	if err != nil {
		return nil, fmt.Errorf("loading rules: %w", err)
	}

	var allErrs []RuleValidationError
	for _, rule := range rules {
		errs := ValidateRule(rule, schema)
		allErrs = append(allErrs, errs...)
		for _, e := range errs {
			if e.Level == "error" {
				logger.Error().Str("rule", e.RuleID).Str("field", e.Field).Msg(e.Message)
			} else {
				logger.Warn().Str("rule", e.RuleID).Str("field", e.Field).Msg(e.Message)
			}
		}
	}

	return allErrs, nil
}
