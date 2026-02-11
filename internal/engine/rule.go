package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/sentinel-agent/sentinel/internal/platform"
	"github.com/sentinel-agent/sentinel/internal/types"
	"gopkg.in/yaml.v3"
)

// Rule represents a SIGMA-compatible detection rule with Sentinel extensions.
type Rule struct {
	ID          string           `yaml:"id"`
	Title       string           `yaml:"title"`
	Description string           `yaml:"description"`
	Severity    string           `yaml:"severity"`
	Status      string           `yaml:"status"` // "active", "test", "disabled"
	Author      string           `yaml:"author"`
	Tags        []string         `yaml:"tags"`
	LogSource   RuleLogSource    `yaml:"logsource"`
	Detection   RuleDetection    `yaml:"detection"`
	Correlation *RuleCorrelation `yaml:"correlation,omitempty"`
	Response    []RuleAction     `yaml:"response,omitempty"` // Sentinel extension
}

// RuleLogSource filters which events should be evaluated against this rule.
type RuleLogSource struct {
	Category string `yaml:"category"` // e.g., "auth", "web", "network"
	Product  string `yaml:"product"`  // e.g., "linux", "windows", "nginx"
	Service  string `yaml:"service"`  // e.g., "sshd", "iis"
}

// RuleDetection defines the matching logic.
// Supports both simple (single "selection" key) and SIGMA-style named selections
// (selection_*, condition string with "or"/"and" logic).
type RuleDetection struct {
	Selection  map[string]interface{}            `yaml:"selection"`        // Simple single selection
	Selections map[string]map[string]interface{} `yaml:"-"`                // Named selections (populated by custom unmarshal)
	Filter     map[string]interface{}            `yaml:"filter,omitempty"` // Exclusions
	Condition  string                            `yaml:"condition"`        // "selection", "selection_a or selection_b"
}

// UnmarshalYAML implements a custom YAML unmarshaler for RuleDetection that
// captures named selection blocks (selection_*) alongside the standard keys.
func (d *RuleDetection) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("detection must be a mapping")
	}

	d.Selections = make(map[string]map[string]interface{})

	for i := 0; i+1 < len(value.Content); i += 2 {
		key := value.Content[i].Value
		val := value.Content[i+1]

		switch {
		case key == "selection":
			// Decode single "selection" into the Selection map.
			var sel map[string]interface{}
			if err := val.Decode(&sel); err != nil {
				return fmt.Errorf("decoding selection: %w", err)
			}
			d.Selection = sel
		case key == "filter":
			var f map[string]interface{}
			if err := val.Decode(&f); err != nil {
				return fmt.Errorf("decoding filter: %w", err)
			}
			d.Filter = f
		case key == "condition":
			d.Condition = val.Value
		case strings.HasPrefix(key, "selection_"):
			// Named selection — store in Selections map.
			var sel map[string]interface{}
			if err := val.Decode(&sel); err != nil {
				return fmt.Errorf("decoding %s: %w", key, err)
			}
			d.Selections[key] = sel
		}
	}

	return nil
}

// RuleCorrelation enables threshold/window-based detection.
type RuleCorrelation struct {
	GroupBy   []string      `yaml:"group_by"`  // Fields to group by
	Threshold int           `yaml:"threshold"` // Min events to trigger
	Window    time.Duration `yaml:"window"`    // Time window
}

// RuleAction defines a response action associated with a rule.
type RuleAction struct {
	Type        types.ActionType `yaml:"type"`
	TargetField string           `yaml:"target_field"` // Event field to use as target
}

// CompiledRule is a pre-compiled, ready-to-evaluate rule.
type CompiledRule struct {
	ID              string
	Title           string
	Description     string
	Severity        types.Severity
	Enabled         bool
	Tags            []string
	LogSource       RuleLogSource
	Conditions      []Condition   // Single selection: all must match (AND)
	ConditionGroups [][]Condition // Named selections: groups OR'd, conditions within AND'd
	ConditionLogic  string        // "and" or "or" — how groups combine
	Filters         []Condition
	Correlation     *RuleCorrelation
	Actions         []RuleAction
	MessageTpl      string
}

// Condition is a single compiled match condition.
type Condition struct {
	Field    string
	Operator MatchOp
	Value    string
	Regex    *regexp.Regexp
	Values   []string // For "in" operator
}

// MatchOp defines the match operation type.
type MatchOp int

const (
	OpEquals MatchOp = iota
	OpContains
	OpStartsWith
	OpEndsWith
	OpRegex
	OpIn
	OpExists
)

// LoadRulesFromDir loads all YAML rule files from a directory.
func LoadRulesFromDir(dir string) ([]Rule, error) {
	var rules []Rule

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading rules directory %s: %w", dir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext != ".yml" && ext != ".yaml" {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		rule, err := LoadRuleFile(path)
		if err != nil {
			return nil, fmt.Errorf("loading rule %s: %w", path, err)
		}
		rules = append(rules, *rule)
	}

	return rules, nil
}

// LoadRuleFile loads a single SIGMA rule from a YAML file.
func LoadRuleFile(path string) (*Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var rule Rule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return nil, fmt.Errorf("parsing rule YAML: %w", err)
	}

	if rule.ID == "" {
		// Use filename as fallback ID.
		rule.ID = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}

	return &rule, nil
}

// CompileRule transforms a parsed rule into a compiled, efficient evaluation form.
func CompileRule(rule Rule) (*CompiledRule, error) {
	compiled := &CompiledRule{
		ID:          rule.ID,
		Title:       rule.Title,
		Description: rule.Description,
		Severity:    types.ParseSeverity(rule.Severity),
		Enabled:     rule.Status != "disabled",
		Tags:        rule.Tags,
		LogSource:   rule.LogSource,
		Correlation: rule.Correlation,
		Actions:     rule.Response,
		MessageTpl:  fmt.Sprintf("[%s] %s", rule.Severity, rule.Title),
	}

	// Compile named selections (selection_*) if present.
	if len(rule.Detection.Selections) > 0 {
		compiled.ConditionLogic = parseConditionLogic(rule.Detection.Condition)
		for name, selMap := range rule.Detection.Selections {
			var group []Condition
			for field, value := range selMap {
				cond, err := compileCondition(field, value)
				if err != nil {
					return nil, fmt.Errorf("compiling %s field %q: %w", name, field, err)
				}
				group = append(group, cond)
			}
			compiled.ConditionGroups = append(compiled.ConditionGroups, group)
		}
	}

	// Compile simple "selection" conditions (backward-compatible).
	for field, value := range rule.Detection.Selection {
		cond, err := compileCondition(field, value)
		if err != nil {
			return nil, fmt.Errorf("compiling selection for field %q: %w", field, err)
		}
		compiled.Conditions = append(compiled.Conditions, cond)
	}

	// Compile filter conditions.
	for field, value := range rule.Detection.Filter {
		cond, err := compileCondition(field, value)
		if err != nil {
			return nil, fmt.Errorf("compiling filter for field %q: %w", field, err)
		}
		compiled.Filters = append(compiled.Filters, cond)
	}

	return compiled, nil
}

// parseConditionLogic extracts the logical operator from a SIGMA condition string.
// Returns "or" if any "or" is found (e.g., "selection_a or selection_b"),
// "and" if "and" is found, defaults to "or" for named selections.
func parseConditionLogic(condition string) string {
	lower := strings.ToLower(condition)
	if strings.Contains(lower, " and ") && !strings.Contains(lower, " or ") {
		return "and"
	}
	return "or" // Default: named selections are OR'd
}

// compileCondition compiles a single field/value pair into a Condition.
func compileCondition(field string, value interface{}) (Condition, error) {
	cond := Condition{Field: field}

	// Handle modifiers in field name: "field|contains", "field|startswith", etc.
	parts := strings.SplitN(field, "|", 2)
	if len(parts) == 2 {
		cond.Field = parts[0]
		switch parts[1] {
		case "contains":
			cond.Operator = OpContains
		case "startswith":
			cond.Operator = OpStartsWith
		case "endswith":
			cond.Operator = OpEndsWith
		case "re":
			cond.Operator = OpRegex
		default:
			return cond, fmt.Errorf("unknown modifier %q", parts[1])
		}
	} else {
		cond.Operator = OpEquals
	}

	switch v := value.(type) {
	case string:
		cond.Value = v
		if cond.Operator == OpRegex {
			compiled, err := regexp.Compile(v)
			if err != nil {
				return cond, fmt.Errorf("compiling regex %q: %w", v, err)
			}
			cond.Regex = compiled
		}
	case []interface{}:
		// Preserve modifier-based operator (e.g., contains+list → containsAny).
		// Only default to OpIn when no modifier was specified (plain equality match).
		if cond.Operator == OpEquals {
			cond.Operator = OpIn
		}
		for _, item := range v {
			cond.Values = append(cond.Values, fmt.Sprintf("%v", item))
		}
	case bool:
		if v {
			cond.Operator = OpExists
		}
	default:
		cond.Value = fmt.Sprintf("%v", v)
	}

	return cond, nil
}

// Matches evaluates whether a log event matches this rule.
func (cr *CompiledRule) Matches(event types.LogEvent) bool {
	// Check log source filters.
	if cr.LogSource.Category != "" && cr.LogSource.Category != event.Category {
		return false
	}
	if cr.LogSource.Product != "" && cr.LogSource.Product != event.Platform {
		return false
	}

	matched := false

	// Evaluate named selection groups (SIGMA-style).
	if len(cr.ConditionGroups) > 0 {
		if cr.ConditionLogic == "and" {
			// All groups must match.
			matched = true
			for _, group := range cr.ConditionGroups {
				if !matchGroup(group, event) {
					matched = false
					break
				}
			}
		} else {
			// Any group matching is sufficient (OR).
			for _, group := range cr.ConditionGroups {
				if matchGroup(group, event) {
					matched = true
					break
				}
			}
		}
	}

	// Evaluate simple selection conditions (all must match — AND).
	if len(cr.Conditions) > 0 {
		allMatch := true
		for _, cond := range cr.Conditions {
			if !cond.Evaluate(event) {
				allMatch = false
				break
			}
		}
		if allMatch {
			matched = true
		}
	}

	// If neither condition groups nor simple conditions exist, match everything
	// (a rule with no detection logic is a catch-all).
	if len(cr.ConditionGroups) == 0 && len(cr.Conditions) == 0 {
		matched = true
	}

	if !matched {
		return false
	}

	// If any filter matches, the event is excluded.
	for _, filter := range cr.Filters {
		if filter.Evaluate(event) {
			return false
		}
	}

	return true
}

// matchGroup returns true if all conditions in the group match (AND within a group).
func matchGroup(group []Condition, event types.LogEvent) bool {
	for _, cond := range group {
		if !cond.Evaluate(event) {
			return false
		}
	}
	return len(group) > 0
}

// Evaluate checks a single condition against an event.
func (c *Condition) Evaluate(event types.LogEvent) bool {
	// Get the field value: try dotted lookup first, then special fields.
	value, ok := platform.LookupField(event.Fields, c.Field)
	if !ok {
		switch c.Field {
		case "raw", "message":
			value = event.Raw
			ok = true
		case "source":
			value = event.Source
			ok = true
		case "category":
			value = event.Category
			ok = true
		case "hostname":
			value = event.Hostname
			ok = true
		case "platform":
			value = event.Platform
			ok = true
		default:
			if c.Operator == OpExists {
				return false
			}
			return false
		}
	}

	switch c.Operator {
	case OpEquals:
		return strings.EqualFold(value, c.Value)
	case OpContains:
		lower := strings.ToLower(value)
		// When Values is populated (list), match if ANY value is a substring (OR).
		if len(c.Values) > 0 {
			for _, v := range c.Values {
				if strings.Contains(lower, strings.ToLower(v)) {
					return true
				}
			}
			return false
		}
		return strings.Contains(lower, strings.ToLower(c.Value))
	case OpStartsWith:
		lower := strings.ToLower(value)
		if len(c.Values) > 0 {
			for _, v := range c.Values {
				if strings.HasPrefix(lower, strings.ToLower(v)) {
					return true
				}
			}
			return false
		}
		return strings.HasPrefix(lower, strings.ToLower(c.Value))
	case OpEndsWith:
		lower := strings.ToLower(value)
		if len(c.Values) > 0 {
			for _, v := range c.Values {
				if strings.HasSuffix(lower, strings.ToLower(v)) {
					return true
				}
			}
			return false
		}
		return strings.HasSuffix(lower, strings.ToLower(c.Value))
	case OpRegex:
		if c.Regex != nil {
			return c.Regex.MatchString(value)
		}
		return false
	case OpIn:
		for _, v := range c.Values {
			if strings.EqualFold(value, v) {
				return true
			}
		}
		return false
	case OpExists:
		return ok
	default:
		return false
	}
}

// CorrelationKey generates a grouping key for correlation.
func (cr *CompiledRule) CorrelationKey(event types.LogEvent) string {
	if cr.Correlation == nil {
		return ""
	}
	var parts []string
	for _, field := range cr.Correlation.GroupBy {
		if val, ok := event.Fields[field]; ok {
			parts = append(parts, val)
		}
	}
	return strings.Join(parts, ":")
}

// FormatMessage creates a human-readable alert message.
func (cr *CompiledRule) FormatMessage(event types.LogEvent) string {
	msg := fmt.Sprintf("[%s] %s", cr.Severity.String(), cr.Title)
	if ip, ok := event.Fields["source_ip"]; ok {
		msg += fmt.Sprintf(" from %s", ip)
	}
	if user, ok := event.Fields["username"]; ok {
		msg += fmt.Sprintf(" (user: %s)", user)
	}
	return msg
}

// ResolveTarget extracts the target value from an event based on the action's target field.
func (a *RuleAction) ResolveTarget(event types.LogEvent) string {
	if a.TargetField == "" {
		return ""
	}
	if val, ok := event.Fields[a.TargetField]; ok {
		return val
	}
	return ""
}
