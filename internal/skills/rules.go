package skills

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/sentinel-agent/sentinel/internal/engine"
	"github.com/sentinel-agent/sentinel/internal/types"
)

// ---------------------------------------------------------------------------
// list_rules — List all detection rules with status
// ---------------------------------------------------------------------------

// ListRulesSkill lets the agent inspect the current rule set.
type ListRulesSkill struct {
	eng    *engine.Engine
	logger zerolog.Logger
}

func NewListRulesSkill(eng *engine.Engine, logger zerolog.Logger) *ListRulesSkill {
	return &ListRulesSkill{eng: eng, logger: logger.With().Str("skill", "list_rules").Logger()}
}

func (s *ListRulesSkill) Name() string { return "list_rules" }
func (s *ListRulesSkill) Description() string {
	return "List all loaded SIGMA detection rules with their ID, title, severity, enabled/disabled status, and tags. Use to understand what the engine is detecting."
}

func (s *ListRulesSkill) ParametersSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"severity": map[string]interface{}{
				"type":        "string",
				"description": "Filter by severity (info, low, medium, high, critical)",
			},
			"enabled_only": map[string]interface{}{
				"type":        "boolean",
				"description": "If true, only return enabled rules",
			},
		},
		"required": []string{},
	}
}

func (s *ListRulesSkill) Validate(params map[string]interface{}) error { return nil }

func (s *ListRulesSkill) Execute(ctx context.Context, params map[string]interface{}) (*types.ToolResult, error) {
	rules := s.eng.GetRules()

	sevFilter, _ := GetStringParam(params, "severity")
	enabledOnly := false
	if v, ok := params["enabled_only"]; ok {
		if b, ok := v.(bool); ok {
			enabledOnly = b
		}
	}

	var results []map[string]interface{}
	for _, r := range rules {
		if enabledOnly && !r.Enabled {
			continue
		}
		if sevFilter != "" && !strings.EqualFold(r.Severity.String(), sevFilter) {
			continue
		}
		results = append(results, map[string]interface{}{
			"id":          r.ID,
			"title":       r.Title,
			"description": r.Description,
			"severity":    r.Severity.String(),
			"enabled":     r.Enabled,
			"tags":        r.Tags,
		})
	}

	output, _ := json.MarshalIndent(results, "", "  ")
	return &types.ToolResult{
		Success: true,
		Output:  string(output),
		Data:    map[string]interface{}{"count": len(results), "total": len(rules)},
	}, nil
}

// ---------------------------------------------------------------------------
// get_rule — Get full details of a single rule
// ---------------------------------------------------------------------------

type GetRuleSkill struct {
	eng    *engine.Engine
	logger zerolog.Logger
}

func NewGetRuleSkill(eng *engine.Engine, logger zerolog.Logger) *GetRuleSkill {
	return &GetRuleSkill{eng: eng, logger: logger.With().Str("skill", "get_rule").Logger()}
}

func (s *GetRuleSkill) Name() string { return "get_rule" }
func (s *GetRuleSkill) Description() string {
	return "Get the full details of a specific detection rule by ID, including its detection logic, correlation settings, and response actions."
}

func (s *GetRuleSkill) ParametersSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"rule_id": map[string]interface{}{
				"type":        "string",
				"description": "The rule ID to look up",
			},
		},
		"required": []string{"rule_id"},
	}
}

func (s *GetRuleSkill) Validate(params map[string]interface{}) error {
	id, err := GetStringParam(params, "rule_id")
	if err != nil {
		return err
	}
	if id == "" {
		return fmt.Errorf("rule_id cannot be empty")
	}
	return nil
}

func (s *GetRuleSkill) Execute(ctx context.Context, params map[string]interface{}) (*types.ToolResult, error) {
	id, _ := GetStringParam(params, "rule_id")
	rule := s.eng.GetRule(id)
	if rule == nil {
		return &types.ToolResult{
			Success: false,
			Error:   fmt.Sprintf("rule %q not found", id),
		}, nil
	}

	// Build a rich detail map.
	conditions := make([]string, 0, len(rule.Conditions))
	for _, c := range rule.Conditions {
		conditions = append(conditions, fmt.Sprintf("%s %s %q", c.Field, opName(c.Operator), c.Value))
	}

	detail := map[string]interface{}{
		"id":          rule.ID,
		"title":       rule.Title,
		"description": rule.Description,
		"severity":    rule.Severity.String(),
		"enabled":     rule.Enabled,
		"tags":        rule.Tags,
		"logsource": map[string]interface{}{
			"category": rule.LogSource.Category,
			"product":  rule.LogSource.Product,
			"service":  rule.LogSource.Service,
		},
		"conditions": conditions,
	}

	if rule.Correlation != nil {
		detail["correlation"] = map[string]interface{}{
			"group_by":  rule.Correlation.GroupBy,
			"threshold": rule.Correlation.Threshold,
			"window":    rule.Correlation.Window.String(),
		}
	}

	if len(rule.Actions) > 0 {
		var actions []map[string]string
		for _, a := range rule.Actions {
			actions = append(actions, map[string]string{
				"type":         string(a.Type),
				"target_field": a.TargetField,
			})
		}
		detail["response_actions"] = actions
	}

	output, _ := json.MarshalIndent(detail, "", "  ")
	return &types.ToolResult{
		Success: true,
		Output:  string(output),
		Data:    detail,
	}, nil
}

func opName(op engine.MatchOp) string {
	switch op {
	case engine.OpEquals:
		return "equals"
	case engine.OpContains:
		return "contains"
	case engine.OpStartsWith:
		return "starts_with"
	case engine.OpEndsWith:
		return "ends_with"
	case engine.OpRegex:
		return "regex"
	case engine.OpIn:
		return "in"
	case engine.OpExists:
		return "exists"
	default:
		return "unknown"
	}
}

// ---------------------------------------------------------------------------
// create_rule — Create a new SIGMA detection rule
// ---------------------------------------------------------------------------

type CreateRuleSkill struct {
	eng    *engine.Engine
	logger zerolog.Logger
}

func NewCreateRuleSkill(eng *engine.Engine, logger zerolog.Logger) *CreateRuleSkill {
	return &CreateRuleSkill{eng: eng, logger: logger.With().Str("skill", "create_rule").Logger()}
}

func (s *CreateRuleSkill) Name() string { return "create_rule" }
func (s *CreateRuleSkill) Description() string {
	return "Create a new SIGMA-compatible detection rule. The rule is compiled, loaded into the engine, and persisted to disk. Provide the rule fields: id, title, description, severity (info/low/medium/high/critical), logsource category, and detection selection fields."
}

func (s *CreateRuleSkill) ParametersSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"id": map[string]interface{}{
				"type":        "string",
				"description": "Unique rule identifier (snake_case, e.g. suspicious_powershell)",
			},
			"title": map[string]interface{}{
				"type":        "string",
				"description": "Human-readable rule title",
			},
			"description": map[string]interface{}{
				"type":        "string",
				"description": "What this rule detects and why it matters",
			},
			"severity": map[string]interface{}{
				"type":        "string",
				"description": "Rule severity: info, low, medium, high, or critical",
			},
			"category": map[string]interface{}{
				"type":        "string",
				"description": "Log source category to match (auth, web, network, container, system)",
			},
			"product": map[string]interface{}{
				"type":        "string",
				"description": "Log source product filter (linux, windows, nginx). Optional.",
			},
			"selection": map[string]interface{}{
				"type":        "object",
				"description": "Detection selection map, e.g. {\"raw|contains\": \"Failed password\", \"source_ip|re\": \"^10\\\\.\"}",
			},
			"filter": map[string]interface{}{
				"type":        "object",
				"description": "Optional filter (exclusion) map, same syntax as selection",
			},
			"group_by": map[string]interface{}{
				"type":        "array",
				"description": "Fields to group by for correlation (e.g. [\"source_ip\"]). Optional.",
				"items":       map[string]interface{}{"type": "string"},
			},
			"threshold": map[string]interface{}{
				"type":        "integer",
				"description": "Correlation threshold — min events in window to trigger. Optional.",
			},
			"window": map[string]interface{}{
				"type":        "string",
				"description": "Correlation time window (e.g. \"5m\", \"1h\"). Required if threshold is set.",
			},
			"response_type": map[string]interface{}{
				"type":        "string",
				"description": "Response action type: block_ip, disable_user, kill_process, isolate_container. Optional.",
			},
			"response_target_field": map[string]interface{}{
				"type":        "string",
				"description": "Event field to use as the response target (e.g. source_ip, username). Required if response_type is set.",
			},
			"tags": map[string]interface{}{
				"type":        "array",
				"description": "MITRE ATT&CK or custom tags (e.g. [\"attack.t1110\", \"attack.credential_access\"])",
				"items":       map[string]interface{}{"type": "string"},
			},
		},
		"required": []string{"id", "title", "description", "severity", "category", "selection"},
	}
}

func (s *CreateRuleSkill) Validate(params map[string]interface{}) error {
	id, err := GetStringParam(params, "id")
	if err != nil {
		return err
	}
	if strings.ContainsAny(id, " /\\;|&$`'\"") {
		return fmt.Errorf("rule id %q contains invalid characters", id)
	}
	if _, err := GetStringParam(params, "title"); err != nil {
		return err
	}
	sev, err := GetStringParam(params, "severity")
	if err != nil {
		return err
	}
	switch strings.ToLower(sev) {
	case "info", "low", "medium", "high", "critical":
	default:
		return fmt.Errorf("invalid severity %q — must be info/low/medium/high/critical", sev)
	}
	if _, ok := params["selection"]; !ok {
		return fmt.Errorf("selection is required")
	}
	return nil
}

func (s *CreateRuleSkill) Execute(ctx context.Context, params map[string]interface{}) (*types.ToolResult, error) {
	id, _ := GetStringParam(params, "id")
	title, _ := GetStringParam(params, "title")
	desc, _ := GetStringParam(params, "description")
	sev, _ := GetStringParam(params, "severity")
	cat, _ := GetStringParam(params, "category")
	product, _ := GetStringParam(params, "product")

	rule := engine.Rule{
		ID:          id,
		Title:       title,
		Description: desc,
		Severity:    strings.ToLower(sev),
		Status:      "active",
		Author:      "sentinel-ai",
	}

	// Tags.
	if tags, ok := params["tags"]; ok {
		if tagSlice, ok := tags.([]interface{}); ok {
			for _, t := range tagSlice {
				if s, ok := t.(string); ok {
					rule.Tags = append(rule.Tags, s)
				}
			}
		}
	}

	// Log source.
	rule.LogSource = engine.RuleLogSource{
		Category: cat,
		Product:  product,
	}

	// Detection selection.
	sel := toStringInterfaceMap(params["selection"])
	rule.Detection = engine.RuleDetection{
		Selection: sel,
		Condition: "selection",
	}

	// Detection filter (optional).
	if f, ok := params["filter"]; ok {
		filt := toStringInterfaceMap(f)
		if len(filt) > 0 {
			rule.Detection.Filter = filt
			rule.Detection.Condition = "selection and not filter"
		}
	}

	// Correlation (optional).
	threshold := GetIntParam(params, "threshold", 0)
	if threshold > 0 {
		windowStr, _ := GetStringParam(params, "window")
		if windowStr == "" {
			windowStr = "5m"
		}
		window, err := time.ParseDuration(windowStr)
		if err != nil {
			return &types.ToolResult{Success: false, Error: fmt.Sprintf("invalid window %q: %v", windowStr, err)}, nil
		}

		var groupBy []string
		if gb, ok := params["group_by"]; ok {
			if gbSlice, ok := gb.([]interface{}); ok {
				for _, g := range gbSlice {
					if s, ok := g.(string); ok {
						groupBy = append(groupBy, s)
					}
				}
			}
		}
		if len(groupBy) == 0 {
			groupBy = []string{"source_ip"}
		}

		rule.Correlation = &engine.RuleCorrelation{
			GroupBy:   groupBy,
			Threshold: threshold,
			Window:    window,
		}
	}

	// Response action (optional).
	if rt, err := GetStringParam(params, "response_type"); err == nil && rt != "" {
		tf, _ := GetStringParam(params, "response_target_field")
		rule.Response = []engine.RuleAction{
			{Type: types.ActionType(rt), TargetField: tf},
		}
	}

	// Add to engine with persistence.
	if err := s.eng.AddRule(rule, true); err != nil {
		return &types.ToolResult{Success: false, Error: err.Error()}, nil
	}

	s.logger.Info().Str("rule", id).Str("severity", sev).Msg("rule created by AI agent")

	return &types.ToolResult{
		Success: true,
		Output:  fmt.Sprintf("Rule %q created successfully. Title: %s, Severity: %s, Category: %s. It is now active and will be evaluated against incoming events.", id, title, sev, cat),
		Data: map[string]interface{}{
			"rule_id":  id,
			"title":    title,
			"severity": sev,
			"status":   "active",
		},
	}, nil
}

// ---------------------------------------------------------------------------
// update_rule — Modify an existing detection rule
// ---------------------------------------------------------------------------

type UpdateRuleSkill struct {
	eng    *engine.Engine
	logger zerolog.Logger
}

func NewUpdateRuleSkill(eng *engine.Engine, logger zerolog.Logger) *UpdateRuleSkill {
	return &UpdateRuleSkill{eng: eng, logger: logger.With().Str("skill", "update_rule").Logger()}
}

func (s *UpdateRuleSkill) Name() string { return "update_rule" }
func (s *UpdateRuleSkill) Description() string {
	return "Update an existing detection rule's fields: severity, detection logic, thresholds, response actions, or enabled status. The change is persisted to disk."
}

func (s *UpdateRuleSkill) ParametersSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"rule_id": map[string]interface{}{
				"type":        "string",
				"description": "ID of the rule to update",
			},
			"title": map[string]interface{}{
				"type":        "string",
				"description": "New title (leave empty to keep current)",
			},
			"description": map[string]interface{}{
				"type":        "string",
				"description": "New description (leave empty to keep current)",
			},
			"severity": map[string]interface{}{
				"type":        "string",
				"description": "New severity: info, low, medium, high, or critical",
			},
			"enabled": map[string]interface{}{
				"type":        "boolean",
				"description": "Enable or disable the rule",
			},
			"selection": map[string]interface{}{
				"type":        "object",
				"description": "New detection selection map (replaces existing)",
			},
			"filter": map[string]interface{}{
				"type":        "object",
				"description": "New detection filter map (replaces existing)",
			},
			"threshold": map[string]interface{}{
				"type":        "integer",
				"description": "New correlation threshold (0 to remove correlation)",
			},
			"window": map[string]interface{}{
				"type":        "string",
				"description": "New correlation window (e.g. \"5m\")",
			},
			"group_by": map[string]interface{}{
				"type":        "array",
				"description": "New correlation group-by fields",
				"items":       map[string]interface{}{"type": "string"},
			},
			"response_type": map[string]interface{}{
				"type":        "string",
				"description": "New response action type (empty to remove)",
			},
			"response_target_field": map[string]interface{}{
				"type":        "string",
				"description": "New response target field",
			},
			"tags": map[string]interface{}{
				"type":        "array",
				"description": "New tag list (replaces existing)",
				"items":       map[string]interface{}{"type": "string"},
			},
		},
		"required": []string{"rule_id"},
	}
}

func (s *UpdateRuleSkill) Validate(params map[string]interface{}) error {
	id, err := GetStringParam(params, "rule_id")
	if err != nil {
		return err
	}
	if s.eng.GetRule(id) == nil {
		return fmt.Errorf("rule %q not found", id)
	}
	if sev, err := GetStringParam(params, "severity"); err == nil && sev != "" {
		switch strings.ToLower(sev) {
		case "info", "low", "medium", "high", "critical":
		default:
			return fmt.Errorf("invalid severity %q", sev)
		}
	}
	return nil
}

func (s *UpdateRuleSkill) Execute(ctx context.Context, params map[string]interface{}) (*types.ToolResult, error) {
	id, _ := GetStringParam(params, "rule_id")
	existing := s.eng.GetRule(id)
	if existing == nil {
		return &types.ToolResult{Success: false, Error: fmt.Sprintf("rule %q not found", id)}, nil
	}

	// Reconstruct a Rule from compiled rule, then apply changes.
	rule := engine.Rule{
		ID:          existing.ID,
		Title:       existing.Title,
		Description: existing.Description,
		Severity:    existing.Severity.String(),
		Author:      "sentinel-ai",
		Tags:        existing.Tags,
		LogSource:   existing.LogSource,
		Correlation: existing.Correlation,
		Response:    existing.Actions,
	}
	if existing.Enabled {
		rule.Status = "active"
	} else {
		rule.Status = "disabled"
	}

	// Rebuild detection from compiled conditions.
	selection := make(map[string]interface{})
	for _, c := range existing.Conditions {
		key := c.Field
		if c.Operator == engine.OpContains {
			key += "|contains"
		} else if c.Operator == engine.OpStartsWith {
			key += "|startswith"
		} else if c.Operator == engine.OpEndsWith {
			key += "|endswith"
		} else if c.Operator == engine.OpRegex {
			key += "|re"
		}
		if c.Operator == engine.OpIn {
			vals := make([]interface{}, len(c.Values))
			for i, v := range c.Values {
				vals[i] = v
			}
			selection[key] = vals
		} else {
			selection[key] = c.Value
		}
	}
	filter := make(map[string]interface{})
	for _, c := range existing.Filters {
		key := c.Field
		if c.Operator == engine.OpContains {
			key += "|contains"
		}
		filter[key] = c.Value
	}
	rule.Detection = engine.RuleDetection{
		Selection: selection,
		Condition: "selection",
	}
	if len(filter) > 0 {
		rule.Detection.Filter = filter
		rule.Detection.Condition = "selection and not filter"
	}

	// Apply updates.
	changes := []string{}

	if title, err := GetStringParam(params, "title"); err == nil && title != "" {
		rule.Title = title
		changes = append(changes, "title")
	}
	if desc, err := GetStringParam(params, "description"); err == nil && desc != "" {
		rule.Description = desc
		changes = append(changes, "description")
	}
	if sev, err := GetStringParam(params, "severity"); err == nil && sev != "" {
		rule.Severity = strings.ToLower(sev)
		changes = append(changes, "severity")
	}
	if v, ok := params["enabled"]; ok {
		if b, ok := v.(bool); ok {
			if b {
				rule.Status = "active"
			} else {
				rule.Status = "disabled"
			}
			changes = append(changes, "enabled")
		}
	}
	if sel, ok := params["selection"]; ok {
		rule.Detection.Selection = toStringInterfaceMap(sel)
		rule.Detection.Condition = "selection"
		if len(rule.Detection.Filter) > 0 {
			rule.Detection.Condition = "selection and not filter"
		}
		changes = append(changes, "detection.selection")
	}
	if f, ok := params["filter"]; ok {
		rule.Detection.Filter = toStringInterfaceMap(f)
		if len(rule.Detection.Filter) > 0 {
			rule.Detection.Condition = "selection and not filter"
		} else {
			rule.Detection.Condition = "selection"
		}
		changes = append(changes, "detection.filter")
	}
	if tags, ok := params["tags"]; ok {
		rule.Tags = nil
		if tagSlice, ok := tags.([]interface{}); ok {
			for _, t := range tagSlice {
				if s, ok := t.(string); ok {
					rule.Tags = append(rule.Tags, s)
				}
			}
		}
		changes = append(changes, "tags")
	}

	// Correlation.
	if _, ok := params["threshold"]; ok {
		threshold := GetIntParam(params, "threshold", 0)
		if threshold > 0 {
			windowStr, _ := GetStringParam(params, "window")
			if windowStr == "" {
				windowStr = "5m"
			}
			window, err := time.ParseDuration(windowStr)
			if err != nil {
				return &types.ToolResult{Success: false, Error: fmt.Sprintf("invalid window: %v", err)}, nil
			}
			var groupBy []string
			if gb, ok := params["group_by"]; ok {
				if gbSlice, ok := gb.([]interface{}); ok {
					for _, g := range gbSlice {
						if s, ok := g.(string); ok {
							groupBy = append(groupBy, s)
						}
					}
				}
			}
			if len(groupBy) == 0 && rule.Correlation != nil {
				groupBy = rule.Correlation.GroupBy
			}
			if len(groupBy) == 0 {
				groupBy = []string{"source_ip"}
			}
			rule.Correlation = &engine.RuleCorrelation{GroupBy: groupBy, Threshold: threshold, Window: window}
			changes = append(changes, "correlation")
		} else {
			rule.Correlation = nil
			changes = append(changes, "correlation(removed)")
		}
	}

	// Response.
	if rt, err := GetStringParam(params, "response_type"); err == nil {
		if rt != "" {
			tf, _ := GetStringParam(params, "response_target_field")
			rule.Response = []engine.RuleAction{{Type: types.ActionType(rt), TargetField: tf}}
			changes = append(changes, "response")
		} else {
			rule.Response = nil
			changes = append(changes, "response(removed)")
		}
	}

	if err := s.eng.UpdateRule(rule, true); err != nil {
		return &types.ToolResult{Success: false, Error: err.Error()}, nil
	}

	s.logger.Info().Str("rule", id).Strs("changes", changes).Msg("rule updated by AI agent")

	return &types.ToolResult{
		Success: true,
		Output:  fmt.Sprintf("Rule %q updated successfully. Changed: %s.", id, strings.Join(changes, ", ")),
		Data:    map[string]interface{}{"rule_id": id, "changes": changes},
	}, nil
}

// ---------------------------------------------------------------------------
// delete_rule — Remove a detection rule
// ---------------------------------------------------------------------------

type DeleteRuleSkill struct {
	eng    *engine.Engine
	logger zerolog.Logger
}

func NewDeleteRuleSkill(eng *engine.Engine, logger zerolog.Logger) *DeleteRuleSkill {
	return &DeleteRuleSkill{eng: eng, logger: logger.With().Str("skill", "delete_rule").Logger()}
}

func (s *DeleteRuleSkill) Name() string { return "delete_rule" }
func (s *DeleteRuleSkill) Description() string {
	return "Delete a detection rule by ID. Removes it from the engine and deletes the YAML file from disk. Use with caution."
}

func (s *DeleteRuleSkill) ParametersSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"rule_id": map[string]interface{}{
				"type":        "string",
				"description": "ID of the rule to delete",
			},
			"reason": map[string]interface{}{
				"type":        "string",
				"description": "Justification for deleting the rule",
			},
		},
		"required": []string{"rule_id", "reason"},
	}
}

func (s *DeleteRuleSkill) Validate(params map[string]interface{}) error {
	id, err := GetStringParam(params, "rule_id")
	if err != nil {
		return err
	}
	if s.eng.GetRule(id) == nil {
		return fmt.Errorf("rule %q not found", id)
	}
	if _, err := GetStringParam(params, "reason"); err != nil {
		return fmt.Errorf("reason is required for rule deletion")
	}
	return nil
}

func (s *DeleteRuleSkill) Execute(ctx context.Context, params map[string]interface{}) (*types.ToolResult, error) {
	id, _ := GetStringParam(params, "rule_id")
	reason, _ := GetStringParam(params, "reason")

	if err := s.eng.DeleteRule(id, true); err != nil {
		return &types.ToolResult{Success: false, Error: err.Error()}, nil
	}

	s.logger.Warn().Str("rule", id).Str("reason", reason).Msg("rule deleted by AI agent")

	return &types.ToolResult{
		Success: true,
		Output:  fmt.Sprintf("Rule %q deleted successfully. Reason: %s", id, reason),
		Data:    map[string]interface{}{"rule_id": id, "reason": reason},
	}, nil
}

// ---------------------------------------------------------------------------
// enable_rule / disable_rule — Toggle rule status
// ---------------------------------------------------------------------------

type EnableRuleSkill struct {
	eng    *engine.Engine
	logger zerolog.Logger
}

func NewEnableRuleSkill(eng *engine.Engine, logger zerolog.Logger) *EnableRuleSkill {
	return &EnableRuleSkill{eng: eng, logger: logger.With().Str("skill", "enable_rule").Logger()}
}

func (s *EnableRuleSkill) Name() string { return "enable_rule" }
func (s *EnableRuleSkill) Description() string {
	return "Enable a disabled detection rule so it starts matching incoming events again."
}

func (s *EnableRuleSkill) ParametersSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"rule_id": map[string]interface{}{
				"type":        "string",
				"description": "ID of the rule to enable",
			},
		},
		"required": []string{"rule_id"},
	}
}

func (s *EnableRuleSkill) Validate(params map[string]interface{}) error {
	id, err := GetStringParam(params, "rule_id")
	if err != nil {
		return err
	}
	if s.eng.GetRule(id) == nil {
		return fmt.Errorf("rule %q not found", id)
	}
	return nil
}

func (s *EnableRuleSkill) Execute(ctx context.Context, params map[string]interface{}) (*types.ToolResult, error) {
	id, _ := GetStringParam(params, "rule_id")
	if err := s.eng.EnableRule(id); err != nil {
		return &types.ToolResult{Success: false, Error: err.Error()}, nil
	}
	s.logger.Info().Str("rule", id).Msg("rule enabled by AI agent")
	return &types.ToolResult{
		Success: true,
		Output:  fmt.Sprintf("Rule %q is now enabled and actively detecting.", id),
		Data:    map[string]interface{}{"rule_id": id, "enabled": true},
	}, nil
}

type DisableRuleSkill struct {
	eng    *engine.Engine
	logger zerolog.Logger
}

func NewDisableRuleSkill(eng *engine.Engine, logger zerolog.Logger) *DisableRuleSkill {
	return &DisableRuleSkill{eng: eng, logger: logger.With().Str("skill", "disable_rule").Logger()}
}

func (s *DisableRuleSkill) Name() string { return "disable_rule" }
func (s *DisableRuleSkill) Description() string {
	return "Disable a detection rule without deleting it. The rule will stop matching events until re-enabled. Use to reduce false positives or during tuning."
}

func (s *DisableRuleSkill) ParametersSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"rule_id": map[string]interface{}{
				"type":        "string",
				"description": "ID of the rule to disable",
			},
			"reason": map[string]interface{}{
				"type":        "string",
				"description": "Reason for disabling (e.g. too many false positives)",
			},
		},
		"required": []string{"rule_id"},
	}
}

func (s *DisableRuleSkill) Validate(params map[string]interface{}) error {
	id, err := GetStringParam(params, "rule_id")
	if err != nil {
		return err
	}
	if s.eng.GetRule(id) == nil {
		return fmt.Errorf("rule %q not found", id)
	}
	return nil
}

func (s *DisableRuleSkill) Execute(ctx context.Context, params map[string]interface{}) (*types.ToolResult, error) {
	id, _ := GetStringParam(params, "rule_id")
	reason, _ := GetStringParam(params, "reason")

	if err := s.eng.DisableRule(id); err != nil {
		return &types.ToolResult{Success: false, Error: err.Error()}, nil
	}
	s.logger.Warn().Str("rule", id).Str("reason", reason).Msg("rule disabled by AI agent")
	return &types.ToolResult{
		Success: true,
		Output:  fmt.Sprintf("Rule %q is now disabled. Reason: %s", id, reason),
		Data:    map[string]interface{}{"rule_id": id, "enabled": false, "reason": reason},
	}, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// toStringInterfaceMap converts an interface{} to map[string]interface{}.
func toStringInterfaceMap(v interface{}) map[string]interface{} {
	if v == nil {
		return nil
	}
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	return nil
}
