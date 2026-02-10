package skills

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rs/zerolog"
	"github.com/sentinel-agent/sentinel/internal/types"
)

// ForensicsSkill provides log search and incident investigation capabilities.
type ForensicsSkill struct {
	db     *sql.DB
	logger zerolog.Logger
}

// NewForensicsSkill creates a forensics skill attached to the database.
func NewForensicsSkill(db *sql.DB, logger zerolog.Logger) *ForensicsSkill {
	return &ForensicsSkill{
		db:     db,
		logger: logger.With().Str("skill", "forensics").Logger(),
	}
}

// --- get_logs skill ---

type GetLogsSkill struct {
	db     *sql.DB
	logger zerolog.Logger
}

func NewGetLogsSkill(db *sql.DB, logger zerolog.Logger) *GetLogsSkill {
	return &GetLogsSkill{db: db, logger: logger.With().Str("skill", "get_logs").Logger()}
}

func (s *GetLogsSkill) Name() string { return "get_logs" }
func (s *GetLogsSkill) Description() string {
	return "Search log events by keyword, source, or category. Returns recent matching log entries for investigation."
}

func (s *GetLogsSkill) ParametersSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"keyword": map[string]interface{}{
				"type":        "string",
				"description": "Search keyword to match against log content",
			},
			"source": map[string]interface{}{
				"type":        "string",
				"description": "Filter by log source (e.g. syslog, eventlog)",
			},
			"category": map[string]interface{}{
				"type":        "string",
				"description": "Filter by category (e.g. auth, web, network)",
			},
			"limit": map[string]interface{}{
				"type":        "integer",
				"description": "Maximum number of results (default 20, max 100)",
			},
		},
		"required": []string{},
	}
}

func (s *GetLogsSkill) Validate(params map[string]interface{}) error {
	return nil // all params optional
}

func (s *GetLogsSkill) Execute(ctx context.Context, params map[string]interface{}) (*types.ToolResult, error) {
	limit := GetIntParam(params, "limit", 20)
	if limit > 100 {
		limit = 100
	}

	query := "SELECT id, timestamp, source, category, severity, hostname, raw FROM events WHERE 1=1"
	var args []interface{}

	if kw, err := GetStringParam(params, "keyword"); err == nil && kw != "" {
		query += " AND raw LIKE ?"
		args = append(args, "%"+kw+"%")
	}
	if src, err := GetStringParam(params, "source"); err == nil && src != "" {
		query += " AND source = ?"
		args = append(args, src)
	}
	if cat, err := GetStringParam(params, "category"); err == nil && cat != "" {
		query += " AND category = ?"
		args = append(args, cat)
	}

	query += " ORDER BY timestamp DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return &types.ToolResult{Success: false, Error: err.Error()}, nil
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var id, source, category, hostname, raw string
		var ts string
		var sev int
		if err := rows.Scan(&id, &ts, &source, &category, &sev, &hostname, &raw); err != nil {
			continue
		}
		results = append(results, map[string]interface{}{
			"id": id, "timestamp": ts, "source": source,
			"category": category, "severity": sev, "hostname": hostname, "raw": raw,
		})
	}

	output, _ := json.MarshalIndent(results, "", "  ")
	return &types.ToolResult{
		Success: true,
		Output:  string(output),
		Data:    map[string]interface{}{"count": len(results)},
	}, nil
}

// --- search_incidents skill ---

type SearchIncidentsSkill struct {
	db     *sql.DB
	logger zerolog.Logger
}

func NewSearchIncidentsSkill(db *sql.DB, logger zerolog.Logger) *SearchIncidentsSkill {
	return &SearchIncidentsSkill{db: db, logger: logger.With().Str("skill", "search_incidents").Logger()}
}

func (s *SearchIncidentsSkill) Name() string { return "search_incidents" }
func (s *SearchIncidentsSkill) Description() string {
	return "Search past security incidents by source IP, rule ID, severity, or status. Returns matching incidents for context."
}

func (s *SearchIncidentsSkill) ParametersSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"source_ip": map[string]interface{}{
				"type":        "string",
				"description": "Filter by source IP address",
			},
			"rule_id": map[string]interface{}{
				"type":        "string",
				"description": "Filter by detection rule ID",
			},
			"status": map[string]interface{}{
				"type":        "string",
				"description": "Filter by status (open, acknowledged, resolved, false_positive)",
			},
			"limit": map[string]interface{}{
				"type":        "integer",
				"description": "Max results (default 10)",
			},
		},
		"required": []string{},
	}
}

func (s *SearchIncidentsSkill) Validate(params map[string]interface{}) error { return nil }

func (s *SearchIncidentsSkill) Execute(ctx context.Context, params map[string]interface{}) (*types.ToolResult, error) {
	limit := GetIntParam(params, "limit", 10)
	if limit > 50 {
		limit = 50
	}

	query := "SELECT id, title, severity, status, rule_id, source_ip, created_at FROM incidents WHERE 1=1"
	var args []interface{}

	if ip, err := GetStringParam(params, "source_ip"); err == nil && ip != "" {
		query += " AND source_ip = ?"
		args = append(args, ip)
	}
	if rid, err := GetStringParam(params, "rule_id"); err == nil && rid != "" {
		query += " AND rule_id = ?"
		args = append(args, rid)
	}
	if st, err := GetStringParam(params, "status"); err == nil && st != "" {
		query += " AND status = ?"
		args = append(args, st)
	}

	query += " ORDER BY created_at DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return &types.ToolResult{Success: false, Error: err.Error()}, nil
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var id, title, status, ruleID, sourceIP, createdAt string
		var sev int
		if err := rows.Scan(&id, &title, &sev, &status, &ruleID, &sourceIP, &createdAt); err != nil {
			continue
		}
		results = append(results, map[string]interface{}{
			"id": id, "title": title, "severity": sev, "status": status,
			"rule_id": ruleID, "source_ip": sourceIP, "created_at": createdAt,
		})
	}

	output, _ := json.MarshalIndent(results, "", "  ")
	return &types.ToolResult{
		Success: true,
		Output:  string(output),
		Data:    map[string]interface{}{"count": len(results)},
	}, nil
}

// --- check_if_internal skill ---

type CheckInternalSkill struct {
	internalCIDRs []string
	logger        zerolog.Logger
}

func NewCheckInternalSkill(internalCIDRs []string, logger zerolog.Logger) *CheckInternalSkill {
	if len(internalCIDRs) == 0 {
		internalCIDRs = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"}
	}
	return &CheckInternalSkill{internalCIDRs: internalCIDRs, logger: logger}
}

func (s *CheckInternalSkill) Name() string { return "check_if_internal" }
func (s *CheckInternalSkill) Description() string {
	return "Check if an IP address belongs to a private/internal network range (RFC1918). Returns whether the IP is internal."
}

func (s *CheckInternalSkill) ParametersSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"ip": map[string]interface{}{
				"type":        "string",
				"description": "IP address to check",
			},
		},
		"required": []string{"ip"},
	}
}

func (s *CheckInternalSkill) Validate(params map[string]interface{}) error {
	ip, err := GetStringParam(params, "ip")
	if err != nil {
		return err
	}
	return ValidateIP(ip)
}

func (s *CheckInternalSkill) Execute(ctx context.Context, params map[string]interface{}) (*types.ToolResult, error) {
	ip, _ := GetStringParam(params, "ip")

	isInternal := false
	var matchedRange string
	for _, cidr := range s.internalCIDRs {
		if IsIPInCIDR(ip, cidr) {
			isInternal = true
			matchedRange = cidr
			break
		}
	}

	result := map[string]interface{}{
		"ip":          ip,
		"is_internal": isInternal,
	}
	if isInternal {
		result["matched_range"] = matchedRange
	}

	var sb strings.Builder
	if isInternal {
		sb.WriteString(fmt.Sprintf("IP %s IS INTERNAL (range: %s). Do NOT block — investigate first.", ip, matchedRange))
	} else {
		sb.WriteString(fmt.Sprintf("IP %s is EXTERNAL. May be blocked if confirmed malicious.", ip))
	}

	return &types.ToolResult{
		Success: true,
		Output:  sb.String(),
		Data:    result,
	}, nil
}
