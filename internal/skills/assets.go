package skills

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog"
	"github.com/sentinel-agent/sentinel/internal/types"
)

// AssetQuerySkill queries the asset/incident database for host context.
type AssetQuerySkill struct {
	db     *sql.DB
	logger zerolog.Logger
}

func NewAssetQuerySkill(db *sql.DB, logger zerolog.Logger) *AssetQuerySkill {
	return &AssetQuerySkill{db: db, logger: logger.With().Str("skill", "assets").Logger()}
}

func (s *AssetQuerySkill) Name() string { return "query_asset" }
func (s *AssetQuerySkill) Description() string {
	return "Query the asset database for information about a host or IP. Returns known incidents, events, and context associated with that asset."
}

func (s *AssetQuerySkill) ParametersSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"ip": map[string]interface{}{
				"type":        "string",
				"description": "IP address to query",
			},
			"hostname": map[string]interface{}{
				"type":        "string",
				"description": "Hostname to query",
			},
		},
		"required": []string{},
	}
}

func (s *AssetQuerySkill) Validate(params map[string]interface{}) error {
	ip, _ := GetStringParam(params, "ip")
	host, _ := GetStringParam(params, "hostname")
	if ip == "" && host == "" {
		return fmt.Errorf("at least one of 'ip' or 'hostname' is required")
	}
	if ip != "" {
		return ValidateIP(ip)
	}
	return nil
}

func (s *AssetQuerySkill) Execute(ctx context.Context, params map[string]interface{}) (*types.ToolResult, error) {
	ip, _ := GetStringParam(params, "ip")

	// Look up past incidents for this IP.
	var incidents []map[string]interface{}
	if ip != "" {
		rows, err := s.db.QueryContext(ctx,
			"SELECT id, title, severity, status, created_at FROM incidents WHERE source_ip = ? ORDER BY created_at DESC LIMIT 10", ip)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var id, title, status, createdAt string
				var sev int
				if rows.Scan(&id, &title, &sev, &status, &createdAt) == nil {
					incidents = append(incidents, map[string]interface{}{
						"id": id, "title": title, "severity": sev, "status": status, "created_at": createdAt,
					})
				}
			}
		}
	}

	// Look up recent events from this IP.
	var recentEvents int
	if ip != "" {
		s.db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM events WHERE fields LIKE ?", "%"+ip+"%").Scan(&recentEvents)
	}

	// Look up agent memory facts.
	var knownFacts []string
	if ip != "" {
		rows, err := s.db.QueryContext(ctx,
			"SELECT fact FROM agent_memory WHERE fact LIKE ? ORDER BY confidence DESC LIMIT 5", "%"+ip+"%")
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var f string
				if rows.Scan(&f) == nil {
					knownFacts = append(knownFacts, f)
				}
			}
		}
	}

	data := map[string]interface{}{
		"ip":            ip,
		"incidents":     incidents,
		"recent_events": recentEvents,
		"known_facts":   knownFacts,
	}

	output, _ := json.MarshalIndent(data, "", "  ")
	summary := fmt.Sprintf("Asset %s: %d past incidents, %d recent events, %d known facts",
		ip, len(incidents), recentEvents, len(knownFacts))

	return &types.ToolResult{
		Success: true,
		Output:  summary + "\n" + string(output),
		Data:    data,
	}, nil
}
