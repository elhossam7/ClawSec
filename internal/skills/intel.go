package skills

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog"
	"github.com/sentinel-agent/sentinel/internal/types"
)

// IPReputationSkill queries external threat intelligence for IP reputation.
type IPReputationSkill struct {
	abuseIPDBKey string
	httpClient   *http.Client
	logger       zerolog.Logger
}

// NewIPReputationSkill creates a threat-intel skill for IP reputation checks.
func NewIPReputationSkill(abuseIPDBKey string, logger zerolog.Logger) *IPReputationSkill {
	return &IPReputationSkill{
		abuseIPDBKey: abuseIPDBKey,
		httpClient:   &http.Client{Timeout: 15 * time.Second},
		logger:       logger.With().Str("skill", "ip_reputation").Logger(),
	}
}

func (s *IPReputationSkill) Name() string { return "check_ip_reputation" }
func (s *IPReputationSkill) Description() string {
	return "Check an IP address against threat intelligence databases (AbuseIPDB). Returns abuse confidence score, reports, and country."
}

func (s *IPReputationSkill) ParametersSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"ip": map[string]interface{}{
				"type":        "string",
				"description": "IP address to check reputation for",
			},
		},
		"required": []string{"ip"},
	}
}

func (s *IPReputationSkill) Validate(params map[string]interface{}) error {
	ip, err := GetStringParam(params, "ip")
	if err != nil {
		return err
	}
	return ValidateIP(ip)
}

func (s *IPReputationSkill) Execute(ctx context.Context, params map[string]interface{}) (*types.ToolResult, error) {
	ip, _ := GetStringParam(params, "ip")

	if s.abuseIPDBKey == "" {
		return &types.ToolResult{
			Success: true,
			Output:  fmt.Sprintf("Threat intel API key not configured. Cannot check reputation for %s. Treat with caution.", ip),
			Data:    map[string]interface{}{"ip": ip, "status": "api_key_missing"},
		}, nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.abuseipdb.com/api/v2/check", nil)
	if err != nil {
		return &types.ToolResult{Success: false, Error: err.Error()}, nil
	}

	q := req.URL.Query()
	q.Set("ipAddress", ip)
	q.Set("maxAgeInDays", "90")
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Key", s.abuseIPDBKey)
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return &types.ToolResult{Success: false, Error: fmt.Sprintf("AbuseIPDB API error: %v", err)}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return &types.ToolResult{Success: false, Error: fmt.Sprintf("AbuseIPDB returned %d: %s", resp.StatusCode, string(body))}, nil
	}

	var result struct {
		Data struct {
			IPAddress            string `json:"ipAddress"`
			IsPublic             bool   `json:"isPublic"`
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			CountryCode          string `json:"countryCode"`
			ISP                  string `json:"isp"`
			Domain               string `json:"domain"`
			TotalReports         int    `json:"totalReports"`
			LastReportedAt       string `json:"lastReportedAt"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return &types.ToolResult{Success: false, Error: fmt.Sprintf("parsing response: %v", err)}, nil
	}

	d := result.Data
	var summary string
	if d.AbuseConfidenceScore > 75 {
		summary = fmt.Sprintf("HIGH RISK: IP %s has abuse confidence %d%%, %d reports, country: %s, ISP: %s",
			d.IPAddress, d.AbuseConfidenceScore, d.TotalReports, d.CountryCode, d.ISP)
	} else if d.AbuseConfidenceScore > 25 {
		summary = fmt.Sprintf("MEDIUM RISK: IP %s has abuse confidence %d%%, %d reports, country: %s",
			d.IPAddress, d.AbuseConfidenceScore, d.TotalReports, d.CountryCode)
	} else {
		summary = fmt.Sprintf("LOW RISK: IP %s has abuse confidence %d%%, %d reports, country: %s",
			d.IPAddress, d.AbuseConfidenceScore, d.TotalReports, d.CountryCode)
	}

	return &types.ToolResult{
		Success: true,
		Output:  summary,
		Data: map[string]interface{}{
			"ip":                     d.IPAddress,
			"abuse_confidence_score": d.AbuseConfidenceScore,
			"total_reports":          d.TotalReports,
			"country":                d.CountryCode,
			"isp":                    d.ISP,
			"domain":                 d.Domain,
			"last_reported":          d.LastReportedAt,
		},
	}, nil
}

// HashReputationSkill checks file hashes against VirusTotal.
type HashReputationSkill struct {
	vtKey      string
	httpClient *http.Client
	logger     zerolog.Logger
}

func NewHashReputationSkill(vtKey string, logger zerolog.Logger) *HashReputationSkill {
	return &HashReputationSkill{
		vtKey:      vtKey,
		httpClient: &http.Client{Timeout: 15 * time.Second},
		logger:     logger.With().Str("skill", "hash_reputation").Logger(),
	}
}

func (s *HashReputationSkill) Name() string { return "check_file_hash" }
func (s *HashReputationSkill) Description() string {
	return "Check a file hash (MD5/SHA1/SHA256) against VirusTotal for known malware detections."
}

func (s *HashReputationSkill) ParametersSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"hash": map[string]interface{}{
				"type":        "string",
				"description": "File hash (MD5, SHA1, or SHA256)",
			},
		},
		"required": []string{"hash"},
	}
}

func (s *HashReputationSkill) Validate(params map[string]interface{}) error {
	hash, err := GetStringParam(params, "hash")
	if err != nil {
		return err
	}
	// Basic length checks for known hash formats.
	switch len(hash) {
	case 32, 40, 64: // MD5, SHA1, SHA256
		return nil
	default:
		return fmt.Errorf("hash length %d does not match MD5(32), SHA1(40), or SHA256(64)", len(hash))
	}
}

func (s *HashReputationSkill) Execute(ctx context.Context, params map[string]interface{}) (*types.ToolResult, error) {
	hash, _ := GetStringParam(params, "hash")

	if s.vtKey == "" {
		return &types.ToolResult{
			Success: true,
			Output:  fmt.Sprintf("VirusTotal API key not configured. Cannot check hash %s.", hash),
			Data:    map[string]interface{}{"hash": hash, "status": "api_key_missing"},
		}, nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", hash), nil)
	if err != nil {
		return &types.ToolResult{Success: false, Error: err.Error()}, nil
	}
	req.Header.Set("x-apikey", s.vtKey)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return &types.ToolResult{Success: false, Error: fmt.Sprintf("VirusTotal API: %v", err)}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return &types.ToolResult{
			Success: true,
			Output:  fmt.Sprintf("Hash %s not found in VirusTotal database", hash),
			Data:    map[string]interface{}{"hash": hash, "found": false},
		}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return &types.ToolResult{Success: false, Error: fmt.Sprintf("VT returned %d: %s", resp.StatusCode, string(body))}, nil
	}

	var vt struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Undetected int `json:"undetected"`
				} `json:"last_analysis_stats"`
				MeaningfulName string `json:"meaningful_name"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &vt); err != nil {
		return &types.ToolResult{Success: false, Error: fmt.Sprintf("parsing VT response: %v", err)}, nil
	}

	stats := vt.Data.Attributes.LastAnalysisStats
	summary := fmt.Sprintf("Hash %s: %d engines detect as malicious, %d suspicious, %d clean. Name: %s",
		hash, stats.Malicious, stats.Suspicious, stats.Undetected, vt.Data.Attributes.MeaningfulName)

	return &types.ToolResult{
		Success: true,
		Output:  summary,
		Data: map[string]interface{}{
			"hash":       hash,
			"found":      true,
			"malicious":  stats.Malicious,
			"suspicious": stats.Suspicious,
			"undetected": stats.Undetected,
			"name":       vt.Data.Attributes.MeaningfulName,
		},
	}, nil
}
