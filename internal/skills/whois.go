package skills

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/sentinel-agent/sentinel/internal/types"
)

// WhoisSkill performs domain/IP ownership lookups.
type WhoisSkill struct {
	logger zerolog.Logger
}

// NewWhoisSkill creates a WHOIS lookup skill.
func NewWhoisSkill(logger zerolog.Logger) *WhoisSkill {
	return &WhoisSkill{
		logger: logger.With().Str("skill", "whois_lookup").Logger(),
	}
}

func (w *WhoisSkill) Name() string { return "whois_lookup" }
func (w *WhoisSkill) Description() string {
	return "Look up domain or IP ownership information via WHOIS. Returns registrar, registrant org, creation date, and CIDR block. Use when investigating suspicious domains or IPs."
}

func (w *WhoisSkill) ParametersSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"target": map[string]interface{}{
				"type":        "string",
				"description": "Domain name or IP address to look up",
			},
		},
		"required": []string{"target"},
	}
}

func (w *WhoisSkill) Validate(params map[string]interface{}) error {
	target, err := GetStringParam(params, "target")
	if err != nil {
		return err
	}
	if len(target) > 253 {
		return fmt.Errorf("target too long (max 253 characters)")
	}
	if strings.ContainsAny(target, ";|&$`\"'\\") {
		return fmt.Errorf("invalid characters in target")
	}
	return nil
}

func (w *WhoisSkill) Execute(ctx context.Context, params map[string]interface{}) (*types.ToolResult, error) {
	target, _ := GetStringParam(params, "target")

	w.logger.Info().Str("target", target).Msg("WHOIS lookup")

	// Determine WHOIS server.
	server := "whois.iana.org"
	if net.ParseIP(target) != nil {
		server = "whois.arin.net"
	} else if strings.HasSuffix(target, ".com") || strings.HasSuffix(target, ".net") {
		server = "whois.verisign-grs.com"
	} else if strings.HasSuffix(target, ".org") {
		server = "whois.pir.org"
	} else if strings.HasSuffix(target, ".io") {
		server = "whois.nic.io"
	}

	result, err := queryWhois(ctx, server, target)
	if err != nil {
		return &types.ToolResult{
			Success: false,
			Error:   fmt.Sprintf("WHOIS query failed: %v", err),
		}, nil
	}

	// Truncate very long results.
	if len(result) > 5000 {
		result = result[:5000] + "\n... (truncated)"
	}

	return &types.ToolResult{
		Success: true,
		Output:  fmt.Sprintf("WHOIS Results for %s (via %s)\n%s\n%s", target, server, strings.Repeat("-", 50), result),
		Data: map[string]interface{}{
			"target": target,
			"server": server,
		},
	}, nil
}

// queryWhois performs a raw WHOIS query over TCP.
func queryWhois(ctx context.Context, server, query string) (string, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", server+":43")
	if err != nil {
		return "", fmt.Errorf("connecting to %s: %w", server, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(15 * time.Second))

	_, err = fmt.Fprintf(conn, "%s\r\n", query)
	if err != nil {
		return "", fmt.Errorf("sending query: %w", err)
	}

	buf := make([]byte, 32768)
	var response strings.Builder
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			response.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}

	return response.String(), nil
}
