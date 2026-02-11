package skills

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/rs/zerolog"
	"github.com/sentinel-agent/sentinel/internal/types"
)

// DNSLookupSkill resolves hostnames, reverse DNS, and specific record types.
type DNSLookupSkill struct {
	logger zerolog.Logger
}

// NewDNSLookupSkill creates a DNS lookup skill.
func NewDNSLookupSkill(logger zerolog.Logger) *DNSLookupSkill {
	return &DNSLookupSkill{
		logger: logger.With().Str("skill", "dns_lookup").Logger(),
	}
}

func (d *DNSLookupSkill) Name() string { return "dns_lookup" }
func (d *DNSLookupSkill) Description() string {
	return "Resolve hostnames, perform reverse DNS lookups, and query specific record types (A, AAAA, MX, TXT, PTR, NS, CNAME). Use when investigating suspicious domains or IP addresses."
}

func (d *DNSLookupSkill) ParametersSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"target": map[string]interface{}{
				"type":        "string",
				"description": "Hostname or IP address to look up",
			},
			"record_type": map[string]interface{}{
				"type":        "string",
				"description": "DNS record type: A, AAAA, MX, TXT, PTR, NS, CNAME (default: A)",
				"enum":        []string{"A", "AAAA", "MX", "TXT", "PTR", "NS", "CNAME"},
			},
		},
		"required": []string{"target"},
	}
}

func (d *DNSLookupSkill) Validate(params map[string]interface{}) error {
	target, err := GetStringParam(params, "target")
	if err != nil {
		return err
	}
	if len(target) > 253 {
		return fmt.Errorf("target too long (max 253 characters)")
	}
	// Block injection characters.
	if strings.ContainsAny(target, ";|&$`\"'\\") {
		return fmt.Errorf("invalid characters in target")
	}
	return nil
}

func (d *DNSLookupSkill) Execute(ctx context.Context, params map[string]interface{}) (*types.ToolResult, error) {
	target, _ := GetStringParam(params, "target")
	recordType := "A"
	if rt, err := GetStringParam(params, "record_type"); err == nil && rt != "" {
		recordType = strings.ToUpper(rt)
	}

	d.logger.Info().Str("target", target).Str("type", recordType).Msg("DNS lookup")

	var output strings.Builder
	output.WriteString(fmt.Sprintf("DNS Lookup: %s (type: %s)\n", target, recordType))
	output.WriteString(strings.Repeat("-", 50) + "\n")

	resolver := net.DefaultResolver

	switch recordType {
	case "A":
		ips, err := resolver.LookupIPAddr(ctx, target)
		if err != nil {
			return &types.ToolResult{Success: false, Error: fmt.Sprintf("A lookup failed: %v", err)}, nil
		}
		for _, ip := range ips {
			if ip.IP.To4() != nil {
				output.WriteString(fmt.Sprintf("A: %s\n", ip.IP.String()))
			}
		}

	case "AAAA":
		ips, err := resolver.LookupIPAddr(ctx, target)
		if err != nil {
			return &types.ToolResult{Success: false, Error: fmt.Sprintf("AAAA lookup failed: %v", err)}, nil
		}
		for _, ip := range ips {
			if ip.IP.To4() == nil {
				output.WriteString(fmt.Sprintf("AAAA: %s\n", ip.IP.String()))
			}
		}

	case "MX":
		mxs, err := resolver.LookupMX(ctx, target)
		if err != nil {
			return &types.ToolResult{Success: false, Error: fmt.Sprintf("MX lookup failed: %v", err)}, nil
		}
		for _, mx := range mxs {
			output.WriteString(fmt.Sprintf("MX: %s (priority: %d)\n", mx.Host, mx.Pref))
		}

	case "TXT":
		txts, err := resolver.LookupTXT(ctx, target)
		if err != nil {
			return &types.ToolResult{Success: false, Error: fmt.Sprintf("TXT lookup failed: %v", err)}, nil
		}
		for _, txt := range txts {
			output.WriteString(fmt.Sprintf("TXT: %s\n", txt))
		}

	case "PTR":
		names, err := resolver.LookupAddr(ctx, target)
		if err != nil {
			return &types.ToolResult{Success: false, Error: fmt.Sprintf("PTR lookup failed: %v", err)}, nil
		}
		for _, name := range names {
			output.WriteString(fmt.Sprintf("PTR: %s\n", name))
		}

	case "NS":
		nss, err := resolver.LookupNS(ctx, target)
		if err != nil {
			return &types.ToolResult{Success: false, Error: fmt.Sprintf("NS lookup failed: %v", err)}, nil
		}
		for _, ns := range nss {
			output.WriteString(fmt.Sprintf("NS: %s\n", ns.Host))
		}

	case "CNAME":
		cname, err := resolver.LookupCNAME(ctx, target)
		if err != nil {
			return &types.ToolResult{Success: false, Error: fmt.Sprintf("CNAME lookup failed: %v", err)}, nil
		}
		output.WriteString(fmt.Sprintf("CNAME: %s\n", cname))

	default:
		return &types.ToolResult{Success: false, Error: fmt.Sprintf("unsupported record type: %s", recordType)}, nil
	}

	return &types.ToolResult{
		Success: true,
		Output:  output.String(),
		Data: map[string]interface{}{
			"target":      target,
			"record_type": recordType,
		},
	}, nil
}
