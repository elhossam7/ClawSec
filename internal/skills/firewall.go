package skills

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/rs/zerolog"
	"github.com/sentinel-agent/sentinel/internal/types"
)

// FirewallSkill blocks/unblocks IP addresses using the system firewall.
type FirewallSkill struct {
	protectedCIDRs []string
	logger         zerolog.Logger
}

// NewFirewallSkill creates a firewall skill with protected CIDR ranges.
func NewFirewallSkill(protectedCIDRs []string, logger zerolog.Logger) *FirewallSkill {
	if len(protectedCIDRs) == 0 {
		protectedCIDRs = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"}
	}
	return &FirewallSkill{
		protectedCIDRs: protectedCIDRs,
		logger:         logger.With().Str("skill", "firewall").Logger(),
	}
}

func (f *FirewallSkill) Name() string { return "block_ip" }
func (f *FirewallSkill) Description() string {
	return "Block an IP address using the system firewall (iptables/Windows Firewall). Use when the agent needs to prevent malicious traffic from a specific IP."
}

func (f *FirewallSkill) ParametersSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"ip": map[string]interface{}{
				"type":        "string",
				"description": "IPv4 or IPv6 address to block",
			},
			"duration": map[string]interface{}{
				"type":        "integer",
				"description": "Block duration in seconds (0 = permanent, max 86400)",
			},
			"reason": map[string]interface{}{
				"type":        "string",
				"description": "Justification for blocking",
			},
		},
		"required": []string{"ip", "reason"},
	}
}

func (f *FirewallSkill) Validate(params map[string]interface{}) error {
	ip, err := GetStringParam(params, "ip")
	if err != nil {
		return err
	}
	if err := ValidateIP(ip); err != nil {
		return err
	}

	// Check protected ranges.
	for _, cidr := range f.protectedCIDRs {
		if IsIPInCIDR(ip, cidr) {
			return fmt.Errorf("cannot block IP %s — it is in protected range %s", ip, cidr)
		}
	}

	dur := GetIntParam(params, "duration", 0)
	if dur < 0 || dur > 86400 {
		return fmt.Errorf("duration must be between 0 and 86400 seconds")
	}

	return nil
}

func (f *FirewallSkill) Execute(ctx context.Context, params map[string]interface{}) (*types.ToolResult, error) {
	ip, _ := GetStringParam(params, "ip")
	reason, _ := GetStringParam(params, "reason")

	f.logger.Info().Str("ip", ip).Str("reason", reason).Msg("blocking IP")

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.CommandContext(ctx, "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
	case "windows":
		ruleName := fmt.Sprintf("Sentinel_Block_%s", strings.ReplaceAll(ip, ".", "_"))
		psCmd := fmt.Sprintf(`New-NetFirewallRule -DisplayName "%s" -Direction Inbound -RemoteAddress %s -Action Block`, ruleName, ip)
		cmd = exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", psCmd)
	default:
		return &types.ToolResult{Success: false, Error: "unsupported platform"}, nil
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return &types.ToolResult{
			Success: false,
			Output:  string(output),
			Error:   err.Error(),
		}, nil
	}

	return &types.ToolResult{
		Success: true,
		Output:  fmt.Sprintf("IP %s blocked successfully", ip),
		Data:    map[string]interface{}{"ip": ip, "reason": reason},
	}, nil
}
