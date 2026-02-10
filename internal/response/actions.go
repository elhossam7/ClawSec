package response

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/rs/zerolog"
)

// PlatformExecutor implements Executor for the current platform.
type PlatformExecutor struct {
	logger zerolog.Logger
}

// NewPlatformExecutor creates the platform-specific action executor.
func NewPlatformExecutor(logger zerolog.Logger) *PlatformExecutor {
	return &PlatformExecutor{
		logger: logger.With().Str("component", "executor").Logger(),
	}
}

// BlockIP blocks an IP address using the platform firewall.
func (pe *PlatformExecutor) BlockIP(ctx context.Context, ip string) (string, error) {
	if ip == "" {
		return "", fmt.Errorf("empty IP address")
	}

	// Validate IP format (basic check).
	if strings.ContainsAny(ip, ";|&$`") {
		return "", fmt.Errorf("invalid characters in IP: %s", ip)
	}

	switch runtime.GOOS {
	case "linux":
		return pe.blockIPLinux(ctx, ip)
	case "windows":
		return pe.blockIPWindows(ctx, ip)
	default:
		return "", fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// UnblockIP removes the IP block.
func (pe *PlatformExecutor) UnblockIP(ctx context.Context, ip string) error {
	switch runtime.GOOS {
	case "linux":
		return pe.unblockIPLinux(ctx, ip)
	case "windows":
		return pe.unblockIPWindows(ctx, ip)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// DisableUser locks a user account.
func (pe *PlatformExecutor) DisableUser(ctx context.Context, username string) (string, error) {
	if username == "" {
		return "", fmt.Errorf("empty username")
	}
	if strings.ContainsAny(username, ";|&$`") {
		return "", fmt.Errorf("invalid characters in username: %s", username)
	}

	switch runtime.GOOS {
	case "linux":
		return pe.disableUserLinux(ctx, username)
	case "windows":
		return pe.disableUserWindows(ctx, username)
	default:
		return "", fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// EnableUser unlocks a user account.
func (pe *PlatformExecutor) EnableUser(ctx context.Context, username string) error {
	switch runtime.GOOS {
	case "linux":
		return pe.enableUserLinux(ctx, username)
	case "windows":
		return pe.enableUserWindows(ctx, username)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// KillProcess terminates a process by PID.
func (pe *PlatformExecutor) KillProcess(ctx context.Context, pid string) error {
	if pid == "" {
		return fmt.Errorf("empty PID")
	}

	switch runtime.GOOS {
	case "linux":
		cmd := exec.CommandContext(ctx, "kill", "-9", pid)
		return cmd.Run()
	case "windows":
		cmd := exec.CommandContext(ctx, "taskkill", "/F", "/PID", pid)
		return cmd.Run()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// IsolateContainer disconnects a container from all networks.
func (pe *PlatformExecutor) IsolateContainer(ctx context.Context, containerID string) (string, error) {
	if containerID == "" {
		return "", fmt.Errorf("empty container ID")
	}

	// Get current networks.
	cmd := exec.CommandContext(ctx, "docker", "inspect", "-f",
		"{{range $key, $val := .NetworkSettings.Networks}}{{$key}} {{end}}", containerID)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("inspecting container: %w", err)
	}

	networks := strings.Fields(strings.TrimSpace(string(output)))

	// Disconnect from all networks.
	for _, net := range networks {
		cmd := exec.CommandContext(ctx, "docker", "network", "disconnect", "-f", net, containerID)
		if err := cmd.Run(); err != nil {
			pe.logger.Warn().Err(err).Str("network", net).Msg("failed to disconnect network")
		}
	}

	// Build rollback: reconnect to all networks.
	var rollbackParts []string
	for _, net := range networks {
		rollbackParts = append(rollbackParts, fmt.Sprintf("docker network connect %s %s", net, containerID))
	}

	return strings.Join(rollbackParts, " && "), nil
}

// --- Linux implementations ---

func (pe *PlatformExecutor) blockIPLinux(ctx context.Context, ip string) (string, error) {
	// Try iptables first, fall back to ufw.
	cmd := exec.CommandContext(ctx, "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
	if err := cmd.Run(); err != nil {
		// Try ufw.
		cmd = exec.CommandContext(ctx, "ufw", "deny", "from", ip)
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("blocking IP %s: %w", ip, err)
		}
		return fmt.Sprintf("ufw delete deny from %s", ip), nil
	}
	return fmt.Sprintf("iptables -D INPUT -s %s -j DROP", ip), nil
}

func (pe *PlatformExecutor) unblockIPLinux(ctx context.Context, ip string) error {
	// Try iptables first.
	cmd := exec.CommandContext(ctx, "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
	if err := cmd.Run(); err != nil {
		// Try ufw.
		cmd = exec.CommandContext(ctx, "ufw", "delete", "deny", "from", ip)
		return cmd.Run()
	}
	return nil
}

func (pe *PlatformExecutor) disableUserLinux(ctx context.Context, username string) (string, error) {
	cmd := exec.CommandContext(ctx, "usermod", "-L", username)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("disabling user %s: %w", username, err)
	}
	return fmt.Sprintf("usermod -U %s", username), nil
}

func (pe *PlatformExecutor) enableUserLinux(ctx context.Context, username string) error {
	cmd := exec.CommandContext(ctx, "usermod", "-U", username)
	return cmd.Run()
}

// --- Windows implementations ---

func (pe *PlatformExecutor) blockIPWindows(ctx context.Context, ip string) (string, error) {
	ruleName := fmt.Sprintf("Sentinel_Block_%s", strings.ReplaceAll(ip, ".", "_"))
	psCmd := fmt.Sprintf(
		`New-NetFirewallRule -DisplayName "%s" -Direction Inbound -RemoteAddress %s -Action Block`,
		ruleName, ip,
	)
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", psCmd)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("blocking IP %s: %w", ip, err)
	}
	return fmt.Sprintf(`Remove-NetFirewallRule -DisplayName "%s"`, ruleName), nil
}

func (pe *PlatformExecutor) unblockIPWindows(ctx context.Context, ip string) error {
	ruleName := fmt.Sprintf("Sentinel_Block_%s", strings.ReplaceAll(ip, ".", "_"))
	psCmd := fmt.Sprintf(`Remove-NetFirewallRule -DisplayName "%s"`, ruleName)
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", psCmd)
	return cmd.Run()
}

func (pe *PlatformExecutor) disableUserWindows(ctx context.Context, username string) (string, error) {
	psCmd := fmt.Sprintf(`Disable-LocalUser -Name "%s"`, username)
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", psCmd)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("disabling user %s: %w", username, err)
	}
	return fmt.Sprintf(`Enable-LocalUser -Name "%s"`, username), nil
}

func (pe *PlatformExecutor) enableUserWindows(ctx context.Context, username string) error {
	psCmd := fmt.Sprintf(`Enable-LocalUser -Name "%s"`, username)
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", psCmd)
	return cmd.Run()
}
