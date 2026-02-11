package skills

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/rs/zerolog"
	"github.com/sentinel-agent/sentinel/internal/types"
)

// NetstatSkill lists active network connections.
type NetstatSkill struct {
	logger zerolog.Logger
}

// NewNetstatSkill creates a network connections skill.
func NewNetstatSkill(logger zerolog.Logger) *NetstatSkill {
	return &NetstatSkill{
		logger: logger.With().Str("skill", "network_connections").Logger(),
	}
}

func (n *NetstatSkill) Name() string { return "network_connections" }
func (n *NetstatSkill) Description() string {
	return "List active network connections (like netstat/ss). Can filter by state, port, or process. Use when investigating suspicious network activity or lateral movement."
}

func (n *NetstatSkill) ParametersSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"state": map[string]interface{}{
				"type":        "string",
				"description": "Filter by connection state: ESTABLISHED, LISTEN, TIME_WAIT, CLOSE_WAIT, SYN_SENT, all (default: all)",
			},
			"port": map[string]interface{}{
				"type":        "integer",
				"description": "Filter by port number (matches local or remote port)",
			},
			"protocol": map[string]interface{}{
				"type":        "string",
				"description": "Protocol filter: tcp, udp, all (default: tcp)",
				"enum":        []string{"tcp", "udp", "all"},
			},
		},
	}
}

func (n *NetstatSkill) Validate(params map[string]interface{}) error {
	return nil // All parameters are optional.
}

func (n *NetstatSkill) Execute(ctx context.Context, params map[string]interface{}) (*types.ToolResult, error) {
	state := "all"
	if s, err := GetStringParam(params, "state"); err == nil && s != "" {
		state = strings.ToUpper(s)
	}
	port := GetIntParam(params, "port", 0)
	proto := "tcp"
	if p, err := GetStringParam(params, "protocol"); err == nil && p != "" {
		proto = strings.ToLower(p)
	}

	n.logger.Info().Str("state", state).Int("port", port).Str("proto", proto).Msg("listing connections")

	var output string
	var err error

	switch runtime.GOOS {
	case "linux":
		output, err = n.executeLinux(ctx, state, port, proto)
	case "windows":
		output, err = n.executeWindows(ctx, state, port, proto)
	default:
		return &types.ToolResult{Success: false, Error: fmt.Sprintf("unsupported platform: %s", runtime.GOOS)}, nil
	}

	if err != nil {
		return &types.ToolResult{Success: false, Error: err.Error()}, nil
	}

	return &types.ToolResult{
		Success: true,
		Output:  output,
		Data: map[string]interface{}{
			"state":    state,
			"port":     port,
			"protocol": proto,
		},
	}, nil
}

func (n *NetstatSkill) executeLinux(ctx context.Context, state string, port int, proto string) (string, error) {
	// Parse /proc/net/tcp for TCP connections.
	var output strings.Builder
	output.WriteString("Active Network Connections\n")
	output.WriteString(fmt.Sprintf("%-6s %-25s %-25s %-15s\n", "Proto", "Local Address", "Remote Address", "State"))
	output.WriteString(strings.Repeat("-", 75) + "\n")

	files := []struct {
		path  string
		proto string
	}{
		{"/proc/net/tcp", "tcp"},
		{"/proc/net/tcp6", "tcp6"},
		{"/proc/net/udp", "udp"},
		{"/proc/net/udp6", "udp6"},
	}

	count := 0
	for _, f := range files {
		if proto != "all" && !strings.HasPrefix(f.proto, proto) {
			continue
		}

		entries, err := parseProcNet(f.path)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if state != "all" && state != entry.state {
				continue
			}
			if port != 0 && entry.localPort != port && entry.remotePort != port {
				continue
			}
			output.WriteString(fmt.Sprintf("%-6s %-25s %-25s %-15s\n",
				f.proto, entry.localAddr, entry.remoteAddr, entry.state))
			count++
			if count >= 200 {
				output.WriteString("... (truncated at 200 entries)\n")
				return output.String(), nil
			}
		}
	}

	output.WriteString(fmt.Sprintf("\nTotal: %d connections\n", count))
	return output.String(), nil
}

type netEntry struct {
	localAddr  string
	remoteAddr string
	localPort  int
	remotePort int
	state      string
}

// parseProcNet reads /proc/net/tcp or /proc/net/udp.
func parseProcNet(path string) ([]netEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []netEntry
	scanner := bufio.NewScanner(f)
	scanner.Scan() // Skip header line.

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}

		localAddr, localPort := parseHexAddr(fields[1])
		remoteAddr, remotePort := parseHexAddr(fields[2])
		state := tcpStateMap(fields[3])

		entries = append(entries, netEntry{
			localAddr:  fmt.Sprintf("%s:%d", localAddr, localPort),
			remoteAddr: fmt.Sprintf("%s:%d", remoteAddr, remotePort),
			localPort:  localPort,
			remotePort: remotePort,
			state:      state,
		})
	}

	return entries, nil
}

func parseHexAddr(s string) (string, int) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return s, 0
	}

	var port int
	fmt.Sscanf(parts[1], "%X", &port)

	hex := parts[0]
	if len(hex) == 8 {
		// IPv4: little-endian hex.
		var a, b, c, d uint32
		fmt.Sscanf(hex, "%02X%02X%02X%02X", &d, &c, &b, &a)
		return fmt.Sprintf("%d.%d.%d.%d", a, b, c, d), port
	}

	return hex, port
}

func tcpStateMap(hex string) string {
	states := map[string]string{
		"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
		"04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
		"07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
		"0A": "LISTEN", "0B": "CLOSING",
	}
	if s, ok := states[strings.ToUpper(hex)]; ok {
		return s
	}
	return hex
}

func (n *NetstatSkill) executeWindows(ctx context.Context, state string, port int, proto string) (string, error) {
	psCmd := `Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State | Format-Table -AutoSize`
	if proto == "udp" {
		psCmd = `Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort | Format-Table -AutoSize`
	}

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", psCmd)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("PowerShell command failed: %w", err)
	}

	output := string(out)

	// Apply port/state filters.
	if port != 0 || (state != "all" && state != "") {
		var filtered strings.Builder
		lines := strings.Split(output, "\n")
		for i, line := range lines {
			if i < 3 { // Keep header lines.
				filtered.WriteString(line + "\n")
				continue
			}
			if port != 0 && !strings.Contains(line, fmt.Sprintf("%d", port)) {
				continue
			}
			if state != "all" && state != "" && !strings.Contains(strings.ToUpper(line), state) {
				continue
			}
			filtered.WriteString(line + "\n")
		}
		output = filtered.String()
	}

	return output, nil
}
