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

// ServiceInfoSkill lists running services or queries a specific service status.
type ServiceInfoSkill struct {
	logger zerolog.Logger
}

// NewServiceInfoSkill creates a service info skill.
func NewServiceInfoSkill(logger zerolog.Logger) *ServiceInfoSkill {
	return &ServiceInfoSkill{
		logger: logger.With().Str("skill", "service_info").Logger(),
	}
}

func (s *ServiceInfoSkill) Name() string { return "service_info" }
func (s *ServiceInfoSkill) Description() string {
	return "List running services or query a specific service status. Use when investigating unauthorized services, persistence mechanisms, or service-based attacks."
}

func (s *ServiceInfoSkill) ParametersSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"service_name": map[string]interface{}{
				"type":        "string",
				"description": "Name of a specific service to query (optional; omit to list all services)",
			},
			"status_filter": map[string]interface{}{
				"type":        "string",
				"description": "Filter by status: running, stopped, or all (default: all)",
				"enum":        []string{"running", "stopped", "all"},
			},
		},
	}
}

func (s *ServiceInfoSkill) Validate(params map[string]interface{}) error {
	// Validate service_name if provided.
	if name, err := GetStringParam(params, "service_name"); err == nil && name != "" {
		if strings.ContainsAny(name, ";|&$`\"'\\") {
			return fmt.Errorf("invalid characters in service_name: %s", name)
		}
	}

	// Validate status_filter if provided.
	if sf, err := GetStringParam(params, "status_filter"); err == nil && sf != "" {
		sf = strings.ToLower(sf)
		if sf != "running" && sf != "stopped" && sf != "all" {
			return fmt.Errorf("status_filter must be 'running', 'stopped', or 'all', got: %s", sf)
		}
	}

	return nil
}

func (s *ServiceInfoSkill) Execute(ctx context.Context, params map[string]interface{}) (*types.ToolResult, error) {
	serviceName := ""
	if name, err := GetStringParam(params, "service_name"); err == nil {
		serviceName = strings.TrimSpace(name)
	}
	statusFilter := "all"
	if sf, err := GetStringParam(params, "status_filter"); err == nil && sf != "" {
		statusFilter = strings.ToLower(sf)
	}

	s.logger.Info().
		Str("service_name", serviceName).
		Str("status_filter", statusFilter).
		Msg("querying services")

	var output string
	var err error

	switch runtime.GOOS {
	case "linux":
		output, err = s.executeLinux(ctx, serviceName, statusFilter)
	case "windows":
		output, err = s.executeWindows(ctx, serviceName, statusFilter)
	default:
		return &types.ToolResult{Success: false, Error: fmt.Sprintf("unsupported platform: %s", runtime.GOOS)}, nil
	}

	if err != nil {
		return &types.ToolResult{Success: false, Error: err.Error()}, nil
	}

	data := map[string]interface{}{
		"status_filter": statusFilter,
	}
	if serviceName != "" {
		data["service_name"] = serviceName
	}

	return &types.ToolResult{
		Success: true,
		Output:  output,
		Data:    data,
	}, nil
}

// executeLinux uses systemctl to list or query services.
func (s *ServiceInfoSkill) executeLinux(ctx context.Context, serviceName, statusFilter string) (string, error) {
	// Query a specific service.
	if serviceName != "" {
		return s.queryLinuxService(ctx, serviceName)
	}

	// List all services.
	cmd := exec.CommandContext(ctx, "systemctl", "list-units", "--type=service", "--no-pager", "--all", "--plain")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("systemctl command failed: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")

	var result strings.Builder
	result.WriteString("System Services\n")
	result.WriteString(fmt.Sprintf("%-40s %-15s %-15s %-12s\n", "Name", "Display Name", "Status", "Start Type"))
	result.WriteString(strings.Repeat("-", 85) + "\n")

	count := 0
	for _, line := range lines {
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// systemctl output: UNIT LOAD ACTIVE SUB [DESCRIPTION...]
		unit := fields[0]
		if !strings.HasSuffix(unit, ".service") {
			continue
		}

		name := strings.TrimSuffix(unit, ".service")
		activeState := strings.ToLower(fields[2]) // active/inactive
		subState := strings.ToLower(fields[3])    // running/dead/exited/etc.

		// Map to our status terms.
		status := "stopped"
		if activeState == "active" && subState == "running" {
			status = "running"
		} else if activeState == "active" {
			status = subState // exited, waiting, etc.
		}

		// Apply filter.
		if statusFilter == "running" && status != "running" {
			continue
		}
		if statusFilter == "stopped" && status != "stopped" {
			continue
		}

		// Build display name from remaining fields.
		displayName := name
		if len(fields) > 4 {
			displayName = strings.Join(fields[4:], " ")
		}
		if len(displayName) > 15 {
			displayName = displayName[:12] + "..."
		}

		result.WriteString(fmt.Sprintf("%-40s %-15s %-15s %-12s\n", name, displayName, status, "-"))

		count++
		if count >= 200 {
			result.WriteString("... (truncated at 200 entries)\n")
			break
		}
	}

	result.WriteString(fmt.Sprintf("\nTotal: %d services\n", count))
	return result.String(), nil
}

// queryLinuxService gets detailed info about a specific service using systemctl show.
func (s *ServiceInfoSkill) queryLinuxService(ctx context.Context, serviceName string) (string, error) {
	unit := serviceName
	if !strings.HasSuffix(unit, ".service") {
		unit = serviceName + ".service"
	}

	cmd := exec.CommandContext(ctx, "systemctl", "show", unit,
		"--property=Id,Description,ActiveState,SubState,LoadState,UnitFileState,MainPID,ExecMainStartTimestamp,FragmentPath")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("systemctl show failed: %w", err)
	}

	// Parse key=value output from systemctl show.
	props := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			props[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	if props["LoadState"] == "not-found" {
		return "", fmt.Errorf("service %q not found", serviceName)
	}

	// Determine status.
	status := "stopped"
	if props["ActiveState"] == "active" && props["SubState"] == "running" {
		status = "running"
	} else if props["ActiveState"] == "active" {
		status = props["SubState"]
	}

	// Map UnitFileState to start type.
	startType := "unknown"
	switch props["UnitFileState"] {
	case "enabled":
		startType = "auto"
	case "disabled":
		startType = "disabled"
	case "static":
		startType = "manual"
	case "masked":
		startType = "disabled"
	default:
		startType = props["UnitFileState"]
	}

	var result strings.Builder
	result.WriteString(fmt.Sprintf("Service Details: %s\n", serviceName))
	result.WriteString(strings.Repeat("=", 50) + "\n")
	result.WriteString(fmt.Sprintf("%-20s %s\n", "Name:", serviceName))
	result.WriteString(fmt.Sprintf("%-20s %s\n", "Display Name:", props["Description"]))
	result.WriteString(fmt.Sprintf("%-20s %s\n", "Status:", status))
	result.WriteString(fmt.Sprintf("%-20s %s (%s)\n", "Active State:", props["ActiveState"], props["SubState"]))
	result.WriteString(fmt.Sprintf("%-20s %s\n", "Start Type:", startType))
	result.WriteString(fmt.Sprintf("%-20s %s\n", "Main PID:", props["MainPID"]))
	result.WriteString(fmt.Sprintf("%-20s %s\n", "Started At:", props["ExecMainStartTimestamp"]))
	result.WriteString(fmt.Sprintf("%-20s %s\n", "Unit File:", props["FragmentPath"]))

	return result.String(), nil
}

// executeWindows uses PowerShell Get-Service to list or query services.
func (s *ServiceInfoSkill) executeWindows(ctx context.Context, serviceName, statusFilter string) (string, error) {
	var psCmd string

	if serviceName != "" {
		// Query a specific service.
		psCmd = fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
try {
    $svc = Get-Service -Name '%s'
} catch {
    Write-Output "ERROR: Service '%s' not found"
    exit 1
}

$startType = $svc.StartType
Write-Output "Service Details: $($svc.ServiceName)"
Write-Output ('=' * 50)
Write-Output "Name:           $($svc.ServiceName)"
Write-Output "Display Name:   $($svc.DisplayName)"
Write-Output "Status:         $($svc.Status)"
Write-Output "Start Type:     $startType"

try {
    $wmiSvc = Get-WmiObject Win32_Service -Filter "Name='$($svc.ServiceName)'" -ErrorAction SilentlyContinue
    if ($wmiSvc) {
        Write-Output "PID:            $($wmiSvc.ProcessId)"
        Write-Output "Path:           $($wmiSvc.PathName)"
        Write-Output "Start Name:     $($wmiSvc.StartName)"
        Write-Output "Description:    $($wmiSvc.Description)"
    }
} catch {}
`, serviceName, serviceName)
	} else {
		// List all services with optional filter.
		filterClause := ""
		switch statusFilter {
		case "running":
			filterClause = " | Where-Object { $_.Status -eq 'Running' }"
		case "stopped":
			filterClause = " | Where-Object { $_.Status -eq 'Stopped' }"
		}

		psCmd = fmt.Sprintf(`
$services = Get-Service%s | Select-Object ServiceName, DisplayName, Status, StartType | Sort-Object ServiceName

Write-Output "System Services"
Write-Output ("{0,-40} {1,-30} {2,-12} {3,-12}" -f "Name", "Display Name", "Status", "Start Type")
Write-Output ('-' * 95)

$count = 0
foreach ($svc in $services) {
    $displayName = $svc.DisplayName
    if ($displayName.Length -gt 28) { $displayName = $displayName.Substring(0, 25) + "..." }
    Write-Output ("{0,-40} {1,-30} {2,-12} {3,-12}" -f $svc.ServiceName, $displayName, $svc.Status, $svc.StartType)
    $count++
    if ($count -ge 200) {
        Write-Output "... (truncated at 200 entries)"
        break
    }
}
Write-Output ""
Write-Output "Total: $count services"
`, filterClause)
	}

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", psCmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		output := string(out)
		if strings.Contains(output, "ERROR:") {
			return "", fmt.Errorf("%s", strings.TrimSpace(output))
		}
		return "", fmt.Errorf("PowerShell command failed: %w", err)
	}

	return string(out), nil
}
