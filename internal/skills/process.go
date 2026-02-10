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

// ProcessSkill manages system processes (kill, info).
type ProcessSkill struct {
	protectedProcesses []string
	logger             zerolog.Logger
}

// NewProcessSkill creates a process skill with protected process names.
func NewProcessSkill(protectedProcesses []string, logger zerolog.Logger) *ProcessSkill {
	if len(protectedProcesses) == 0 {
		protectedProcesses = []string{"systemd", "init", "sshd", "sentinel", "explorer", "csrss", "smss", "lsass"}
	}
	return &ProcessSkill{
		protectedProcesses: protectedProcesses,
		logger:             logger.With().Str("skill", "process").Logger(),
	}
}

func (p *ProcessSkill) Name() string { return "kill_process" }
func (p *ProcessSkill) Description() string {
	return "Terminate a running process by PID. Use when a malicious or compromised process must be stopped."
}

func (p *ProcessSkill) ParametersSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"pid": map[string]interface{}{
				"type":        "string",
				"description": "Process ID to terminate",
			},
			"reason": map[string]interface{}{
				"type":        "string",
				"description": "Justification for killing the process",
			},
		},
		"required": []string{"pid", "reason"},
	}
}

func (p *ProcessSkill) Validate(params map[string]interface{}) error {
	pid, err := GetStringParam(params, "pid")
	if err != nil {
		return err
	}
	if strings.ContainsAny(pid, ";|&$` ") {
		return fmt.Errorf("invalid PID: %s", pid)
	}
	return nil
}

func (p *ProcessSkill) Execute(ctx context.Context, params map[string]interface{}) (*types.ToolResult, error) {
	pid, _ := GetStringParam(params, "pid")
	reason, _ := GetStringParam(params, "reason")

	p.logger.Info().Str("pid", pid).Str("reason", reason).Msg("killing process")

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.CommandContext(ctx, "kill", "-9", pid)
	case "windows":
		cmd = exec.CommandContext(ctx, "taskkill", "/F", "/PID", pid)
	default:
		return &types.ToolResult{Success: false, Error: "unsupported platform"}, nil
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return &types.ToolResult{Success: false, Output: string(output), Error: err.Error()}, nil
	}

	return &types.ToolResult{
		Success: true,
		Output:  fmt.Sprintf("Process %s terminated", pid),
		Data:    map[string]interface{}{"pid": pid, "reason": reason},
	}, nil
}

// ProcessInfoSkill gathers information about a process.
type ProcessInfoSkill struct {
	logger zerolog.Logger
}

func NewProcessInfoSkill(logger zerolog.Logger) *ProcessInfoSkill {
	return &ProcessInfoSkill{logger: logger.With().Str("skill", "process_info").Logger()}
}

func (p *ProcessInfoSkill) Name() string { return "get_process_info" }
func (p *ProcessInfoSkill) Description() string {
	return "Get detailed information about a running process by PID, including command line, user, and resource usage."
}

func (p *ProcessInfoSkill) ParametersSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"pid": map[string]interface{}{
				"type":        "string",
				"description": "Process ID to inspect",
			},
		},
		"required": []string{"pid"},
	}
}

func (p *ProcessInfoSkill) Validate(params map[string]interface{}) error {
	pid, err := GetStringParam(params, "pid")
	if err != nil {
		return err
	}
	if strings.ContainsAny(pid, ";|&$` ") {
		return fmt.Errorf("invalid PID: %s", pid)
	}
	return nil
}

func (p *ProcessInfoSkill) Execute(ctx context.Context, params map[string]interface{}) (*types.ToolResult, error) {
	pid, _ := GetStringParam(params, "pid")

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.CommandContext(ctx, "ps", "-p", pid, "-o", "pid,ppid,user,%cpu,%mem,etime,args")
	case "windows":
		psCmd := fmt.Sprintf(`Get-Process -Id %s | Select-Object Id,ProcessName,CPU,WorkingSet64,StartTime,Path | ConvertTo-Json`, pid)
		cmd = exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", psCmd)
	default:
		return &types.ToolResult{Success: false, Error: "unsupported platform"}, nil
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return &types.ToolResult{Success: false, Output: string(output), Error: err.Error()}, nil
	}

	return &types.ToolResult{
		Success: true,
		Output:  string(output),
		Data:    map[string]interface{}{"pid": pid},
	}, nil
}
