//go:build linux

package platform

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/sentinel-agent/sentinel/internal/types"
)

// JournaldSource reads from systemd journal on Linux.
// This implementation uses `journalctl --follow` as a subprocess
// for portability without requiring cgo sd-journal bindings.
type JournaldSource struct {
	units  []string
	logger zerolog.Logger
	cancel context.CancelFunc
}

// NewJournaldSource creates a journald log source.
func NewJournaldSource(units []string, logger zerolog.Logger) *JournaldSource {
	return &JournaldSource{
		units:  units,
		logger: logger.With().Str("source", "journald").Logger(),
	}
}

func (j *JournaldSource) Name() string {
	return "journald"
}

func (j *JournaldSource) Start(ctx context.Context, events chan<- types.LogEvent) error {
	ctx, j.cancel = context.WithCancel(ctx)

	args := []string{"--follow", "--no-pager", "-o", "short-iso"}
	for _, unit := range j.units {
		args = append(args, "-u", unit)
	}

	// Use os/exec to stream journalctl output.
	cmd := execCommandContext(ctx, "journalctl", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("journalctl stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting journalctl: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	hostname, _ := os.Hostname()

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		ev := types.LogEvent{
			ID:        fmt.Sprintf("journald_%d", time.Now().UnixNano()),
			Timestamp: time.Now(),
			Source:    "journald",
			Category:  categorizeJournalLine(line),
			Severity:  detectSeverity(line),
			Hostname:  hostname,
			Raw:       line,
			Fields:    parseJournalLine(line),
			Platform:  "linux",
		}

		select {
		case events <- ev:
		case <-ctx.Done():
			return nil
		}
	}

	return cmd.Wait()
}

func (j *JournaldSource) Stop() error {
	if j.cancel != nil {
		j.cancel()
	}
	return nil
}

// SyslogSource reads from a syslog file on Linux.
type SyslogSource struct {
	path   string
	fw     *FileWatcher
	logger zerolog.Logger
}

// NewSyslogSource creates a syslog file watcher.
func NewSyslogSource(path string, logger zerolog.Logger) (*SyslogSource, error) {
	paths := []WatchedPath{{
		Path:     path,
		Category: "auth",
		Parser:   "auto",
	}}

	fw, err := NewFileWatcher(paths, logger)
	if err != nil {
		return nil, err
	}

	return &SyslogSource{path: path, fw: fw, logger: logger}, nil
}

func (s *SyslogSource) Name() string {
	return "syslog"
}

func (s *SyslogSource) Start(ctx context.Context, events chan<- types.LogEvent) error {
	return s.fw.Start(ctx, events)
}

func (s *SyslogSource) Stop() error {
	return s.fw.Stop()
}

// Helper functions for journald parsing.

func categorizeJournalLine(line string) string {
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "sshd") || strings.Contains(lower, "pam"):
		return "auth"
	case strings.Contains(lower, "iptables") || strings.Contains(lower, "ufw"):
		return "network"
	case strings.Contains(lower, "docker") || strings.Contains(lower, "containerd"):
		return "container"
	case strings.Contains(lower, "kernel"):
		return "system"
	default:
		return "general"
	}
}

func parseJournalLine(line string) map[string]string {
	fields := make(map[string]string)

	// Extract common patterns from syslog-style lines.
	// Format: "date hostname process[pid]: message"
	parts := strings.SplitN(line, ": ", 2)
	if len(parts) == 2 {
		fields["message"] = parts[1]
	}

	// Extract IPs.
	if idx := strings.Index(line, "from "); idx >= 0 {
		rest := line[idx+5:]
		if spaceIdx := strings.IndexByte(rest, ' '); spaceIdx > 0 {
			fields["source_ip"] = rest[:spaceIdx]
		}
	}

	// Extract usernames.
	for _, prefix := range []string{"user ", "for ", "user="} {
		if idx := strings.Index(line, prefix); idx >= 0 {
			rest := line[idx+len(prefix):]
			if spaceIdx := strings.IndexByte(rest, ' '); spaceIdx > 0 {
				fields["username"] = rest[:spaceIdx]
			} else {
				fields["username"] = rest
			}
			break
		}
	}

	return fields
}

func detectSeverity(line string) types.Severity {
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "failed") || strings.Contains(lower, "error"):
		return types.SeverityMedium
	case strings.Contains(lower, "invalid") || strings.Contains(lower, "denied"):
		return types.SeverityMedium
	case strings.Contains(lower, "accepted") || strings.Contains(lower, "success"):
		return types.SeverityInfo
	case strings.Contains(lower, "critical") || strings.Contains(lower, "emergency"):
		return types.SeverityCritical
	default:
		return types.SeverityInfo
	}
}
