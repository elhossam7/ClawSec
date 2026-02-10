//go:build windows

package platform

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/sentinel-agent/sentinel/internal/types"
)

// EventLogSource monitors Windows Event Log channels using wevtutil.
type EventLogSource struct {
	channels []string
	logger   zerolog.Logger
	cancel   context.CancelFunc
}

// NewEventLogSource creates a Windows Event Log source.
func NewEventLogSource(channels []string, logger zerolog.Logger) *EventLogSource {
	return &EventLogSource{
		channels: channels,
		logger:   logger.With().Str("source", "eventlog").Logger(),
	}
}

func (e *EventLogSource) Name() string {
	return "eventlog"
}

func (e *EventLogSource) Start(ctx context.Context, events chan<- types.LogEvent) error {
	ctx, e.cancel = context.WithCancel(ctx)

	hostname, _ := os.Hostname()
	ticker := time.NewTicker(5 * time.Second) // Poll interval
	defer ticker.Stop()

	lastCheck := time.Now()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			for _, channel := range e.channels {
				newEvents, err := e.queryEvents(ctx, channel, lastCheck, hostname)
				if err != nil {
					e.logger.Error().Err(err).Str("channel", channel).Msg("failed to query event log")
					continue
				}
				for _, ev := range newEvents {
					select {
					case events <- ev:
					case <-ctx.Done():
						return nil
					}
				}
			}
			lastCheck = time.Now()
		}
	}
}

func (e *EventLogSource) Stop() error {
	if e.cancel != nil {
		e.cancel()
	}
	return nil
}

// queryEvents uses PowerShell Get-WinEvent to retrieve recent events.
func (e *EventLogSource) queryEvents(ctx context.Context, channel string, since time.Time, hostname string) ([]types.LogEvent, error) {
	// Build PowerShell command to query events since last check.
	sinceStr := since.Format("2006-01-02T15:04:05")
	psCmd := fmt.Sprintf(
		`Get-WinEvent -FilterHashtable @{LogName='%s'; StartTime='%s'} -MaxEvents 100 -ErrorAction SilentlyContinue | ForEach-Object { "$($_.TimeCreated)|$($_.Id)|$($_.LevelDisplayName)|$($_.Message)" }`,
		channel, sinceStr,
	)

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", psCmd)
	output, err := cmd.Output()
	if err != nil {
		// No events found is not an error.
		return nil, nil
	}

	var events []types.LogEvent
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "|", 4)
		ev := types.LogEvent{
			ID:        fmt.Sprintf("evtlog_%d", time.Now().UnixNano()),
			Timestamp: time.Now(),
			Source:    fmt.Sprintf("eventlog:%s", channel),
			Category:  categorizeEventLog(channel, line),
			Severity:  detectEventLogSeverity(parts),
			Hostname:  hostname,
			Raw:       line,
			Fields:    parseEventLogLine(parts),
			Platform:  "windows",
		}
		events = append(events, ev)
	}

	return events, nil
}

// categorizeEventLog determines the category based on channel and content.
func categorizeEventLog(channel, line string) string {
	switch strings.ToLower(channel) {
	case "security":
		lower := strings.ToLower(line)
		if strings.Contains(lower, "logon") || strings.Contains(lower, "logoff") ||
			strings.Contains(lower, "account") || strings.Contains(lower, "credential") {
			return "auth"
		}
		if strings.Contains(lower, "firewall") || strings.Contains(lower, "network") {
			return "network"
		}
		return "security"
	case "system":
		return "system"
	case "application":
		return "application"
	default:
		return "general"
	}
}

// detectEventLogSeverity maps Windows event levels to Sentinel severity.
func detectEventLogSeverity(parts []string) types.Severity {
	if len(parts) < 3 {
		return types.SeverityInfo
	}
	switch strings.TrimSpace(strings.ToLower(parts[2])) {
	case "critical":
		return types.SeverityCritical
	case "error":
		return types.SeverityHigh
	case "warning":
		return types.SeverityMedium
	case "information":
		return types.SeverityInfo
	default:
		return types.SeverityInfo
	}
}

// parseEventLogLine extracts fields from piped event output.
func parseEventLogLine(parts []string) map[string]string {
	fields := make(map[string]string)
	if len(parts) >= 1 {
		fields["timestamp"] = strings.TrimSpace(parts[0])
	}
	if len(parts) >= 2 {
		fields["event_id"] = strings.TrimSpace(parts[1])
	}
	if len(parts) >= 3 {
		fields["level"] = strings.TrimSpace(parts[2])
	}
	if len(parts) >= 4 {
		msg := strings.TrimSpace(parts[3])
		fields["message"] = msg

		// Extract IPs from message.
		lower := strings.ToLower(msg)
		if idx := strings.Index(lower, "source network address:"); idx >= 0 {
			rest := strings.TrimSpace(msg[idx+23:])
			if nlIdx := strings.IndexByte(rest, '\n'); nlIdx > 0 {
				fields["source_ip"] = strings.TrimSpace(rest[:nlIdx])
			} else {
				fields["source_ip"] = rest
			}
		}

		// Extract account name.
		if idx := strings.Index(lower, "account name:"); idx >= 0 {
			rest := strings.TrimSpace(msg[idx+13:])
			if nlIdx := strings.IndexAny(rest, "\n\r\t"); nlIdx > 0 {
				fields["username"] = strings.TrimSpace(rest[:nlIdx])
			} else {
				fields["username"] = strings.TrimSpace(rest)
			}
		}
	}
	return fields
}
