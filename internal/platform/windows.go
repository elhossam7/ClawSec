//go:build windows

package platform

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/sentinel-agent/sentinel/internal/types"
)

// EventLogSource monitors Windows Event Log channels.
// It uses PowerShell Register-WmiEvent streaming by default and falls
// back to polling if streaming is unavailable.
type EventLogSource struct {
	channels []string
	logger   zerolog.Logger
	cancel   context.CancelFunc
	wg       sync.WaitGroup
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

	for _, channel := range e.channels {
		ch := channel
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			e.streamChannel(ctx, ch, hostname, events)
		}()
	}

	// Block until context is cancelled.
	<-ctx.Done()
	e.wg.Wait()
	return nil
}

func (e *EventLogSource) Stop() error {
	if e.cancel != nil {
		e.cancel()
	}
	e.wg.Wait()
	return nil
}

// streamChannel tries streaming via Get-WinEvent -Wait first.
// If the streaming process exits unexpectedly, it falls back to polling.
func (e *EventLogSource) streamChannel(ctx context.Context, channel, hostname string, events chan<- types.LogEvent) {
	e.logger.Info().Str("channel", channel).Msg("starting event log stream")

	for {
		// Attempt streaming. If it returns without ctx being cancelled, fall back.
		err := e.runStreaming(ctx, channel, hostname, events)
		if ctx.Err() != nil {
			return // Normal shutdown.
		}

		e.logger.Warn().Err(err).Str("channel", channel).Msg("event log stream ended, falling back to polling")
		e.runPolling(ctx, channel, hostname, events)
		if ctx.Err() != nil {
			return
		}

		// Brief pause before retrying streaming.
		select {
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
			return
		}
	}
}

// runStreaming launches a long-running PowerShell process that continuously
// tails the specified event log channel using Get-WinEvent with a tight
// poll loop and outputs one event per line.
func (e *EventLogSource) runStreaming(ctx context.Context, channel, hostname string, events chan<- types.LogEvent) error {
	// PowerShell script that continuously reads new events.
	// We use a small poll interval inside PS to get near-real-time delivery.
	psScript := fmt.Sprintf(`
$lastTime = (Get-Date)
while ($true) {
    $evts = Get-WinEvent -FilterHashtable @{LogName='%s'; StartTime=$lastTime} -MaxEvents 50 -ErrorAction SilentlyContinue
    if ($evts) {
        foreach ($ev in $evts) {
            Write-Output "$($ev.TimeCreated)|$($ev.Id)|$($ev.LevelDisplayName)|$($ev.Message -replace '\r?\n',' ')"
        }
        $lastTime = ($evts | Select-Object -First 1).TimeCreated.AddMilliseconds(1)
    }
    Start-Sleep -Milliseconds 500
}
`, channel)

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NoLogo", "-Command", psScript)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("creating stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting streaming process: %w", err)
	}

	e.logger.Info().Str("channel", channel).Int("pid", cmd.Process.Pid).Msg("event log streaming started")

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 256*1024) // handle long messages

	for scanner.Scan() {
		if ctx.Err() != nil {
			break
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		ev := parseEventLine(channel, line, hostname)
		select {
		case events <- ev:
		case <-ctx.Done():
			break
		}
	}

	// Kill the process if still running.
	if cmd.Process != nil {
		cmd.Process.Kill()
	}
	cmd.Wait()

	if ctx.Err() != nil {
		return nil
	}
	return fmt.Errorf("streaming process exited")
}

// runPolling is the fallback: queries events every 2 seconds.
func (e *EventLogSource) runPolling(ctx context.Context, channel, hostname string, events chan<- types.LogEvent) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	lastCheck := time.Now()
	maxPolls := 60 // After 60 polls (~2 min), try streaming again.
	polls := 0

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			polls++
			if polls > maxPolls {
				e.logger.Info().Str("channel", channel).Msg("polling limit reached, will retry streaming")
				return
			}

			newEvents, err := e.queryEvents(ctx, channel, lastCheck, hostname)
			if err != nil {
				e.logger.Error().Err(err).Str("channel", channel).Msg("poll query failed")
				continue
			}
			for _, ev := range newEvents {
				select {
				case events <- ev:
				case <-ctx.Done():
					return
				}
			}
			lastCheck = time.Now()
		}
	}
}

// queryEvents uses PowerShell Get-WinEvent to retrieve recent events (polling fallback).
func (e *EventLogSource) queryEvents(ctx context.Context, channel string, since time.Time, hostname string) ([]types.LogEvent, error) {
	sinceStr := since.Format("2006-01-02T15:04:05")
	psCmd := fmt.Sprintf(
		`Get-WinEvent -FilterHashtable @{LogName='%s'; StartTime='%s'} -MaxEvents 100 -ErrorAction SilentlyContinue | ForEach-Object { "$($_.TimeCreated)|$($_.Id)|$($_.LevelDisplayName)|$($_.Message -replace '\r?\n',' ')" }`,
		channel, sinceStr,
	)

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", psCmd)
	output, err := cmd.Output()
	if err != nil {
		return nil, nil // No events found is not an error.
	}

	var events []types.LogEvent
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		events = append(events, parseEventLine(channel, line, hostname))
	}

	return events, nil
}

// parseEventLine converts a piped event log line to a LogEvent.
func parseEventLine(channel, line, hostname string) types.LogEvent {
	parts := strings.SplitN(line, "|", 4)
	return types.LogEvent{
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
			if nlIdx := strings.IndexAny(rest, "\n\r\t "); nlIdx > 0 {
				fields["username"] = strings.TrimSpace(rest[:nlIdx])
			} else {
				fields["username"] = strings.TrimSpace(rest)
			}
		}
	}
	return fields
}
