package platform

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"
	"github.com/sentinel-agent/sentinel/internal/types"
)

// FileWatcher monitors log files for new lines using filesystem notifications.
type FileWatcher struct {
	paths    []WatchedPath
	watcher  *fsnotify.Watcher
	logger   zerolog.Logger
	offsets  map[string]int64 // Track read position per file
	cancel   context.CancelFunc
}

// WatchedPath is a file path with metadata for parsing.
type WatchedPath struct {
	Path     string
	Category string
	Parser   string // "auto", "json", "regex"
	Pattern  string // regex pattern for line parsing
	compiled *regexp.Regexp
}

// NewFileWatcher creates a watcher for the given file paths.
func NewFileWatcher(paths []WatchedPath, logger zerolog.Logger) (*FileWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("creating fsnotify watcher: %w", err)
	}

	// Compile regex patterns.
	for i, p := range paths {
		if p.Parser == "regex" && p.Pattern != "" {
			compiled, err := regexp.Compile(p.Pattern)
			if err != nil {
				return nil, fmt.Errorf("compiling pattern for %s: %w", p.Path, err)
			}
			paths[i].compiled = compiled
		}
	}

	return &FileWatcher{
		paths:   paths,
		watcher: watcher,
		logger:  logger.With().Str("source", "file_watcher").Logger(),
		offsets: make(map[string]int64),
	}, nil
}

func (fw *FileWatcher) Name() string {
	return "file_watcher"
}

func (fw *FileWatcher) Start(ctx context.Context, events chan<- types.LogEvent) error {
	ctx, fw.cancel = context.WithCancel(ctx)

	// Add all paths to the watcher.
	for _, wp := range fw.paths {
		// Watch the directory so we catch log rotation (new files).
		dir := filepath.Dir(wp.Path)
		if err := fw.watcher.Add(dir); err != nil {
			fw.logger.Warn().Err(err).Str("path", dir).Msg("cannot watch directory")
		}

		// Seek to end of existing files (only process new lines).
		if info, err := os.Stat(wp.Path); err == nil {
			fw.offsets[wp.Path] = info.Size()
		}
	}

	// Event processing loop.
	for {
		select {
		case <-ctx.Done():
			return nil

		case event, ok := <-fw.watcher.Events:
			if !ok {
				return nil
			}
			if event.Has(fsnotify.Write) {
				wp := fw.findWatchedPath(event.Name)
				if wp == nil {
					continue
				}
				newEvents, err := fw.readNewLines(wp)
				if err != nil {
					fw.logger.Error().Err(err).Str("file", wp.Path).Msg("error reading new lines")
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

		case err, ok := <-fw.watcher.Errors:
			if !ok {
				return nil
			}
			fw.logger.Error().Err(err).Msg("watcher error")
		}
	}
}

func (fw *FileWatcher) Stop() error {
	if fw.cancel != nil {
		fw.cancel()
	}
	return fw.watcher.Close()
}

// readNewLines reads lines added since the last known offset.
func (fw *FileWatcher) readNewLines(wp *WatchedPath) ([]types.LogEvent, error) {
	f, err := os.Open(wp.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	offset := fw.offsets[wp.Path]

	// Handle log rotation: if file is smaller than offset, start from beginning.
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() < offset {
		offset = 0
	}

	if _, err := f.Seek(offset, 0); err != nil {
		return nil, err
	}

	var events []types.LogEvent
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		ev := fw.parseLine(wp, line)
		events = append(events, ev)
	}

	// Update offset.
	newOffset, _ := f.Seek(0, 1) // current position
	fw.offsets[wp.Path] = newOffset

	return events, scanner.Err()
}

// parseLine converts a raw log line into a LogEvent.
func (fw *FileWatcher) parseLine(wp *WatchedPath, line string) types.LogEvent {
	hostname, _ := os.Hostname()
	ev := types.LogEvent{
		ID:        fmt.Sprintf("file_%d", time.Now().UnixNano()),
		Timestamp: time.Now(),
		Source:    wp.Path,
		Category:  wp.Category,
		Severity:  types.SeverityInfo,
		Hostname:  hostname,
		Raw:       line,
		Fields:    make(map[string]string),
		Platform:  "file",
	}

	// Attempt regex parsing if configured.
	if wp.compiled != nil {
		matches := wp.compiled.FindStringSubmatch(line)
		if matches != nil {
			names := wp.compiled.SubexpNames()
			for i, name := range names {
				if i > 0 && name != "" && i < len(matches) {
					ev.Fields[name] = matches[i]
				}
			}
		}
	}

	// Auto-detect severity from common keywords.
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "error") || strings.Contains(lower, "failed"):
		ev.Severity = types.SeverityMedium
	case strings.Contains(lower, "warning") || strings.Contains(lower, "warn"):
		ev.Severity = types.SeverityLow
	case strings.Contains(lower, "critical") || strings.Contains(lower, "emergency"):
		ev.Severity = types.SeverityCritical
	}

	return ev
}

// findWatchedPath finds the WatchedPath matching a given filename.
func (fw *FileWatcher) findWatchedPath(name string) *WatchedPath {
	absName, _ := filepath.Abs(name)
	for i, wp := range fw.paths {
		absPath, _ := filepath.Abs(wp.Path)
		if absName == absPath {
			return &fw.paths[i]
		}
	}
	return nil
}
