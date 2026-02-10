// Package platform provides cross-platform log source abstractions.
package platform

import (
	"context"
	"fmt"
	"sync"

	"github.com/rs/zerolog"
	"github.com/sentinel-agent/sentinel/internal/types"
)

// LogSource is the interface all platform-specific log collectors implement.
type LogSource interface {
	// Name returns a human-readable identifier for this source.
	Name() string
	// Start begins collecting logs and sending them to the events channel.
	Start(ctx context.Context, events chan<- types.LogEvent) error
	// Stop gracefully shuts down the log source.
	Stop() error
}

// Manager coordinates multiple log sources.
type Manager struct {
	sources []LogSource
	events  chan types.LogEvent
	logger  zerolog.Logger
	mu      sync.Mutex
	running bool
}

// NewManager creates a new platform manager with the given event buffer size.
func NewManager(bufferSize int, logger zerolog.Logger) *Manager {
	return &Manager{
		sources: make([]LogSource, 0),
		events:  make(chan types.LogEvent, bufferSize),
		logger:  logger.With().Str("component", "platform").Logger(),
	}
}

// Register adds a log source to the manager.
func (m *Manager) Register(source LogSource) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sources = append(m.sources, source)
	m.logger.Info().Str("source", source.Name()).Msg("registered log source")
}

// Events returns the channel where all collected log events are sent.
func (m *Manager) Events() <-chan types.LogEvent {
	return m.events
}

// Start begins all registered log sources.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return fmt.Errorf("platform manager already running")
	}

	if len(m.sources) == 0 {
		return fmt.Errorf("no log sources registered")
	}

	for _, source := range m.sources {
		s := source // capture
		go func() {
			m.logger.Info().Str("source", s.Name()).Msg("starting log source")
			if err := s.Start(ctx, m.events); err != nil {
				m.logger.Error().Err(err).Str("source", s.Name()).Msg("log source error")
			}
		}()
	}

	m.running = true
	m.logger.Info().Int("sources", len(m.sources)).Msg("platform manager started")
	return nil
}

// Stop shuts down all log sources.
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var lastErr error
	for _, source := range m.sources {
		if err := source.Stop(); err != nil {
			m.logger.Error().Err(err).Str("source", source.Name()).Msg("error stopping log source")
			lastErr = err
		}
	}
	m.running = false
	m.logger.Info().Msg("platform manager stopped")
	return lastErr
}

// SourceNames returns the names of all registered sources.
func (m *Manager) SourceNames() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	names := make([]string, len(m.sources))
	for i, s := range m.sources {
		names[i] = s.Name()
	}
	return names
}
