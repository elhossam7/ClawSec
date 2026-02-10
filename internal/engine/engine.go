// Package engine implements the Sentinel detection engine.
// It processes log events against SIGMA-compatible rules and generates incidents.
package engine

import (
	"context"
	"fmt"
	"sync"

	"github.com/rs/zerolog"
	"github.com/sentinel-agent/sentinel/internal/types"
)

// Engine is the core detection engine that processes log events against rules.
type Engine struct {
	rules      map[string]*CompiledRule
	correlator *Correlator
	workers    int
	logger     zerolog.Logger
	mu         sync.RWMutex

	// Channels
	events    <-chan types.LogEvent
	incidents chan Incident
	actions   chan types.ResponseAction
}

// Incident is an engine-level detection result.
type Incident struct {
	Rule     *CompiledRule
	Event    types.LogEvent
	Severity types.Severity
	Message  string
	Fields   map[string]string
}

// New creates a new detection engine.
func New(workers int, events <-chan types.LogEvent, logger zerolog.Logger) *Engine {
	return &Engine{
		rules:      make(map[string]*CompiledRule),
		correlator: NewCorrelator(logger),
		workers:    workers,
		events:     events,
		incidents:  make(chan Incident, 1000),
		actions:    make(chan types.ResponseAction, 100),
		logger:     logger.With().Str("component", "engine").Logger(),
	}
}

// LoadRules loads and compiles all rules from the given directory.
func (e *Engine) LoadRules(dir string) error {
	rules, err := LoadRulesFromDir(dir)
	if err != nil {
		return fmt.Errorf("loading rules from %s: %w", dir, err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	loaded := 0
	for _, rule := range rules {
		compiled, err := CompileRule(rule)
		if err != nil {
			e.logger.Warn().Err(err).Str("rule", rule.ID).Msg("failed to compile rule, skipping")
			continue
		}
		e.rules[rule.ID] = compiled
		loaded++
	}

	e.logger.Info().Int("loaded", loaded).Int("total", len(rules)).Msg("rules loaded")
	return nil
}

// Incidents returns the channel where detected incidents are sent.
func (e *Engine) Incidents() <-chan Incident {
	return e.incidents
}

// Actions returns the channel where proposed response actions are sent.
func (e *Engine) Actions() <-chan types.ResponseAction {
	return e.actions
}

// Start begins processing events with the configured number of workers.
func (e *Engine) Start(ctx context.Context) {
	e.logger.Info().Int("workers", e.workers).Msg("starting detection engine")

	for i := 0; i < e.workers; i++ {
		go e.worker(ctx, i)
	}

	// Start the correlator cleanup goroutine.
	go e.correlator.Start(ctx)
}

// worker processes events from the event channel.
func (e *Engine) worker(ctx context.Context, id int) {
	e.logger.Debug().Int("worker", id).Msg("engine worker started")

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-e.events:
			if !ok {
				return
			}
			e.processEvent(ctx, event)
		}
	}
}

// processEvent evaluates a single event against all active rules.
func (e *Engine) processEvent(ctx context.Context, event types.LogEvent) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}

		// Check if the event matches the rule's detection logic.
		if !rule.Matches(event) {
			continue
		}

		// Check correlation (e.g., threshold within time window).
		if rule.Correlation != nil {
			key := rule.CorrelationKey(event)
			count := e.correlator.Increment(rule.ID, key, rule.Correlation.Window)
			if count < rule.Correlation.Threshold {
				continue // Not enough occurrences yet
			}
			// Reset counter after triggering.
			e.correlator.Reset(rule.ID, key)
		}

		// Build the incident.
		incident := Incident{
			Rule:     rule,
			Event:    event,
			Severity: rule.Severity,
			Message:  rule.FormatMessage(event),
			Fields:   event.Fields,
		}

		select {
		case e.incidents <- incident:
		case <-ctx.Done():
			return
		}

		e.logger.Info().
			Str("rule", rule.ID).
			Str("severity", rule.Severity.String()).
			Str("source", event.Source).
			Msg("detection triggered")

		// If the rule has response actions, queue them.
		for _, action := range rule.Actions {
			ra := types.ResponseAction{
				Type:     action.Type,
				Status:   types.ActionPending,
				Target:   action.ResolveTarget(event),
				Reason:   incident.Message,
				RuleID:   rule.ID,
				Severity: rule.Severity,
				Evidence: []string{event.ID},
			}

			select {
			case e.actions <- ra:
			case <-ctx.Done():
				return
			}
		}
	}
}

// RuleCount returns the number of loaded rules.
func (e *Engine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

// ActiveRules returns a list of active rule IDs.
func (e *Engine) ActiveRules() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var ids []string
	for id, rule := range e.rules {
		if rule.Enabled {
			ids = append(ids, id)
		}
	}
	return ids
}

// EnableRule enables a rule by ID.
func (e *Engine) EnableRule(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	rule, ok := e.rules[id]
	if !ok {
		return fmt.Errorf("rule %q not found", id)
	}
	rule.Enabled = true
	return nil
}

// DisableRule disables a rule by ID.
func (e *Engine) DisableRule(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	rule, ok := e.rules[id]
	if !ok {
		return fmt.Errorf("rule %q not found", id)
	}
	rule.Enabled = false
	return nil
}

// GetRules returns all loaded rules.
func (e *Engine) GetRules() []*CompiledRule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	rules := make([]*CompiledRule, 0, len(e.rules))
	for _, rule := range e.rules {
		rules = append(rules, rule)
	}
	return rules
}
