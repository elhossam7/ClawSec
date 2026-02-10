// Package engine implements the Sentinel detection engine.
// It processes log events against SIGMA-compatible rules and generates incidents.
package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/sentinel-agent/sentinel/internal/types"
	"gopkg.in/yaml.v3"
)

// Engine is the core detection engine that processes log events against rules.
type Engine struct {
	rules      map[string]*CompiledRule
	correlator *Correlator
	workers    int
	logger     zerolog.Logger
	mu         sync.RWMutex

	// Channels
	events        <-chan types.LogEvent
	incidents     chan Incident
	actions       chan types.ResponseAction
	analysisQueue chan types.AnalysisRequest // AI agent analysis queue

	// AI agent integration
	aiEnabled bool
	rulesDir  string // Path to rules directory for file persistence
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
		rules:         make(map[string]*CompiledRule),
		correlator:    NewCorrelator(logger),
		workers:       workers,
		events:        events,
		incidents:     make(chan Incident, 1000),
		actions:       make(chan types.ResponseAction, 100),
		analysisQueue: make(chan types.AnalysisRequest, 100),
		logger:        logger.With().Str("component", "engine").Logger(),
	}
}

// EnableAI turns on AI-powered analysis routing.
func (e *Engine) EnableAI() {
	e.aiEnabled = true
	e.logger.Info().Msg("AI-powered analysis enabled — incidents will be routed to agent")
}

// AnalysisQueue returns the channel where AI analysis requests are sent.
func (e *Engine) AnalysisQueue() <-chan types.AnalysisRequest {
	return e.analysisQueue
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

			// When AI is enabled, route to agent analysis instead of direct action.
			if e.aiEnabled {
				analysisReq := types.AnalysisRequest{
					Incident: types.Incident{
						ID:          fmt.Sprintf("inc_%d", time.Now().UnixNano()),
						Title:       incident.Message,
						Description: rule.Description,
						Severity:    rule.Severity,
						Status:      types.IncidentOpen,
						RuleID:      rule.ID,
						SourceIP:    event.Fields["source_ip"],
						TargetUser:  event.Fields["username"],
						CreatedAt:   time.Now(),
						UpdatedAt:   time.Now(),
					},
					MatchedRules: []string{rule.ID},
					Timestamp:    time.Now(),
				}
				select {
				case e.analysisQueue <- analysisReq:
				case <-ctx.Done():
					return
				}
			} else {
				select {
				case e.actions <- ra:
				case <-ctx.Done():
					return
				}
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

// SetRulesDir sets the directory where rules are persisted on disk.
func (e *Engine) SetRulesDir(dir string) {
	e.rulesDir = dir
}

// RulesDir returns the configured rules directory.
func (e *Engine) RulesDir() string {
	return e.rulesDir
}

// GetRule returns a single compiled rule by ID, or nil if not found.
func (e *Engine) GetRule(id string) *CompiledRule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.rules[id]
}

// AddRule compiles and adds a new rule to the engine, optionally persisting to disk.
func (e *Engine) AddRule(raw Rule, persist bool) error {
	compiled, err := CompileRule(raw)
	if err != nil {
		return fmt.Errorf("compiling rule: %w", err)
	}

	e.mu.Lock()
	if _, exists := e.rules[raw.ID]; exists {
		e.mu.Unlock()
		return fmt.Errorf("rule %q already exists — use UpdateRule instead", raw.ID)
	}
	e.rules[raw.ID] = compiled
	e.mu.Unlock()

	if persist && e.rulesDir != "" {
		if err := e.saveRuleFile(raw); err != nil {
			return fmt.Errorf("rule added to engine but failed to persist: %w", err)
		}
	}

	e.logger.Info().Str("rule", raw.ID).Msg("rule added")
	return nil
}

// UpdateRule replaces an existing rule, re-compiles it, and optionally persists.
func (e *Engine) UpdateRule(raw Rule, persist bool) error {
	compiled, err := CompileRule(raw)
	if err != nil {
		return fmt.Errorf("compiling rule: %w", err)
	}

	e.mu.Lock()
	if _, exists := e.rules[raw.ID]; !exists {
		e.mu.Unlock()
		return fmt.Errorf("rule %q not found — use AddRule to create it", raw.ID)
	}
	e.rules[raw.ID] = compiled
	e.mu.Unlock()

	if persist && e.rulesDir != "" {
		if err := e.saveRuleFile(raw); err != nil {
			return fmt.Errorf("rule updated in engine but failed to persist: %w", err)
		}
	}

	e.logger.Info().Str("rule", raw.ID).Msg("rule updated")
	return nil
}

// DeleteRule removes a rule from the engine and optionally deletes the file.
func (e *Engine) DeleteRule(id string, deleteFile bool) error {
	e.mu.Lock()
	if _, exists := e.rules[id]; !exists {
		e.mu.Unlock()
		return fmt.Errorf("rule %q not found", id)
	}
	delete(e.rules, id)
	e.mu.Unlock()

	if deleteFile && e.rulesDir != "" {
		path := filepath.Join(e.rulesDir, id+".yml")
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("rule removed from engine but failed to delete file: %w", err)
		}
	}

	e.logger.Info().Str("rule", id).Msg("rule deleted")
	return nil
}

// saveRuleFile marshals a Rule to YAML and writes it to the rules directory.
func (e *Engine) saveRuleFile(rule Rule) error {
	data, err := yaml.Marshal(&rule)
	if err != nil {
		return fmt.Errorf("marshalling rule YAML: %w", err)
	}

	path := filepath.Join(e.rulesDir, rule.ID+".yml")
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("writing rule file %s: %w", path, err)
	}
	return nil
}
