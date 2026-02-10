package storage

import (
	"github.com/sentinel-agent/sentinel/internal/agent"
)

// AgentStoreAdapter wraps AgentStore to satisfy agent.AnalysisStore interface.
type AgentStoreAdapter struct {
	store *AgentStore
}

// NewAgentStoreAdapter creates an adapter that bridges storage → agent interface.
func NewAgentStoreAdapter(store *AgentStore) *AgentStoreAdapter {
	return &AgentStoreAdapter{store: store}
}

// SaveAnalysisLog converts agent.AnalysisLog → storage.AnalysisLogRow and persists it.
func (a *AgentStoreAdapter) SaveAnalysisLog(log *agent.AnalysisLog) error {
	row := &AnalysisLogRow{
		ID:          log.ID,
		IncidentID:  log.IncidentID,
		SessionID:   log.SessionID,
		Prompt:      log.Prompt,
		Response:    log.Response,
		Reasoning:   log.Reasoning,
		Confidence:  log.Confidence,
		ToolsCalled: log.ToolsCalled,
		Outcome:     log.Outcome,
		CreatedAt:   log.CreatedAt,
	}
	return a.store.SaveAnalysisLog(row)
}

// SaveToolExecution converts agent.ToolExecution → storage.ToolExecutionRow and persists it.
func (a *AgentStoreAdapter) SaveToolExecution(exec *agent.ToolExecution) error {
	row := &ToolExecutionRow{
		ID:            exec.ID,
		AnalysisLogID: exec.AnalysisLogID,
		ToolName:      exec.ToolName,
		Parameters:    exec.Parameters,
		Result:        exec.Result,
		Success:       exec.Success,
		Error:         exec.Error,
		ExecutedAt:    exec.ExecutedAt,
	}
	return a.store.SaveToolExecution(row)
}
