package agent

import (
	"context"

	"github.com/rs/zerolog"
	"github.com/sentinel-agent/sentinel/internal/config"
)

// ---------------------------------------------------------------------------
// MockLLM — a programmable mock for the LLMClient interface.
// ---------------------------------------------------------------------------

// MockLLM is a programmable mock for the LLMClient interface.
// Set Response (raw JSON string) and/or Err before calling the agent.
// After the call, inspect LastSystemPrompt and LastUserMessage.
type MockLLM struct {
	// Response to return (raw JSON string used as LLMResponse.Content).
	Response string
	// Error to return from Complete.
	Err error
	// Captured inputs for verification.
	LastSystemPrompt string
	LastUserMessage  string
	// CallCount tracks how many times Complete was invoked.
	CallCount int
}

// Provider implements LLMClient.
func (m *MockLLM) Provider() string { return "mock" }

// Complete implements LLMClient.
// It captures the system and last user message, then returns a simple
// end-turn response whose Content is m.Response.
func (m *MockLLM) Complete(ctx context.Context, messages []Message, tools []ToolDef) (*LLMResponse, error) {
	m.CallCount++

	// Capture system prompt and last user message for test assertions.
	for _, msg := range messages {
		if msg.Role == "system" {
			m.LastSystemPrompt = msg.Content
		}
		if msg.Role == "user" {
			m.LastUserMessage = msg.Content
		}
	}

	if m.Err != nil {
		return nil, m.Err
	}

	return &LLMResponse{
		Content:    m.Response,
		StopReason: "end_turn",
	}, nil
}

// ---------------------------------------------------------------------------
// Test constructors
// ---------------------------------------------------------------------------

// nullMemory is a no-op Memory implementation for tests.
type nullMemory struct{}

func (nullMemory) StoreLearning(_, _ string, _ float64) error        { return nil }
func (nullMemory) GetRelevantContext(_, _, _ string) (string, error) { return "", nil }
func (nullMemory) StoreContext(_, _ string) error                    { return nil }
func (nullMemory) GetContext(_ string) (string, error)               { return "", nil }

// nullStore is a no-op AnalysisStore for tests.
type nullStore struct{}

func (nullStore) SaveAnalysisLog(_ *AnalysisLog) error     { return nil }
func (nullStore) SaveToolExecution(_ *ToolExecution) error { return nil }

// NewAgentForTest creates an Agent with an externally-provided LLM client
// and full control over config, memory, and store.
// This is intended for integration and unit tests that need to inject a mock LLM.
func NewAgentForTest(llm LLMClient, cfg config.AIConfig, memory Memory, store AnalysisStore, logger zerolog.Logger) *Agent {
	return &Agent{
		llm:       llm,
		tools:     make(map[string]Skill),
		memory:    memory,
		store:     store,
		validator: NewInputValidator(),
		cfg:       cfg,
		logger:    logger.With().Str("component", "agent").Logger(),
	}
}

// NewAgentForQuickTest creates an Agent with sensible defaults — no-op memory,
// no-op audit store, and standard AI config. Only the LLM and logger are needed.
func NewAgentForQuickTest(llm LLMClient, logger zerolog.Logger) *Agent {
	cfg := config.AIConfig{
		MaxToolCalls:             10,
		Temperature:              0.3,
		RequireApprovalAboveRisk: 7,
		ConfidenceThreshold:      0.85,
	}
	return &Agent{
		llm:       llm,
		tools:     make(map[string]Skill),
		memory:    nullMemory{},
		store:     nullStore{},
		validator: NewInputValidator(),
		cfg:       cfg,
		logger:    logger.With().Str("component", "agent").Logger(),
	}
}
