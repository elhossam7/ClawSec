package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/rs/zerolog"
	"github.com/sentinel-agent/sentinel/internal/config"
	"github.com/sentinel-agent/sentinel/internal/types"
)

// Skill is the interface every tool/skill must implement.
// (Defined here so the agent runtime can reference it without circular imports.)
type Skill interface {
	Name() string
	Description() string
	ParametersSchema() map[string]interface{}
	Validate(params map[string]interface{}) error
	Execute(ctx context.Context, params map[string]interface{}) (*types.ToolResult, error)
}

// AnalysisStore persists agent analysis logs.
type AnalysisStore interface {
	SaveAnalysisLog(log *AnalysisLog) error
	SaveToolExecution(exec *ToolExecution) error
}

// AnalysisLog records one LLM interaction.
type AnalysisLog struct {
	ID          string
	IncidentID  string
	SessionID   string
	Prompt      string
	Response    string
	Reasoning   string
	Confidence  float64
	ToolsCalled string // JSON array
	Outcome     string // "approved", "denied", "escalated"
	CreatedAt   time.Time
}

// ToolExecution records one tool invocation.
type ToolExecution struct {
	ID            string
	AnalysisLogID string
	ToolName      string
	Parameters    string // JSON
	Result        string
	Success       bool
	Error         string
	ExecutedAt    time.Time
}

// Agent is the AI-powered SOC analyst.
type Agent struct {
	llm       LLMClient
	tools     map[string]Skill
	memory    Memory
	store     AnalysisStore
	validator *InputValidator
	cfg       config.AIConfig
	logger    zerolog.Logger
}

// NewAgent creates and wires up an Agent.
func NewAgent(cfg config.AIConfig, memory Memory, store AnalysisStore, logger zerolog.Logger) (*Agent, error) {
	llm, err := NewLLMClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating LLM client: %w", err)
	}

	a := &Agent{
		llm:       llm,
		tools:     make(map[string]Skill),
		memory:    memory,
		store:     store,
		validator: NewInputValidator(),
		cfg:       cfg,
		logger:    logger.With().Str("component", "agent").Logger(),
	}
	return a, nil
}

// RegisterTool adds a skill to the agent's toolbox.
func (a *Agent) RegisterTool(skill Skill) {
	a.tools[skill.Name()] = skill
	a.logger.Info().Str("tool", skill.Name()).Msg("registered agent tool")
}

// Health returns a summary of the agent's operational status.
func (a *Agent) Health() map[string]interface{} {
	status := "healthy"
	if a.llm == nil {
		status = "degraded"
	}
	return map[string]interface{}{
		"status":       status,
		"provider":     a.llm.Provider(),
		"model":        a.cfg.Model,
		"tools":        len(a.tools),
		"auto_analyze": a.cfg.AutoAnalyze,
	}
}

// ListTools returns the tool definitions available to the agent.
func (a *Agent) ListTools() []ToolDef {
	return a.getToolDefs()
}

// TestConnection verifies the LLM provider is reachable with a minimal call.
func (a *Agent) TestConnection(ctx context.Context) error {
	msgs := []Message{
		{Role: "user", Content: "Respond with exactly: OK"},
	}
	resp, err := a.llm.Complete(ctx, msgs, nil)
	if err != nil {
		return fmt.Errorf("LLM connection test failed: %w", err)
	}
	if resp.Content == "" {
		return fmt.Errorf("LLM returned empty response")
	}
	return nil
}

// callLLMWithRetry wraps LLM calls with exponential backoff retry logic.
func (a *Agent) callLLMWithRetry(ctx context.Context, messages []Message, tools []ToolDef) (*LLMResponse, error) {
	maxRetries := 3
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
			a.logger.Warn().
				Int("attempt", attempt+1).
				Dur("backoff", backoff).
				Err(lastErr).
				Msg("retrying LLM call")
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		resp, err := a.llm.Complete(ctx, messages, tools)
		if err == nil {
			return resp, nil
		}
		lastErr = err

		// Don't retry on context cancellation or validation errors.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
	}

	return nil, fmt.Errorf("LLM API call failed after %d retries: %w", maxRetries, lastErr)
}

// AnalyzeIncident performs AI-driven analysis of a security incident.
func (a *Agent) AnalyzeIncident(ctx context.Context, req types.AnalysisRequest) (*types.AnalysisResult, error) {
	start := time.Now()
	a.logger.Info().Str("incident", req.Incident.ID).Msg("starting AI analysis")

	// 1. Gather context from memory.
	memCtx, _ := a.memory.GetRelevantContext(req.Incident.ID, req.Incident.SourceIP, req.Incident.RuleID)

	// 2. Build prompt.
	systemMsg := BuildSystemPrompt(SystemPrompt, a.getToolDefs())
	userMsg := BuildIncidentPrompt(req.Incident, req.MatchedRules, memCtx)

	messages := []Message{
		{Role: "system", Content: systemMsg},
		{Role: "user", Content: userMsg},
	}

	// 3. Enter agent loop (LLM may call tools multiple times).
	var allToolCalls []types.ToolCall
	iterations := 0
	maxIter := a.cfg.MaxToolCalls
	if maxIter < 1 {
		maxIter = 10
	}

	for iterations < maxIter {
		iterations++

		resp, err := a.callLLMWithRetry(ctx, messages, a.getToolDefs())
		if err != nil {
			return nil, fmt.Errorf("LLM API call failed: %w", err)
		}

		a.logger.Debug().
			Int("iteration", iterations).
			Int("tool_calls", len(resp.ToolCalls)).
			Str("stop", resp.StopReason).
			Msg("LLM response received")

		// If the model wants to use tools, execute them and loop.
		if len(resp.ToolCalls) > 0 {
			// Add assistant message with tool calls to conversation.
			messages = append(messages, Message{
				Role:      "assistant",
				Content:   resp.Content,
				ToolCalls: resp.ToolCalls,
			})

			for _, tc := range resp.ToolCalls {
				toolResult := a.executeTool(ctx, tc)
				allToolCalls = append(allToolCalls, types.ToolCall{
					ToolName:   tc.Name,
					Parameters: rawToMap(tc.RawInput),
					Result:     toolResult,
					Timestamp:  time.Now(),
				})
				// Feed tool result back to LLM.
				resultJSON, _ := json.Marshal(toolResult)
				messages = append(messages, Message{
					Role:       "tool",
					Content:    string(resultJSON),
					ToolCallID: tc.ID,
				})
			}
			continue
		}

		// No more tool calls — parse the final response.
		result := a.parseAnalysis(resp.Content, req.Incident.ID, allToolCalls)
		result.CreatedAt = time.Now()

		// Determine if human review needed.
		if result.RiskScore > a.cfg.RequireApprovalAboveRisk {
			result.RequiresHuman = true
		}
		if result.Confidence < a.cfg.ConfidenceThreshold {
			result.RequiresHuman = true
		}

		// 4. Persist audit trail.
		a.auditAnalysis(req, messages, resp, result)

		a.logger.Info().
			Str("incident", req.Incident.ID).
			Float64("confidence", result.Confidence).
			Int("risk", result.RiskScore).
			Bool("human_needed", result.RequiresHuman).
			Dur("duration", time.Since(start)).
			Msg("AI analysis complete")

		return result, nil
	}

	return nil, fmt.Errorf("agent exceeded max iterations (%d)", maxIter)
}

// Chat handles an interactive analyst conversation.
func (a *Agent) Chat(ctx context.Context, query, sessionID string) (string, []types.ToolCall, error) {
	// Validate input.
	if err := a.validator.ValidateUserInput(query); err != nil {
		return "", nil, fmt.Errorf("input validation failed: %w", err)
	}

	// Retrieve conversation context.
	prevCtx, _ := a.memory.GetContext(sessionID)

	systemMsg := BuildSystemPrompt(ChatSystemPrompt, a.getToolDefs())
	messages := []Message{
		{Role: "system", Content: systemMsg},
	}
	if prevCtx != "" {
		messages = append(messages, Message{Role: "assistant", Content: prevCtx})
	}
	messages = append(messages, Message{Role: "user", Content: query})

	var allToolCalls []types.ToolCall
	iterations := 0
	maxIter := a.cfg.MaxToolCalls
	if maxIter < 1 {
		maxIter = 10
	}

	for iterations < maxIter {
		iterations++

		resp, err := a.callLLMWithRetry(ctx, messages, a.getToolDefs())
		if err != nil {
			return "", nil, fmt.Errorf("LLM API call: %w", err)
		}

		if len(resp.ToolCalls) > 0 {
			messages = append(messages, Message{
				Role:      "assistant",
				Content:   resp.Content,
				ToolCalls: resp.ToolCalls,
			})
			for _, tc := range resp.ToolCalls {
				toolResult := a.executeTool(ctx, tc)
				allToolCalls = append(allToolCalls, types.ToolCall{
					ToolName:   tc.Name,
					Parameters: rawToMap(tc.RawInput),
					Result:     toolResult,
					Timestamp:  time.Now(),
				})
				resultJSON, _ := json.Marshal(toolResult)
				messages = append(messages, Message{
					Role:       "tool",
					Content:    string(resultJSON),
					ToolCallID: tc.ID,
				})
			}
			continue
		}

		// Save conversation context (last assistant message).
		a.memory.StoreContext(sessionID, resp.Content)

		return resp.Content, allToolCalls, nil
	}

	return "", nil, fmt.Errorf("chat: max iterations reached")
}

// getToolDefs returns tool definitions in LLM-friendly format.
func (a *Agent) getToolDefs() []ToolDef {
	var defs []ToolDef
	for _, t := range a.tools {
		defs = append(defs, ToolDef{
			Name:        t.Name(),
			Description: t.Description(),
			InputSchema: t.ParametersSchema(),
		})
	}
	return defs
}

// executeTool validates and runs a single tool call.
func (a *Agent) executeTool(ctx context.Context, tc LLMTool) *types.ToolResult {
	tool, ok := a.tools[tc.Name]
	if !ok {
		return &types.ToolResult{Success: false, Error: fmt.Sprintf("unknown tool: %s", tc.Name)}
	}

	// Parse parameters.
	var params map[string]interface{}
	if err := json.Unmarshal(tc.RawInput, &params); err != nil {
		return &types.ToolResult{Success: false, Error: fmt.Sprintf("invalid params JSON: %v", err)}
	}

	// Validate against injection.
	if err := a.validator.ValidateToolParams(tc.Name, params); err != nil {
		a.logger.Warn().Str("tool", tc.Name).Err(err).Msg("tool parameter validation failed")
		return &types.ToolResult{Success: false, Error: fmt.Sprintf("validation failed: %v", err)}
	}

	// Validate against tool schema.
	if err := tool.Validate(params); err != nil {
		a.logger.Warn().Str("tool", tc.Name).Err(err).Msg("tool validation rejected")
		return &types.ToolResult{Success: false, Error: fmt.Sprintf("validation failed: %v", err)}
	}

	// Execute.
	result, err := tool.Execute(ctx, params)
	if err != nil {
		a.logger.Error().Str("tool", tc.Name).Err(err).Msg("tool execution error")
		// Sanitise — don't leak internal paths or stack traces to LLM.
		return &types.ToolResult{Success: false, Error: fmt.Sprintf("tool %s execution failed", tc.Name)}
	}

	a.logger.Info().Str("tool", tc.Name).Bool("success", result.Success).Msg("tool executed")

	// Audit the tool execution.
	if a.store != nil {
		paramsJSON, _ := json.Marshal(params)
		resultJSON, _ := json.Marshal(result)
		a.store.SaveToolExecution(&ToolExecution{
			ID:         fmt.Sprintf("te_%d", time.Now().UnixNano()),
			ToolName:   tc.Name,
			Parameters: string(paramsJSON),
			Result:     string(resultJSON),
			Success:    result.Success,
			Error:      result.Error,
			ExecutedAt: time.Now(),
		})
	}

	return result
}

// parseAnalysis extracts structured fields from the LLM's final response.
func (a *Agent) parseAnalysis(content string, incidentID string, toolCalls []types.ToolCall) *types.AnalysisResult {
	result := &types.AnalysisResult{
		IncidentID: incidentID,
		ToolCalls:  toolCalls,
		Confidence: 0.5,
		RiskScore:  5,
	}

	// Try to parse the JSON response.
	var parsed struct {
		Observation    string `json:"observation"`
		Analysis       string `json:"analysis"`
		Recommendation struct {
			Action     string  `json:"action"`
			Target     string  `json:"target"`
			Confidence float64 `json:"confidence"`
			RiskScore  int     `json:"risk_score"`
			Reasoning  string  `json:"reasoning"`
		} `json:"recommendation"`
		Alternatives []struct {
			Action    string `json:"action"`
			RiskScore int    `json:"risk_score"`
			Reasoning string `json:"reasoning"`
		} `json:"alternatives"`
		RequiresHuman bool `json:"requires_human"`
	}

	if err := json.Unmarshal([]byte(content), &parsed); err == nil {
		result.Summary = parsed.Observation
		result.Reasoning = parsed.Analysis
		result.Confidence = parsed.Recommendation.Confidence
		result.RiskScore = parsed.Recommendation.RiskScore
		result.RequiresHuman = parsed.RequiresHuman

		if parsed.Recommendation.Action != "" {
			proposal := types.ActionProposal{
				Action: types.ResponseAction{
					Type:   types.ActionType(parsed.Recommendation.Action),
					Target: parsed.Recommendation.Target,
					Reason: parsed.Recommendation.Reasoning,
				},
				Reasoning:  parsed.Recommendation.Reasoning,
				Confidence: parsed.Recommendation.Confidence,
				RiskScore:  parsed.Recommendation.RiskScore,
			}
			for _, alt := range parsed.Alternatives {
				proposal.Alternatives = append(proposal.Alternatives, types.ResponseAction{
					Type:   types.ActionType(alt.Action),
					Reason: alt.Reasoning,
				})
			}
			result.ProposedActions = append(result.ProposedActions, proposal)
		}
	} else {
		// Fallback: treat entire content as summary.
		result.Summary = content
		result.Reasoning = content
	}

	return result
}

// auditAnalysis persists the analysis for compliance.
func (a *Agent) auditAnalysis(req types.AnalysisRequest, msgs []Message, resp *LLMResponse, result *types.AnalysisResult) {
	if a.store == nil {
		return
	}

	promptJSON, _ := json.Marshal(msgs)
	toolsJSON, _ := json.Marshal(result.ToolCalls)

	outcome := "proposed"
	if result.RequiresHuman {
		outcome = "escalated"
	}

	a.store.SaveAnalysisLog(&AnalysisLog{
		ID:          fmt.Sprintf("al_%d", time.Now().UnixNano()),
		IncidentID:  req.Incident.ID,
		Prompt:      string(promptJSON),
		Response:    resp.Content,
		Reasoning:   result.Reasoning,
		Confidence:  result.Confidence,
		ToolsCalled: string(toolsJSON),
		Outcome:     outcome,
		CreatedAt:   time.Now(),
	})
}

// rawToMap converts a json.RawMessage to map[string]interface{}.
func rawToMap(raw json.RawMessage) map[string]interface{} {
	m := make(map[string]interface{})
	json.Unmarshal(raw, &m)
	return m
}
