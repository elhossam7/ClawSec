// Package agent implements the AI-powered SOC agent runtime.
// It integrates with LLM APIs (Anthropic, OpenAI, Ollama, Gemini) to provide
// intelligent incident analysis, investigation, and response.
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/sentinel-agent/sentinel/internal/config"
)

// ---------------------------------------------------------------------------
// LLM client interface & common types
// ---------------------------------------------------------------------------

// LLMClient abstracts communication with any LLM provider.
type LLMClient interface {
	Complete(ctx context.Context, messages []Message, tools []ToolDef) (*LLMResponse, error)
	Provider() string
	// SetModel swaps the active model name (used for fallback rotation).
	SetModel(model string)
	// GetModel returns the current model name.
	GetModel() string
}

// Message represents a single chat-completion message.
type Message struct {
	Role       string    `json:"role"` // "system", "user", "assistant", "tool"
	Content    string    `json:"content"`
	ToolCallID string    `json:"tool_call_id,omitempty"`
	ToolCalls  []LLMTool `json:"tool_calls,omitempty"`
}

// LLMTool is a tool-use request returned by the LLM.
type LLMTool struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	RawInput json.RawMessage `json:"input"` // tool parameters as JSON
}

// ToolDef describes a tool the LLM may call.
type ToolDef struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"input_schema"` // JSON Schema
}

// LLMResponse is the unified response from any provider.
type LLMResponse struct {
	Content    string    `json:"content"`
	ToolCalls  []LLMTool `json:"tool_calls,omitempty"`
	StopReason string    `json:"stop_reason"` // "end_turn", "tool_use", "max_tokens"
	Usage      Usage     `json:"usage"`
}

// Usage tracks token consumption.
type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// NewLLMClient creates the appropriate client from config.
func NewLLMClient(cfg config.AIConfig) (LLMClient, error) {
	switch cfg.Provider {
	case "anthropic":
		return newAnthropicClient(cfg)
	case "openai":
		return newOpenAIClient(cfg)
	case "ollama":
		return newOllamaClient(cfg)
	case "gemini":
		return newGeminiClient(cfg)
	default:
		return nil, fmt.Errorf("unsupported LLM provider: %q", cfg.Provider)
	}
}

// ---------------------------------------------------------------------------
// Anthropic Claude client
// ---------------------------------------------------------------------------

type anthropicClient struct {
	apiKey     string
	model      string
	baseURL    string
	httpClient *http.Client
}

func newAnthropicClient(cfg config.AIConfig) (*anthropicClient, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("anthropic api_key is required")
	}
	base := "https://api.anthropic.com"
	if cfg.Endpoint != "" {
		base = cfg.Endpoint
	}
	return &anthropicClient{
		apiKey:     cfg.APIKey,
		model:      cfg.Model,
		baseURL:    base,
		httpClient: &http.Client{Timeout: 120 * time.Second},
	}, nil
}

func (c *anthropicClient) Provider() string  { return "anthropic" }
func (c *anthropicClient) SetModel(m string) { c.model = m }
func (c *anthropicClient) GetModel() string  { return c.model }

func (c *anthropicClient) Complete(ctx context.Context, messages []Message, tools []ToolDef) (*LLMResponse, error) {
	// Separate system message from conversation.
	var system string
	var apiMsgs []map[string]interface{}
	for _, m := range messages {
		if m.Role == "system" {
			system = m.Content
			continue
		}
		msg := map[string]interface{}{"role": m.Role, "content": m.Content}
		if m.ToolCallID != "" {
			msg["tool_use_id"] = m.ToolCallID
			msg["type"] = "tool_result"
			msg["role"] = "user"
			msg["content"] = []map[string]interface{}{
				{"type": "tool_result", "tool_use_id": m.ToolCallID, "content": m.Content},
			}
		}
		apiMsgs = append(apiMsgs, msg)
	}

	body := map[string]interface{}{
		"model":      c.model,
		"max_tokens": 4096,
		"messages":   apiMsgs,
	}
	if system != "" {
		body["system"] = system
	}
	if len(tools) > 0 {
		var apiTools []map[string]interface{}
		for _, t := range tools {
			apiTools = append(apiTools, map[string]interface{}{
				"name":         t.Name,
				"description":  t.Description,
				"input_schema": t.InputSchema,
			})
		}
		body["tools"] = apiTools
	}

	return c.doRequest(ctx, body)
}

func (c *anthropicClient) doRequest(ctx context.Context, body map[string]interface{}) (*LLMResponse, error) {
	payload, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/v1/messages", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("anthropic API call: %w", err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anthropic API %d: %s", resp.StatusCode, string(data))
	}

	var raw struct {
		Content []struct {
			Type  string          `json:"type"`
			Text  string          `json:"text,omitempty"`
			ID    string          `json:"id,omitempty"`
			Name  string          `json:"name,omitempty"`
			Input json.RawMessage `json:"input,omitempty"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
		Usage      struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing anthropic response: %w", err)
	}

	result := &LLMResponse{
		StopReason: raw.StopReason,
		Usage:      Usage{InputTokens: raw.Usage.InputTokens, OutputTokens: raw.Usage.OutputTokens},
	}
	for _, block := range raw.Content {
		switch block.Type {
		case "text":
			result.Content += block.Text
		case "tool_use":
			result.ToolCalls = append(result.ToolCalls, LLMTool{
				ID:       block.ID,
				Name:     block.Name,
				RawInput: block.Input,
			})
		}
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// OpenAI GPT client
// ---------------------------------------------------------------------------

type openaiClient struct {
	apiKey     string
	model      string
	baseURL    string
	httpClient *http.Client
}

func newOpenAIClient(cfg config.AIConfig) (*openaiClient, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("openai api_key is required")
	}
	base := "https://api.openai.com"
	if cfg.Endpoint != "" {
		base = cfg.Endpoint
	}
	return &openaiClient{
		apiKey:     cfg.APIKey,
		model:      cfg.Model,
		baseURL:    base,
		httpClient: &http.Client{Timeout: 120 * time.Second},
	}, nil
}

func (c *openaiClient) Provider() string  { return "openai" }
func (c *openaiClient) SetModel(m string) { c.model = m }
func (c *openaiClient) GetModel() string  { return c.model }

func (c *openaiClient) Complete(ctx context.Context, messages []Message, tools []ToolDef) (*LLMResponse, error) {
	var apiMsgs []map[string]interface{}
	for _, m := range messages {
		msg := map[string]interface{}{"role": m.Role, "content": m.Content}
		if m.ToolCallID != "" {
			msg["tool_call_id"] = m.ToolCallID
		}
		apiMsgs = append(apiMsgs, msg)
	}

	body := map[string]interface{}{
		"model":      c.model,
		"messages":   apiMsgs,
		"max_tokens": 4096,
	}
	if len(tools) > 0 {
		var funcs []map[string]interface{}
		for _, t := range tools {
			funcs = append(funcs, map[string]interface{}{
				"type": "function",
				"function": map[string]interface{}{
					"name":        t.Name,
					"description": t.Description,
					"parameters":  t.InputSchema,
				},
			})
		}
		body["tools"] = funcs
	}

	payload, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/v1/chat/completions", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openai API call: %w", err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openai API %d: %s", resp.StatusCode, string(data))
	}

	var raw struct {
		Choices []struct {
			Message struct {
				Content   string `json:"content"`
				ToolCalls []struct {
					ID       string `json:"id"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing openai response: %w", err)
	}
	if len(raw.Choices) == 0 {
		return nil, fmt.Errorf("openai returned no choices")
	}

	choice := raw.Choices[0]
	result := &LLMResponse{
		Content:    choice.Message.Content,
		StopReason: choice.FinishReason,
		Usage:      Usage{InputTokens: raw.Usage.PromptTokens, OutputTokens: raw.Usage.CompletionTokens},
	}
	for _, tc := range choice.Message.ToolCalls {
		result.ToolCalls = append(result.ToolCalls, LLMTool{
			ID:       tc.ID,
			Name:     tc.Function.Name,
			RawInput: json.RawMessage(tc.Function.Arguments),
		})
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Ollama local model client
// ---------------------------------------------------------------------------

type ollamaClient struct {
	endpoint   string
	model      string
	httpClient *http.Client
}

func newOllamaClient(cfg config.AIConfig) (*ollamaClient, error) {
	ep := "http://localhost:11434"
	if cfg.Endpoint != "" {
		ep = cfg.Endpoint
	}
	return &ollamaClient{
		endpoint:   ep,
		model:      cfg.Model,
		httpClient: &http.Client{Timeout: 300 * time.Second},
	}, nil
}

func (c *ollamaClient) Provider() string  { return "ollama" }
func (c *ollamaClient) SetModel(m string) { c.model = m }
func (c *ollamaClient) GetModel() string  { return c.model }

func (c *ollamaClient) Complete(ctx context.Context, messages []Message, tools []ToolDef) (*LLMResponse, error) {
	var apiMsgs []map[string]string
	for _, m := range messages {
		apiMsgs = append(apiMsgs, map[string]string{"role": m.Role, "content": m.Content})
	}

	body := map[string]interface{}{
		"model":    c.model,
		"messages": apiMsgs,
		"stream":   false,
	}

	// Ollama supports tools for some models.
	if len(tools) > 0 {
		var funcs []map[string]interface{}
		for _, t := range tools {
			funcs = append(funcs, map[string]interface{}{
				"type": "function",
				"function": map[string]interface{}{
					"name":        t.Name,
					"description": t.Description,
					"parameters":  t.InputSchema,
				},
			})
		}
		body["tools"] = funcs
	}

	payload, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, "POST", c.endpoint+"/api/chat", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ollama API call: %w", err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ollama API %d: %s", resp.StatusCode, string(data))
	}

	var raw struct {
		Message struct {
			Role      string `json:"role"`
			Content   string `json:"content"`
			ToolCalls []struct {
				Function struct {
					Name      string          `json:"name"`
					Arguments json.RawMessage `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing ollama response: %w", err)
	}

	result := &LLMResponse{
		Content:    raw.Message.Content,
		StopReason: "end_turn",
	}
	for i, tc := range raw.Message.ToolCalls {
		result.ToolCalls = append(result.ToolCalls, LLMTool{
			ID:       fmt.Sprintf("ollama_%d", i),
			Name:     tc.Function.Name,
			RawInput: tc.Function.Arguments,
		})
	}
	if len(result.ToolCalls) > 0 {
		result.StopReason = "tool_use"
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Google Gemini client
// ---------------------------------------------------------------------------

type geminiClient struct {
	apiKey     string
	model      string
	baseURL    string
	httpClient *http.Client
}

func newGeminiClient(cfg config.AIConfig) (*geminiClient, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("gemini api_key is required")
	}
	base := "https://generativelanguage.googleapis.com"
	if cfg.Endpoint != "" {
		base = cfg.Endpoint
	}
	return &geminiClient{
		apiKey:     cfg.APIKey,
		model:      cfg.Model,
		baseURL:    base,
		httpClient: &http.Client{Timeout: 120 * time.Second},
	}, nil
}

func (c *geminiClient) Provider() string  { return "gemini" }
func (c *geminiClient) SetModel(m string) { c.model = m }
func (c *geminiClient) GetModel() string  { return c.model }

func (c *geminiClient) Complete(ctx context.Context, messages []Message, tools []ToolDef) (*LLMResponse, error) {
	// Build Gemini contents from messages.
	var systemInstruction string
	var contents []map[string]interface{}

	for _, m := range messages {
		if m.Role == "system" {
			systemInstruction = m.Content
			continue
		}

		role := m.Role
		if role == "assistant" {
			role = "model"
		}
		if role == "tool" {
			// Gemini expects function responses as "function" role parts.
			contents = append(contents, map[string]interface{}{
				"role": "function",
				"parts": []map[string]interface{}{
					{
						"functionResponse": map[string]interface{}{
							"name":     m.ToolCallID,
							"response": map[string]interface{}{"result": m.Content},
						},
					},
				},
			})
			continue
		}

		contents = append(contents, map[string]interface{}{
			"role":  role,
			"parts": []map[string]interface{}{{"text": m.Content}},
		})
	}

	body := map[string]interface{}{
		"contents": contents,
		"generationConfig": map[string]interface{}{
			"maxOutputTokens": 4096,
			"temperature":     0.3,
		},
	}

	// System instruction.
	if systemInstruction != "" {
		body["systemInstruction"] = map[string]interface{}{
			"parts": []map[string]interface{}{{"text": systemInstruction}},
		}
	}

	// Tool declarations.
	if len(tools) > 0 {
		var funcDecls []map[string]interface{}
		for _, t := range tools {
			decl := map[string]interface{}{
				"name":        t.Name,
				"description": t.Description,
			}
			if len(t.InputSchema) > 0 {
				// Convert JSON Schema to Gemini's parameter format.
				decl["parameters"] = t.InputSchema
			}
			funcDecls = append(funcDecls, decl)
		}
		body["tools"] = []map[string]interface{}{
			{"functionDeclarations": funcDecls},
		}
	}

	// POST to Gemini API.
	url := fmt.Sprintf("%s/v1beta/models/%s:generateContent?key=%s", c.baseURL, c.model, c.apiKey)
	payload, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gemini API call: %w", err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gemini API %d: %s", resp.StatusCode, string(data))
	}

	var raw struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text         string `json:"text,omitempty"`
					FunctionCall *struct {
						Name string          `json:"name"`
						Args json.RawMessage `json:"args"`
					} `json:"functionCall,omitempty"`
				} `json:"parts"`
			} `json:"content"`
			FinishReason string `json:"finishReason"`
		} `json:"candidates"`
		UsageMetadata struct {
			PromptTokenCount     int `json:"promptTokenCount"`
			CandidatesTokenCount int `json:"candidatesTokenCount"`
		} `json:"usageMetadata"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing gemini response: %w", err)
	}
	if len(raw.Candidates) == 0 {
		return nil, fmt.Errorf("gemini returned no candidates")
	}

	candidate := raw.Candidates[0]
	result := &LLMResponse{
		StopReason: mapGeminiFinishReason(candidate.FinishReason),
		Usage: Usage{
			InputTokens:  raw.UsageMetadata.PromptTokenCount,
			OutputTokens: raw.UsageMetadata.CandidatesTokenCount,
		},
	}

	for i, part := range candidate.Content.Parts {
		if part.Text != "" {
			result.Content += part.Text
		}
		if part.FunctionCall != nil {
			result.ToolCalls = append(result.ToolCalls, LLMTool{
				ID:       fmt.Sprintf("gemini_%d", i),
				Name:     part.FunctionCall.Name,
				RawInput: part.FunctionCall.Args,
			})
		}
	}

	return result, nil
}

// mapGeminiFinishReason converts Gemini's finish reasons to our unified format.
func mapGeminiFinishReason(reason string) string {
	switch reason {
	case "STOP":
		return "end_turn"
	case "MAX_TOKENS":
		return "max_tokens"
	case "SAFETY", "RECITATION", "OTHER":
		return "end_turn"
	default:
		return "end_turn"
	}
}
