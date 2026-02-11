// Package alerting implements alert channel integrations for Sentinel.
package alerting

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/sentinel-agent/sentinel/internal/config"
	"github.com/sentinel-agent/sentinel/internal/types"
)

// ---------------------------------------------------------------------------
// Alerter interface
// ---------------------------------------------------------------------------

// Alerter is the common interface for all alert channel implementations.
type Alerter interface {
	SendAlert(action types.ResponseAction)
	SendExecutionNotice(action types.ResponseAction)
}

// ---------------------------------------------------------------------------
// WebhookAlerter – generic HTTP JSON webhook
// ---------------------------------------------------------------------------

// webhookPayload is the JSON body posted to the configured webhook URL.
type webhookPayload struct {
	Event     string               `json:"event"`
	Timestamp string               `json:"timestamp"`
	Action    webhookActionPayload `json:"action"`
}

// webhookActionPayload carries the response-action fields in a
// JSON-friendly layout.
type webhookActionPayload struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Status     string `json:"status"`
	Target     string `json:"target"`
	Reason     string `json:"reason"`
	RuleID     string `json:"rule_id"`
	IncidentID string `json:"incident_id"`
	Severity   string `json:"severity"`
	ApprovedBy string `json:"approved_by,omitempty"`
	CreatedAt  string `json:"created_at"`
	ExecutedAt string `json:"executed_at,omitempty"`
}

// WebhookAlerter sends JSON POST requests to an arbitrary HTTP endpoint.
type WebhookAlerter struct {
	cfg    config.WebhookConfig
	client *http.Client
	logger zerolog.Logger
}

// NewWebhookAlerter creates a WebhookAlerter from the given configuration.
func NewWebhookAlerter(cfg config.WebhookConfig, logger zerolog.Logger) *WebhookAlerter {
	return &WebhookAlerter{
		cfg: cfg,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		logger: logger.With().Str("component", "webhook").Logger(),
	}
}

// SendAlert posts an alert event to the configured webhook URL.
func (w *WebhookAlerter) SendAlert(action types.ResponseAction) {
	payload := w.buildPayload("alert", action)
	w.post(payload)
}

// SendExecutionNotice posts an execution_notice event to the configured
// webhook URL.
func (w *WebhookAlerter) SendExecutionNotice(action types.ResponseAction) {
	payload := w.buildPayload("execution_notice", action)
	w.post(payload)
}

// buildPayload constructs the webhookPayload for the given event type and action.
func (w *WebhookAlerter) buildPayload(event string, action types.ResponseAction) webhookPayload {
	ap := webhookActionPayload{
		ID:         action.ID,
		Type:       string(action.Type),
		Status:     string(action.Status),
		Target:     action.Target,
		Reason:     action.Reason,
		RuleID:     action.RuleID,
		IncidentID: action.IncidentID,
		Severity:   action.Severity.String(),
		ApprovedBy: action.ApprovedBy,
		CreatedAt:  action.CreatedAt.Format(time.RFC3339),
	}
	if action.ExecutedAt != nil {
		ap.ExecutedAt = action.ExecutedAt.Format(time.RFC3339)
	}
	return webhookPayload{
		Event:     event,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Action:    ap,
	}
}

// post marshals the payload and sends it to the webhook URL. It retries once
// on failure.
func (w *WebhookAlerter) post(payload webhookPayload) {
	body, err := json.Marshal(payload)
	if err != nil {
		w.logger.Error().Err(err).Msg("failed to marshal webhook payload")
		return
	}

	// First attempt.
	if w.doPost(body) {
		return
	}

	// Retry once on failure.
	w.logger.Warn().Msg("webhook delivery failed, retrying once")
	if !w.doPost(body) {
		w.logger.Error().Msg("webhook delivery failed after retry")
	}
}

// doPost performs a single HTTP POST and returns true on success (2xx).
func (w *WebhookAlerter) doPost(body []byte) bool {
	req, err := http.NewRequest(http.MethodPost, w.cfg.URL, bytes.NewReader(body))
	if err != nil {
		w.logger.Error().Err(err).Msg("failed to create webhook request")
		return false
	}

	req.Header.Set("Content-Type", "application/json")

	// HMAC-SHA256 signature when a secret is configured.
	if w.cfg.Secret != "" {
		mac := hmac.New(sha256.New, []byte(w.cfg.Secret))
		mac.Write(body)
		sig := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Sentinel-Signature", sig)
	}

	// Apply any custom headers from the configuration.
	for key, value := range w.cfg.Headers {
		req.Header.Set(key, value)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		w.logger.Error().Err(err).Str("url", w.cfg.URL).Msg("webhook request failed")
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		w.logger.Debug().Int("status", resp.StatusCode).Msg("webhook delivered")
		return true
	}

	w.logger.Warn().Int("status", resp.StatusCode).Str("url", w.cfg.URL).Msg("webhook returned non-2xx status")
	return false
}

// ---------------------------------------------------------------------------
// SlackAlerter – Slack Block Kit integration
// ---------------------------------------------------------------------------

// SlackAlerter sends alert messages to Slack via an incoming webhook.
type SlackAlerter struct {
	cfg    config.SlackConfig
	client *http.Client
	logger zerolog.Logger
}

// NewSlackAlerter creates a SlackAlerter from the given configuration.
func NewSlackAlerter(cfg config.SlackConfig, logger zerolog.Logger) *SlackAlerter {
	return &SlackAlerter{
		cfg: cfg,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		logger: logger.With().Str("component", "slack").Logger(),
	}
}

// SendAlert posts a richly-formatted Block Kit message to Slack.
func (s *SlackAlerter) SendAlert(action types.ResponseAction) {
	color := s.severityColor(action.Severity)
	title := fmt.Sprintf("%s Alert — %s", strings.ToUpper(action.Severity.String()), action.Type)

	blocks := []map[string]interface{}{
		{
			"type": "header",
			"text": map[string]string{
				"type": "plain_text",
				"text": title,
			},
		},
		{
			"type": "section",
			"fields": []map[string]string{
				{"type": "mrkdwn", "text": fmt.Sprintf("*Type:*\n`%s`", action.Type)},
				{"type": "mrkdwn", "text": fmt.Sprintf("*Target:*\n`%s`", action.Target)},
				{"type": "mrkdwn", "text": fmt.Sprintf("*Severity:*\n%s", action.Severity.String())},
				{"type": "mrkdwn", "text": fmt.Sprintf("*Rule:*\n`%s`", action.RuleID)},
			},
		},
		{
			"type": "section",
			"text": map[string]string{
				"type": "mrkdwn",
				"text": fmt.Sprintf("*Reason:*\n%s", action.Reason),
			},
		},
		{
			"type": "context",
			"elements": []map[string]string{
				{"type": "mrkdwn", "text": fmt.Sprintf("Action ID: `%s` | Incident: `%s`", action.ID, action.IncidentID)},
			},
		},
	}

	payload := map[string]interface{}{
		"attachments": []map[string]interface{}{
			{
				"color":  color,
				"blocks": blocks,
			},
		},
	}

	if s.cfg.Channel != "" {
		payload["channel"] = s.cfg.Channel
	}

	s.postSlack(payload)
}

// SendExecutionNotice posts a simpler notification about an executed action.
func (s *SlackAlerter) SendExecutionNotice(action types.ResponseAction) {
	executedAt := "N/A"
	if action.ExecutedAt != nil {
		executedAt = action.ExecutedAt.Format(time.RFC3339)
	}

	blocks := []map[string]interface{}{
		{
			"type": "header",
			"text": map[string]string{
				"type": "plain_text",
				"text": "Action Executed",
			},
		},
		{
			"type": "section",
			"fields": []map[string]string{
				{"type": "mrkdwn", "text": fmt.Sprintf("*Type:*\n`%s`", action.Type)},
				{"type": "mrkdwn", "text": fmt.Sprintf("*Target:*\n`%s`", action.Target)},
				{"type": "mrkdwn", "text": fmt.Sprintf("*Approved by:*\n%s", action.ApprovedBy)},
				{"type": "mrkdwn", "text": fmt.Sprintf("*Executed at:*\n%s", executedAt)},
			},
		},
		{
			"type": "context",
			"elements": []map[string]string{
				{"type": "mrkdwn", "text": fmt.Sprintf("Action ID: `%s`", action.ID)},
			},
		},
	}

	payload := map[string]interface{}{
		"attachments": []map[string]interface{}{
			{
				"color":  "#2196f3",
				"blocks": blocks,
			},
		},
	}

	if s.cfg.Channel != "" {
		payload["channel"] = s.cfg.Channel
	}

	s.postSlack(payload)
}

// postSlack marshals and sends the payload to the Slack webhook URL.
func (s *SlackAlerter) postSlack(payload map[string]interface{}) {
	body, err := json.Marshal(payload)
	if err != nil {
		s.logger.Error().Err(err).Msg("failed to marshal slack payload")
		return
	}

	req, err := http.NewRequest(http.MethodPost, s.cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		s.logger.Error().Err(err).Msg("failed to create slack request")
		return
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		s.logger.Error().Err(err).Msg("slack webhook request failed")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		s.logger.Warn().Int("status", resp.StatusCode).Msg("slack webhook returned non-2xx status")
		return
	}

	s.logger.Debug().Msg("slack message delivered")
}

// severityColor returns Slack attachment color hex strings mapped to severity.
func (s *SlackAlerter) severityColor(sev types.Severity) string {
	switch sev {
	case types.SeverityCritical:
		return "#e91e63" // red-pink
	case types.SeverityHigh:
		return "#ff9800" // orange
	case types.SeverityMedium:
		return "#ffeb3b" // yellow
	case types.SeverityLow:
		return "#4caf50" // green
	default:
		return "#2196f3" // blue
	}
}
