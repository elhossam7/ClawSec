package alerting

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/sentinel-agent/sentinel/internal/config"
	"github.com/sentinel-agent/sentinel/internal/types"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newTestLogger returns a no-op zerolog.Logger suitable for tests.
func newTestLogger() zerolog.Logger {
	return zerolog.Nop()
}

// newTestAction returns a fully populated ResponseAction for use in tests.
func newTestAction() types.ResponseAction {
	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	executed := now.Add(30 * time.Second)
	return types.ResponseAction{
		ID:          "act-001",
		Type:        types.ActionBlockIP,
		Status:      types.ActionApproved,
		Target:      "10.0.0.5",
		Reason:      "Brute-force SSH login attempts",
		RuleID:      "rule-ssh-brute",
		IncidentID:  "inc-42",
		Severity:    types.SeverityHigh,
		Evidence:    []string{"evt-1", "evt-2"},
		RollbackCmd: "iptables -D INPUT -s 10.0.0.5 -j DROP",
		ApprovedBy:  "webui:admin",
		CreatedAt:   now,
		ExpiresAt:   now.Add(1 * time.Hour),
		ExecutedAt:  &executed,
	}
}

// ---------------------------------------------------------------------------
// WebhookAlerter tests
// ---------------------------------------------------------------------------

func TestWebhookSendAlert_PayloadStructure(t *testing.T) {
	var received []byte

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		received = buf
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := config.WebhookConfig{
		Enabled: true,
		URL:     ts.URL,
	}

	alerter := NewWebhookAlerter(cfg, newTestLogger())
	action := newTestAction()
	alerter.SendAlert(action)

	// Parse the received payload.
	var payload webhookPayload
	if err := json.Unmarshal(received, &payload); err != nil {
		t.Fatalf("failed to unmarshal webhook payload: %v", err)
	}

	if payload.Event != "alert" {
		t.Errorf("expected event %q, got %q", "alert", payload.Event)
	}
	if payload.Timestamp == "" {
		t.Error("expected non-empty timestamp")
	}
	if payload.Action.ID != "act-001" {
		t.Errorf("expected action ID %q, got %q", "act-001", payload.Action.ID)
	}
	if payload.Action.Type != "block_ip" {
		t.Errorf("expected action type %q, got %q", "block_ip", payload.Action.Type)
	}
	if payload.Action.Status != "approved" {
		t.Errorf("expected action status %q, got %q", "approved", payload.Action.Status)
	}
	if payload.Action.Target != "10.0.0.5" {
		t.Errorf("expected target %q, got %q", "10.0.0.5", payload.Action.Target)
	}
	if payload.Action.Reason != "Brute-force SSH login attempts" {
		t.Errorf("expected reason %q, got %q", "Brute-force SSH login attempts", payload.Action.Reason)
	}
	if payload.Action.RuleID != "rule-ssh-brute" {
		t.Errorf("expected rule_id %q, got %q", "rule-ssh-brute", payload.Action.RuleID)
	}
	if payload.Action.IncidentID != "inc-42" {
		t.Errorf("expected incident_id %q, got %q", "inc-42", payload.Action.IncidentID)
	}
	if payload.Action.Severity != "high" {
		t.Errorf("expected severity %q, got %q", "high", payload.Action.Severity)
	}
	if payload.Action.ApprovedBy != "webui:admin" {
		t.Errorf("expected approved_by %q, got %q", "webui:admin", payload.Action.ApprovedBy)
	}
	if payload.Action.ExecutedAt == "" {
		t.Error("expected non-empty executed_at since action has ExecutedAt set")
	}
}

func TestWebhookSendExecutionNotice_EventField(t *testing.T) {
	var received []byte

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		received = buf
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := config.WebhookConfig{Enabled: true, URL: ts.URL}
	alerter := NewWebhookAlerter(cfg, newTestLogger())
	alerter.SendExecutionNotice(newTestAction())

	var payload webhookPayload
	if err := json.Unmarshal(received, &payload); err != nil {
		t.Fatalf("failed to unmarshal webhook payload: %v", err)
	}

	if payload.Event != "execution_notice" {
		t.Errorf("expected event %q, got %q", "execution_notice", payload.Event)
	}
}

func TestWebhookHMACSignature(t *testing.T) {
	secret := "super-secret-key"
	var sigHeader string
	var bodyBytes []byte

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sigHeader = r.Header.Get("X-Sentinel-Signature")
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		bodyBytes = buf
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := config.WebhookConfig{
		Enabled: true,
		URL:     ts.URL,
		Secret:  secret,
	}

	alerter := NewWebhookAlerter(cfg, newTestLogger())
	alerter.SendAlert(newTestAction())

	if sigHeader == "" {
		t.Fatal("expected X-Sentinel-Signature header to be set when secret is configured")
	}

	// Recompute HMAC-SHA256 and compare.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(bodyBytes)
	expected := hex.EncodeToString(mac.Sum(nil))

	if sigHeader != expected {
		t.Errorf("HMAC mismatch:\n  got:  %s\n  want: %s", sigHeader, expected)
	}
}

func TestWebhookNoSignatureWithoutSecret(t *testing.T) {
	var sigHeader string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sigHeader = r.Header.Get("X-Sentinel-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := config.WebhookConfig{
		Enabled: true,
		URL:     ts.URL,
		Secret:  "", // no secret
	}

	alerter := NewWebhookAlerter(cfg, newTestLogger())
	alerter.SendAlert(newTestAction())

	if sigHeader != "" {
		t.Errorf("expected no X-Sentinel-Signature header when secret is empty, got %q", sigHeader)
	}
}

func TestWebhookCustomHeaders(t *testing.T) {
	var gotAuth string
	var gotCustom string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCustom = r.Header.Get("X-Custom-Tag")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := config.WebhookConfig{
		Enabled: true,
		URL:     ts.URL,
		Headers: map[string]string{
			"Authorization": "Bearer tok-12345",
			"X-Custom-Tag":  "sentinel-test",
		},
	}

	alerter := NewWebhookAlerter(cfg, newTestLogger())
	alerter.SendAlert(newTestAction())

	if gotAuth != "Bearer tok-12345" {
		t.Errorf("expected Authorization header %q, got %q", "Bearer tok-12345", gotAuth)
	}
	if gotCustom != "sentinel-test" {
		t.Errorf("expected X-Custom-Tag header %q, got %q", "sentinel-test", gotCustom)
	}
}

func TestWebhookRetryOnFirstFailure(t *testing.T) {
	var attempt int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempt, 1)
		if n == 1 {
			w.WriteHeader(http.StatusInternalServerError) // 500 on first call
			return
		}
		w.WriteHeader(http.StatusOK) // 200 on retry
	}))
	defer ts.Close()

	cfg := config.WebhookConfig{Enabled: true, URL: ts.URL}
	alerter := NewWebhookAlerter(cfg, newTestLogger())
	alerter.SendAlert(newTestAction())

	total := atomic.LoadInt32(&attempt)
	if total != 2 {
		t.Errorf("expected 2 attempts (initial + 1 retry), got %d", total)
	}
}

func TestWebhookNoRetryOnSuccess(t *testing.T) {
	var attempt int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempt, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := config.WebhookConfig{Enabled: true, URL: ts.URL}
	alerter := NewWebhookAlerter(cfg, newTestLogger())
	alerter.SendAlert(newTestAction())

	total := atomic.LoadInt32(&attempt)
	if total != 1 {
		t.Errorf("expected exactly 1 attempt on immediate success, got %d", total)
	}
}

func TestWebhookContentTypeHeader(t *testing.T) {
	var contentType string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := config.WebhookConfig{Enabled: true, URL: ts.URL}
	alerter := NewWebhookAlerter(cfg, newTestLogger())
	alerter.SendAlert(newTestAction())

	if contentType != "application/json" {
		t.Errorf("expected Content-Type %q, got %q", "application/json", contentType)
	}
}

func TestWebhookNilExecutedAt(t *testing.T) {
	var received []byte

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		received = buf
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := config.WebhookConfig{Enabled: true, URL: ts.URL}
	alerter := NewWebhookAlerter(cfg, newTestLogger())

	action := newTestAction()
	action.ExecutedAt = nil // no execution time
	alerter.SendAlert(action)

	var payload webhookPayload
	if err := json.Unmarshal(received, &payload); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}

	if payload.Action.ExecutedAt != "" {
		t.Errorf("expected empty executed_at when ExecutedAt is nil, got %q", payload.Action.ExecutedAt)
	}
}

// ---------------------------------------------------------------------------
// SlackAlerter tests
// ---------------------------------------------------------------------------

func TestSlackSendAlert_BlockKitStructure(t *testing.T) {
	var received []byte

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		received = buf
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := config.SlackConfig{
		Enabled:    true,
		WebhookURL: ts.URL,
	}

	alerter := NewSlackAlerter(cfg, newTestLogger())
	alerter.SendAlert(newTestAction())

	var payload map[string]interface{}
	if err := json.Unmarshal(received, &payload); err != nil {
		t.Fatalf("failed to unmarshal Slack payload: %v", err)
	}

	// Must have attachments.
	attachments, ok := payload["attachments"].([]interface{})
	if !ok || len(attachments) == 0 {
		t.Fatal("expected non-empty attachments array in Slack payload")
	}

	att, ok := attachments[0].(map[string]interface{})
	if !ok {
		t.Fatal("expected first attachment to be an object")
	}

	// Check color is the severity color for "high" (#ff9800).
	color, _ := att["color"].(string)
	if color != "#ff9800" {
		t.Errorf("expected attachment color %q (high-severity orange), got %q", "#ff9800", color)
	}

	// Check blocks exist and first block is a header.
	blocks, ok := att["blocks"].([]interface{})
	if !ok || len(blocks) < 2 {
		t.Fatalf("expected at least 2 blocks, got %d", len(blocks))
	}

	header, ok := blocks[0].(map[string]interface{})
	if !ok {
		t.Fatal("expected header block to be an object")
	}
	if header["type"] != "header" {
		t.Errorf("expected first block type %q, got %q", "header", header["type"])
	}

	// Verify header text contains the severity and action type.
	headerText, ok := header["text"].(map[string]interface{})
	if !ok {
		t.Fatal("expected header text to be an object")
	}
	text, _ := headerText["text"].(string)
	if text == "" {
		t.Error("expected non-empty header text")
	}

	// Should have a section block with fields.
	section, ok := blocks[1].(map[string]interface{})
	if !ok {
		t.Fatal("expected section block to be an object")
	}
	if section["type"] != "section" {
		t.Errorf("expected second block type %q, got %q", "section", section["type"])
	}

	fields, ok := section["fields"].([]interface{})
	if !ok || len(fields) == 0 {
		t.Fatal("expected non-empty fields array in section block")
	}
}

func TestSlackSendExecutionNotice_DifferentFromAlert(t *testing.T) {
	var alertBody, execBody []byte

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	action := newTestAction()

	// Capture alert payload.
	tsAlert := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		alertBody = buf
		w.WriteHeader(http.StatusOK)
	}))
	defer tsAlert.Close()

	alerterForAlert := NewSlackAlerter(config.SlackConfig{Enabled: true, WebhookURL: tsAlert.URL}, newTestLogger())
	alerterForAlert.SendAlert(action)

	// Capture execution notice payload.
	tsExec := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		execBody = buf
		w.WriteHeader(http.StatusOK)
	}))
	defer tsExec.Close()

	alerterForExec := NewSlackAlerter(config.SlackConfig{Enabled: true, WebhookURL: tsExec.URL}, newTestLogger())
	alerterForExec.SendExecutionNotice(action)

	// Parse both payloads and compare header texts.
	var alertPayload, execPayload map[string]interface{}
	json.Unmarshal(alertBody, &alertPayload)
	json.Unmarshal(execBody, &execPayload)

	alertAtt := alertPayload["attachments"].([]interface{})[0].(map[string]interface{})
	execAtt := execPayload["attachments"].([]interface{})[0].(map[string]interface{})

	alertBlocks := alertAtt["blocks"].([]interface{})
	execBlocks := execAtt["blocks"].([]interface{})

	alertHeader := alertBlocks[0].(map[string]interface{})["text"].(map[string]interface{})["text"].(string)
	execHeader := execBlocks[0].(map[string]interface{})["text"].(map[string]interface{})["text"].(string)

	if alertHeader == execHeader {
		t.Errorf("expected different header text for Alert vs ExecutionNotice, both are %q", alertHeader)
	}

	// ExecutionNotice header should say "Action Executed".
	if execHeader != "Action Executed" {
		t.Errorf("expected execution notice header %q, got %q", "Action Executed", execHeader)
	}

	// ExecutionNotice uses a fixed blue color (#2196f3).
	execColor, _ := execAtt["color"].(string)
	if execColor != "#2196f3" {
		t.Errorf("expected execution notice color %q, got %q", "#2196f3", execColor)
	}
}

func TestSlackSeverityColors(t *testing.T) {
	tests := []struct {
		severity types.Severity
		want     string
	}{
		{types.SeverityCritical, "#e91e63"},
		{types.SeverityHigh, "#ff9800"},
		{types.SeverityMedium, "#ffeb3b"},
		{types.SeverityLow, "#4caf50"},
		{types.SeverityInfo, "#2196f3"}, // default/info maps to blue
	}

	cfg := config.SlackConfig{Enabled: true, WebhookURL: "http://localhost"}
	alerter := NewSlackAlerter(cfg, newTestLogger())

	for _, tt := range tests {
		t.Run(tt.severity.String(), func(t *testing.T) {
			got := alerter.severityColor(tt.severity)
			if got != tt.want {
				t.Errorf("severityColor(%s) = %q, want %q", tt.severity.String(), got, tt.want)
			}
		})
	}
}

func TestSlackChannelOverride(t *testing.T) {
	var received []byte

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		received = buf
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := config.SlackConfig{
		Enabled:    true,
		WebhookURL: ts.URL,
		Channel:    "#security-alerts",
	}

	alerter := NewSlackAlerter(cfg, newTestLogger())
	alerter.SendAlert(newTestAction())

	var payload map[string]interface{}
	if err := json.Unmarshal(received, &payload); err != nil {
		t.Fatalf("failed to unmarshal Slack payload: %v", err)
	}

	channel, ok := payload["channel"].(string)
	if !ok {
		t.Fatal("expected channel field in Slack payload when Channel is configured")
	}
	if channel != "#security-alerts" {
		t.Errorf("expected channel %q, got %q", "#security-alerts", channel)
	}
}

func TestSlackNoChannelWhenEmpty(t *testing.T) {
	var received []byte

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		received = buf
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := config.SlackConfig{
		Enabled:    true,
		WebhookURL: ts.URL,
		Channel:    "", // no channel override
	}

	alerter := NewSlackAlerter(cfg, newTestLogger())
	alerter.SendAlert(newTestAction())

	var payload map[string]interface{}
	if err := json.Unmarshal(received, &payload); err != nil {
		t.Fatalf("failed to unmarshal Slack payload: %v", err)
	}

	if _, exists := payload["channel"]; exists {
		t.Error("expected no channel field in Slack payload when Channel is empty")
	}
}

func TestSlackChannelOverrideInExecutionNotice(t *testing.T) {
	var received []byte

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		received = buf
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := config.SlackConfig{
		Enabled:    true,
		WebhookURL: ts.URL,
		Channel:    "#ops-channel",
	}

	alerter := NewSlackAlerter(cfg, newTestLogger())
	alerter.SendExecutionNotice(newTestAction())

	var payload map[string]interface{}
	if err := json.Unmarshal(received, &payload); err != nil {
		t.Fatalf("failed to unmarshal Slack payload: %v", err)
	}

	channel, ok := payload["channel"].(string)
	if !ok {
		t.Fatal("expected channel field in execution notice Slack payload")
	}
	if channel != "#ops-channel" {
		t.Errorf("expected channel %q, got %q", "#ops-channel", channel)
	}
}

func TestSlackContentType(t *testing.T) {
	var contentType string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := config.SlackConfig{Enabled: true, WebhookURL: ts.URL}
	alerter := NewSlackAlerter(cfg, newTestLogger())
	alerter.SendAlert(newTestAction())

	if contentType != "application/json" {
		t.Errorf("expected Content-Type %q, got %q", "application/json", contentType)
	}
}

func TestSlackHTTPMethodIsPost(t *testing.T) {
	var method string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := config.SlackConfig{Enabled: true, WebhookURL: ts.URL}
	alerter := NewSlackAlerter(cfg, newTestLogger())
	alerter.SendAlert(newTestAction())

	if method != http.MethodPost {
		t.Errorf("expected HTTP method %q, got %q", http.MethodPost, method)
	}
}

// ---------------------------------------------------------------------------
// Constructor tests
// ---------------------------------------------------------------------------

func TestNewWebhookAlerter(t *testing.T) {
	cfg := config.WebhookConfig{Enabled: true, URL: "https://example.com/hook"}
	alerter := NewWebhookAlerter(cfg, newTestLogger())

	if alerter == nil {
		t.Fatal("expected non-nil WebhookAlerter")
	}
	if alerter.cfg.URL != "https://example.com/hook" {
		t.Errorf("expected URL %q, got %q", "https://example.com/hook", alerter.cfg.URL)
	}
	if alerter.client == nil {
		t.Error("expected non-nil http.Client")
	}
}

func TestNewSlackAlerter(t *testing.T) {
	cfg := config.SlackConfig{Enabled: true, WebhookURL: "https://hooks.slack.com/services/T/B/X"}
	alerter := NewSlackAlerter(cfg, newTestLogger())

	if alerter == nil {
		t.Fatal("expected non-nil SlackAlerter")
	}
	if alerter.cfg.WebhookURL != "https://hooks.slack.com/services/T/B/X" {
		t.Errorf("expected WebhookURL %q, got %q", "https://hooks.slack.com/services/T/B/X", alerter.cfg.WebhookURL)
	}
	if alerter.client == nil {
		t.Error("expected non-nil http.Client")
	}
}
