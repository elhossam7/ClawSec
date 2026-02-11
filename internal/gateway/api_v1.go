package gateway

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/sentinel-agent/sentinel/internal/types"
)

// ---------------------------------------------------------------------------
// REST API v1 — External Integrations (Tier 2.9)
// ---------------------------------------------------------------------------
//
// All /api/v1/ endpoints require an API key via the X-API-Key header.
// API keys are managed independently of browser session authentication.

// APIKeyEntry stores API key metadata.
type APIKeyEntry struct {
	KeyHash   string
	Name      string
	CreatedAt time.Time
}

// RegisterAPIRoutes wires up the /api/v1/ REST endpoints on the given mux.
func (s *Server) RegisterAPIRoutes(mux *http.ServeMux) {
	// Health / info endpoints (no auth).
	mux.HandleFunc("/api/v1/health", s.handleV1Health)

	// Protected endpoints.
	mux.HandleFunc("/api/v1/incidents", s.requireAPIKey(s.handleV1Incidents))
	mux.HandleFunc("/api/v1/incidents/", s.requireAPIKey(s.handleV1IncidentByID))
	mux.HandleFunc("/api/v1/events", s.requireAPIKey(s.handleV1Events))
	mux.HandleFunc("/api/v1/rules", s.requireAPIKey(s.handleV1Rules))
	mux.HandleFunc("/api/v1/actions", s.requireAPIKey(s.handleV1Actions))
	mux.HandleFunc("/api/v1/actions/approve/", s.requireAPIKey(s.handleV1Approve))
	mux.HandleFunc("/api/v1/actions/deny/", s.requireAPIKey(s.handleV1Deny))
}

// --- API Key Authentication ---

// requireAPIKey validates the X-API-Key header.
func (s *Server) requireAPIKey(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			writeAPIError(w, http.StatusUnauthorized, "EAUTH-001", "Missing X-API-Key header")
			return
		}

		if !s.validateAPIKey(apiKey) {
			writeAPIError(w, http.StatusForbidden, "EAUTH-002", "Invalid API key")
			return
		}

		next(w, r)
	}
}

// validateAPIKey checks if the given API key is valid.
func (s *Server) validateAPIKey(key string) bool {
	// Look up stored keys from the database.
	rows, err := s.store.DB().Query("SELECT key_hash FROM api_keys WHERE revoked = 0")
	if err != nil {
		// If the table doesn't exist yet, fall back to session key.
		if s.cfg.SessionKey != "" {
			return subtle.ConstantTimeCompare([]byte(key), []byte(s.cfg.SessionKey)) == 1
		}
		return false
	}
	defer rows.Close()

	for rows.Next() {
		var storedHash string
		if err := rows.Scan(&storedHash); err != nil {
			continue
		}
		// Constant-time comparison of hex-encoded SHA256 hash.
		keyHash := hashAPIKey(key)
		if subtle.ConstantTimeCompare([]byte(keyHash), []byte(storedHash)) == 1 {
			return true
		}
	}

	// Fall back to session key from config.
	if s.cfg.SessionKey != "" {
		return subtle.ConstantTimeCompare([]byte(key), []byte(s.cfg.SessionKey)) == 1
	}
	return false
}

// hashAPIKey creates a hex-encoded SHA256 hash of the API key.
func hashAPIKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

// GenerateAPIKey creates a new random API key.
func GenerateAPIKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "sk-" + hex.EncodeToString(b), nil
}

// --- API Response Helpers ---

type apiResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   *apiError   `json:"error,omitempty"`
	Meta    *apiMeta    `json:"meta,omitempty"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type apiMeta struct {
	Total  int    `json:"total,omitempty"`
	Limit  int    `json:"limit,omitempty"`
	Offset int    `json:"offset,omitempty"`
	ReqID  string `json:"request_id,omitempty"`
}

func writeAPISuccess(w http.ResponseWriter, data interface{}, meta *apiMeta) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(apiResponse{
		Success: true,
		Data:    data,
		Meta:    meta,
	})
}

func writeAPIError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(apiResponse{
		Success: false,
		Error:   &apiError{Code: code, Message: message},
	})
}

// --- V1 Handlers ---

func (s *Server) handleV1Health(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeAPIError(w, http.StatusMethodNotAllowed, "EVAL-001", "Method not allowed")
		return
	}

	pending, _ := s.store.PendingActionCount()
	open, _ := s.store.IncidentCount()
	events, _ := s.store.EventCount()

	health := map[string]interface{}{
		"status":          "running",
		"version":         "dev",
		"uptime_seconds":  int(time.Since(s.startTime).Seconds()),
		"active_rules":    s.eng.RuleCount(),
		"pending_actions": pending,
		"open_incidents":  open,
		"total_events":    events,
		"ai_enabled":      s.agent != nil,
	}

	writeAPISuccess(w, health, nil)
}

func (s *Server) handleV1Incidents(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeAPIError(w, http.StatusMethodNotAllowed, "EVAL-001", "Method not allowed")
		return
	}

	limit := parseQueryInt(r, "limit", 50)
	if limit > 200 {
		limit = 200
	}

	incidents, err := s.store.GetAllIncidents(limit)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "ESTO-001", "Failed to fetch incidents")
		return
	}

	writeAPISuccess(w, incidents, &apiMeta{Total: len(incidents), Limit: limit})
}

func (s *Server) handleV1IncidentByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeAPIError(w, http.StatusMethodNotAllowed, "EVAL-001", "Method not allowed")
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/incidents/")
	if id == "" {
		writeAPIError(w, http.StatusBadRequest, "EVAL-002", "Missing incident ID")
		return
	}

	incident, err := s.store.GetIncident(id)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "ESTO-002", fmt.Sprintf("Incident %s not found", id))
		return
	}

	writeAPISuccess(w, incident, nil)
}

func (s *Server) handleV1Events(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeAPIError(w, http.StatusMethodNotAllowed, "EVAL-001", "Method not allowed")
		return
	}

	limit := parseQueryInt(r, "limit", 50)
	if limit > 200 {
		limit = 200
	}

	events, err := s.store.GetRecentEvents(limit)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "ESTO-001", "Failed to fetch events")
		return
	}

	writeAPISuccess(w, events, &apiMeta{Total: len(events), Limit: limit})
}

func (s *Server) handleV1Rules(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeAPIError(w, http.StatusMethodNotAllowed, "EVAL-001", "Method not allowed")
		return
	}

	rules := s.eng.GetRules()

	type ruleInfo struct {
		ID          string   `json:"id"`
		Title       string   `json:"title"`
		Severity    string   `json:"severity"`
		Enabled     bool     `json:"enabled"`
		Description string   `json:"description"`
		Tags        []string `json:"tags,omitempty"`
	}

	var result []ruleInfo
	for _, r := range rules {
		result = append(result, ruleInfo{
			ID:          r.ID,
			Title:       r.Title,
			Severity:    r.Severity.String(),
			Enabled:     r.Enabled,
			Description: r.Description,
			Tags:        r.Tags,
		})
	}

	writeAPISuccess(w, result, &apiMeta{Total: len(result)})
}

func (s *Server) handleV1Actions(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeAPIError(w, http.StatusMethodNotAllowed, "EVAL-001", "Method not allowed")
		return
	}

	status := r.URL.Query().Get("status")
	var actions []types.ResponseAction
	var err error

	switch status {
	case "pending", "":
		actions, err = s.store.GetPendingActions()
	default:
		actions, err = s.store.GetRecentActions(50)
	}

	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "ESTO-001", "Failed to fetch actions")
		return
	}

	writeAPISuccess(w, actions, &apiMeta{Total: len(actions)})
}

func (s *Server) handleV1Approve(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeAPIError(w, http.StatusMethodNotAllowed, "EVAL-001", "Method not allowed")
		return
	}

	actionID := strings.TrimPrefix(r.URL.Path, "/api/v1/actions/approve/")
	if actionID == "" {
		writeAPIError(w, http.StatusBadRequest, "EVAL-002", "Missing action ID")
		return
	}

	actor := "api:external"
	if err := s.orchestrator.Approve(actionID, actor); err != nil {
		writeAPIError(w, http.StatusBadRequest, "ERULE-001", err.Error())
		return
	}

	s.audit("action_approved", actor, fmt.Sprintf("Approved action %s via REST API", actionID))
	writeAPISuccess(w, map[string]string{"action_id": actionID, "status": "approved"}, nil)
}

func (s *Server) handleV1Deny(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeAPIError(w, http.StatusMethodNotAllowed, "EVAL-001", "Method not allowed")
		return
	}

	actionID := strings.TrimPrefix(r.URL.Path, "/api/v1/actions/deny/")
	if actionID == "" {
		writeAPIError(w, http.StatusBadRequest, "EVAL-002", "Missing action ID")
		return
	}

	actor := "api:external"
	if err := s.orchestrator.Deny(actionID, actor); err != nil {
		writeAPIError(w, http.StatusBadRequest, "ERULE-001", err.Error())
		return
	}

	s.audit("action_denied", actor, fmt.Sprintf("Denied action %s via REST API", actionID))
	writeAPISuccess(w, map[string]string{"action_id": actionID, "status": "denied"}, nil)
}

// parseQueryInt extracts an integer query parameter with a default.
func parseQueryInt(r *http.Request, key string, def int) int {
	val := r.URL.Query().Get(key)
	if val == "" {
		return def
	}
	var n int
	if _, err := fmt.Sscanf(val, "%d", &n); err != nil {
		return def
	}
	if n < 1 {
		return def
	}
	return n
}
