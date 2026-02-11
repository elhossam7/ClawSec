// Package gateway implements the HTTP/WebSocket control plane server.
// It serves the htmx WebUI, REST API, and SSE event stream.
package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/sentinel-agent/sentinel/internal/agent"
	"github.com/sentinel-agent/sentinel/internal/config"
	"github.com/sentinel-agent/sentinel/internal/engine"
	"github.com/sentinel-agent/sentinel/internal/logging"
	"github.com/sentinel-agent/sentinel/internal/response"
	"github.com/sentinel-agent/sentinel/internal/storage"
	"github.com/sentinel-agent/sentinel/internal/types"
)

// Server is the HTTP/WebSocket gateway for Sentinel.
type Server struct {
	cfg          config.WebConfig
	store        *storage.SQLite
	eng          *engine.Engine
	orchestrator *response.Orchestrator
	agent        *agent.Agent
	auth         *AuthManager
	templates    *template.Template
	sseClients   map[chan string]bool
	sseMu        sync.Mutex
	reqIDGen     *logging.RequestIDGenerator
	logger       zerolog.Logger
	startTime    time.Time
	httpServer   *http.Server
}

// NewServer creates a new gateway server.
func NewServer(cfg config.WebConfig, store *storage.SQLite, eng *engine.Engine, orch *response.Orchestrator, logger zerolog.Logger) *Server {
	authMgr := NewAuthManager(store.DB())

	// Ensure default admin exists on first run.
	created, err := authMgr.EnsureDefaultAdmin()
	if err != nil {
		logger.Error().Err(err).Msg("failed to ensure default admin user")
	} else if created {
		logger.Warn().Msg("created default admin user (admin/sentinel) — change password immediately")
	}

	return &Server{
		cfg:          cfg,
		store:        store,
		eng:          eng,
		orchestrator: orch,
		auth:         authMgr,
		sseClients:   make(map[chan string]bool),
		reqIDGen:     logging.NewRequestIDGenerator(),
		logger:       logger.With().Str("component", "gateway").Logger(),
		startTime:    time.Now(),
	}
}

// SetAgent wires the AI agent into the gateway for chat and analysis APIs.
func (s *Server) SetAgent(a *agent.Agent) {
	s.agent = a
}

// Start begins serving HTTP requests.
func (s *Server) Start(ctx context.Context) error {
	// Parse templates.
	tmplDir := filepath.Join("web", "templates")
	var err error
	s.templates, err = template.New("").Funcs(template.FuncMap{
		"severityBadge": severityBadge,
		"statusBadge":   statusBadge,
		"timeAgo":       timeAgo,
		"jsonMarshal":   jsonMarshal,
	}).ParseGlob(filepath.Join(tmplDir, "*.html"))
	if err != nil {
		return fmt.Errorf("parsing templates: %w", err)
	}

	mux := http.NewServeMux()

	// Static files.
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(filepath.Join("web", "static")))))

	// Public landing page.
	mux.HandleFunc("/landing", s.handleLanding)

	// Pages (htmx).
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/dashboard", s.requireAuth(s.handleDashboard))
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)
	mux.HandleFunc("/change-password", s.requireAuth(s.handleChangePassword))
	mux.HandleFunc("/approval", s.requireAuth(s.handleApprovalQueue))
	mux.HandleFunc("/rules", s.requireAuth(s.handleRules))
	mux.HandleFunc("/incidents", s.requireAuth(s.handleIncidents))
	mux.HandleFunc("/audit", s.requireAuth(s.handleAuditLog))
	mux.HandleFunc("/chat", s.requireAuth(s.handleChatPage))
	mux.HandleFunc("/agent/tools", s.requireAuth(s.handleAgentToolsPage))

	// Partials (htmx fragments).
	mux.HandleFunc("/partials/agent-status", s.requireAuth(s.handlePartialAgentStatus))

	// API endpoints.
	mux.HandleFunc("/api/approve/", s.requireAuth(s.handleAPIApprove))
	mux.HandleFunc("/api/deny/", s.requireAuth(s.handleAPIDeny))
	mux.HandleFunc("/api/rollback/", s.requireAuth(s.handleAPIRollback))
	mux.HandleFunc("/api/rules/toggle/", s.requireAuth(s.handleAPIRuleToggle))
	mux.HandleFunc("/api/health", s.handleAPIHealth)
	mux.HandleFunc("/api/health/agent", s.handleAPIAgentHealth)
	mux.HandleFunc("/api/tools", s.handleAPITools)

	// AI Agent endpoints.
	mux.HandleFunc("/api/chat", s.requireAuth(s.handleChat))
	mux.HandleFunc("/v1/stream", s.requireAuth(s.handleAgentStream))

	// Server-Sent Events for real-time updates.
	mux.HandleFunc("/api/events/stream", s.requireAuth(s.handleSSE))

	// REST API v1 for external integrations.
	s.RegisterAPIRoutes(mux)

	s.httpServer = &http.Server{
		Addr:         s.cfg.ListenAddr,
		Handler:      s.loggingMiddleware(mux),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 0, // SSE needs no write timeout
		IdleTimeout:  60 * time.Second,
	}

	s.logger.Info().Str("addr", s.cfg.ListenAddr).Msg("starting web server")

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.httpServer.Shutdown(shutCtx)
	}()

	if s.cfg.TLSCert != "" && s.cfg.TLSKey != "" {
		return s.httpServer.ListenAndServeTLS(s.cfg.TLSCert, s.cfg.TLSKey)
	}
	return s.httpServer.ListenAndServe()
}

// BroadcastEvent sends an SSE event to all connected clients.
func (s *Server) BroadcastEvent(eventType, data string) {
	s.sseMu.Lock()
	defer s.sseMu.Unlock()

	msg := fmt.Sprintf("event: %s\ndata: %s\n\n", eventType, data)
	for client := range s.sseClients {
		select {
		case client <- msg:
		default:
			// Client buffer is full, skip.
		}
	}
}

// --- Page Handlers ---

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	session, _ := s.auth.getSessionFromRequest(r)

	events, _ := s.store.GetRecentEvents(50)
	incidents, _ := s.store.GetOpenIncidents()
	pending, _ := s.store.GetPendingActions()
	eventCount, _ := s.store.EventCount()

	data := map[string]interface{}{
		"Events":         events,
		"Incidents":      incidents,
		"PendingActions": pending,
		"EventCount":     eventCount,
		"ActiveRules":    s.eng.RuleCount(),
		"Uptime":         time.Since(s.startTime).Round(time.Second),
		"CSRFToken":      "",
	}
	if session != nil {
		data["CSRFToken"] = session.CSRFToken
	}

	// If htmx partial request, render just the content.
	if r.Header.Get("HX-Request") == "true" {
		s.templates.ExecuteTemplate(w, "dashboard-content", data)
		return
	}

	s.templates.ExecuteTemplate(w, "layout", map[string]interface{}{
		"Page":    "dashboard",
		"Title":   "Dashboard",
		"Content": data,
	})
}

func (s *Server) handleApprovalQueue(w http.ResponseWriter, r *http.Request) {
	actions, _ := s.store.GetPendingActions()
	recent, _ := s.store.GetRecentActions(20)
	session, _ := s.auth.getSessionFromRequest(r)

	data := map[string]interface{}{
		"Pending":   actions,
		"Recent":    recent,
		"CSRFToken": "",
	}
	if session != nil {
		data["CSRFToken"] = session.CSRFToken
	}

	if r.Header.Get("HX-Request") == "true" {
		s.templates.ExecuteTemplate(w, "approval-content", data)
		return
	}

	s.templates.ExecuteTemplate(w, "layout", map[string]interface{}{
		"Page":    "approval",
		"Title":   "Approval Queue",
		"Content": data,
	})
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	rules := s.eng.GetRules()
	data := map[string]interface{}{
		"Rules": rules,
	}

	if r.Header.Get("HX-Request") == "true" {
		s.templates.ExecuteTemplate(w, "rules-content", data)
		return
	}

	s.templates.ExecuteTemplate(w, "layout", map[string]interface{}{
		"Page":    "rules",
		"Title":   "Detection Rules",
		"Content": data,
	})
}

func (s *Server) handleIncidents(w http.ResponseWriter, r *http.Request) {
	incidents, _ := s.store.GetAllIncidents(100)
	data := map[string]interface{}{
		"Incidents": incidents,
	}

	if r.Header.Get("HX-Request") == "true" {
		s.templates.ExecuteTemplate(w, "incidents-content", data)
		return
	}

	s.templates.ExecuteTemplate(w, "layout", map[string]interface{}{
		"Page":    "incidents",
		"Title":   "Incidents",
		"Content": data,
	})
}

func (s *Server) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	entries, _ := s.store.GetAuditLog(100)
	data := map[string]interface{}{
		"Entries": entries,
	}

	if r.Header.Get("HX-Request") == "true" {
		s.templates.ExecuteTemplate(w, "audit-content", data)
		return
	}

	s.templates.ExecuteTemplate(w, "layout", map[string]interface{}{
		"Page":    "audit",
		"Title":   "Audit Log",
		"Content": data,
	})
}

func (s *Server) handleChatPage(w http.ResponseWriter, r *http.Request) {
	agentStatus := ""
	agentProvider := ""
	toolCount := 0
	if s.agent != nil {
		health := s.agent.Health()
		agentStatus, _ = health["status"].(string)
		agentProvider, _ = health["provider"].(string)
		toolCount = len(s.agent.ListTools())
	}

	data := map[string]interface{}{
		"Tools":         s.getAgentToolsList(),
		"AgentStatus":   agentStatus,
		"AgentProvider": agentProvider,
		"ToolCount":     toolCount,
	}

	if r.Header.Get("HX-Request") == "true" {
		s.templates.ExecuteTemplate(w, "chat-content", data)
		return
	}

	s.templates.ExecuteTemplate(w, "layout", map[string]interface{}{
		"Page":    "chat",
		"Title":   "SOC Chat",
		"Content": data,
	})
}

func (s *Server) handleAgentToolsPage(w http.ResponseWriter, r *http.Request) {
	tools := s.getAgentToolsList()
	agentStatus := "offline"
	provider := "none"
	if s.agent != nil {
		health := s.agent.Health()
		agentStatus = health["status"].(string)
		if p, ok := health["provider"]; ok {
			provider = p.(string)
		}
	}

	data := map[string]interface{}{
		"Tools":         tools,
		"AgentStatus":   agentStatus,
		"AgentProvider": provider,
	}

	if r.Header.Get("HX-Request") == "true" {
		s.templates.ExecuteTemplate(w, "agent-tools-content", data)
		return
	}

	s.templates.ExecuteTemplate(w, "layout", map[string]interface{}{
		"Page":    "agent-tools",
		"Title":   "Agent Tools",
		"Content": data,
	})
}

func (s *Server) handlePartialAgentStatus(w http.ResponseWriter, r *http.Request) {
	status := "offline"
	provider := "none"
	toolCount := 0
	if s.agent != nil {
		health := s.agent.Health()
		status = health["status"].(string)
		if p, ok := health["provider"]; ok {
			provider = p.(string)
		}
		toolCount = len(s.agent.ListTools())
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<div class="info-list">
		<div class="info-item">
			<span class="info-item-label">Status</span>
			<span class="info-item-value"><span class="status-dot-sm %s"></span>%s</span>
		</div>
		<div class="info-item">
			<span class="info-item-label">Provider</span>
			<span class="info-item-value"><span class="agent-provider-badge">%s</span></span>
		</div>
		<div class="info-item">
			<span class="info-item-label">Skills</span>
			<span class="info-item-value" style="color: var(--accent);">%d</span>
		</div>
	</div>`, status, status, provider, toolCount)
}

func (s *Server) getAgentToolsList() []map[string]interface{} {
	if s.agent == nil {
		return nil
	}
	tools := s.agent.ListTools()
	result := make([]map[string]interface{}, 0, len(tools))
	for _, t := range tools {
		result = append(result, map[string]interface{}{
			"Name":        t.Name,
			"Description": t.Description,
			"Parameters":  t.InputSchema,
		})
	}
	return result
}

// handleLanding serves the public landing page.
func (s *Server) handleLanding(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	s.templates.ExecuteTemplate(w, "landing", nil)
}

// handleRoot redirects to dashboard if authenticated, otherwise shows landing.
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	// Prevent caching of this response.
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")

	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Check if user is authenticated.
	cookie, err := r.Cookie("session")
	if err == nil {
		_, valid := s.auth.ValidateSession(cookie.Value)
		if valid {
			// Authenticated user — redirect to dashboard.
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
	}

	// Not authenticated — show landing page.
	s.templates.ExecuteTemplate(w, "landing", nil)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Prevent caching.
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")

	// If already authenticated, redirect to dashboard.
	if cookie, err := r.Cookie("session"); err == nil {
		if _, valid := s.auth.ValidateSession(cookie.Value); valid {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
	}

	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		session, err := s.auth.Authenticate(username, password, r.RemoteAddr)
		if err != nil {
			s.audit("login_failed", fmt.Sprintf("webui:%s", username), fmt.Sprintf("Failed login attempt from %s: %v", r.RemoteAddr, err))
			s.templates.ExecuteTemplate(w, "login", map[string]interface{}{
				"Error": "Invalid credentials",
			})
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    session.Token,
			Path:     "/",
			HttpOnly: true,
			Secure:   s.cfg.TLSCert != "",
			SameSite: http.SameSiteStrictMode,
			MaxAge:   int(s.auth.sessionTTL.Seconds()),
		})
		s.audit("login_success", fmt.Sprintf("webui:%s", username), fmt.Sprintf("Successful login from %s", r.RemoteAddr))

		// Redirect to password change if default password.
		if s.auth.IsDefaultPassword(username) {
			http.Redirect(w, r, "/change-password", http.StatusSeeOther)
			return
		}

		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	s.templates.ExecuteTemplate(w, "login", nil)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil {
		s.auth.DestroySession(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	session, _ := s.auth.getSessionFromRequest(r)
	if session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == "POST" {
		// Validate CSRF token.
		if !s.auth.ValidateCSRF(session.Token, r.FormValue("csrf_token")) {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}

		newPassword := r.FormValue("new_password")
		confirmPassword := r.FormValue("confirm_password")

		if newPassword != confirmPassword {
			s.templates.ExecuteTemplate(w, "change-password", map[string]interface{}{
				"Error":     "Passwords do not match",
				"CSRFToken": session.CSRFToken,
			})
			return
		}

		if err := s.auth.ChangePassword(session.Username, newPassword); err != nil {
			s.templates.ExecuteTemplate(w, "change-password", map[string]interface{}{
				"Error":     err.Error(),
				"CSRFToken": session.CSRFToken,
			})
			return
		}

		s.audit("password_changed", fmt.Sprintf("webui:%s", session.Username), "Password changed successfully")
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	isDefault := s.auth.IsDefaultPassword(session.Username)
	s.templates.ExecuteTemplate(w, "change-password", map[string]interface{}{
		"CSRFToken": session.CSRFToken,
		"IsDefault": isDefault,
		"Username":  session.Username,
	})
}

// --- Audit Helpers ---

// getActor returns the "webui:<username>" actor string from the request session.
func (s *Server) getActor(r *http.Request) string {
	session, _ := s.auth.getSessionFromRequest(r)
	if session != nil {
		return fmt.Sprintf("webui:%s", session.Username)
	}
	return "webui:unknown"
}

func (s *Server) audit(action, actor, details string) {
	entry := &types.AuditEntry{
		ID:        fmt.Sprintf("aud_%d", time.Now().UnixNano()),
		Action:    action,
		Actor:     actor,
		Details:   details,
		Timestamp: time.Now(),
	}
	if err := s.store.SaveAuditEntry(entry); err != nil {
		s.logger.Error().Err(err).Str("action", action).Msg("failed to save audit entry")
	}
}

// --- API Handlers ---

func (s *Server) handleAPIApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	actor := s.getActor(r)
	actionID := r.URL.Path[len("/api/approve/"):]
	if err := s.orchestrator.Approve(actionID, actor); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.audit("action_approved", actor, fmt.Sprintf("Approved and executed action %s", actionID))
	s.BroadcastEvent("action_executed", actionID)

	// Return updated approval queue for htmx swap.
	s.handleApprovalQueue(w, r)
}

func (s *Server) handleAPIDeny(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	actor := s.getActor(r)
	actionID := r.URL.Path[len("/api/deny/"):]
	if err := s.orchestrator.Deny(actionID, actor); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.audit("action_denied", actor, fmt.Sprintf("Denied action %s", actionID))
	s.handleApprovalQueue(w, r)
}

func (s *Server) handleAPIRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	actor := s.getActor(r)
	actionID := r.URL.Path[len("/api/rollback/"):]
	if err := s.orchestrator.Rollback(actionID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.audit("action_rolledback", actor, fmt.Sprintf("Rolled back action %s", actionID))
	s.BroadcastEvent("action_rolledback", actionID)
	s.handleApprovalQueue(w, r)
}

func (s *Server) handleAPIRuleToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	actor := s.getActor(r)
	ruleID := r.URL.Path[len("/api/rules/toggle/"):]
	action := r.FormValue("action")

	var err error
	if action == "enable" {
		err = s.eng.EnableRule(ruleID)
	} else {
		err = s.eng.DisableRule(ruleID)
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.audit("rule_"+action+"d", actor, fmt.Sprintf("Rule %s %sd", ruleID, action))
	s.handleRules(w, r)
}

func (s *Server) handleAPIHealth(w http.ResponseWriter, r *http.Request) {
	pending, _ := s.store.PendingActionCount()
	open, _ := s.store.IncidentCount()

	health := types.SystemHealth{
		Uptime:        time.Since(s.startTime),
		ActiveRules:   s.eng.RuleCount(),
		PendingQueue:  pending,
		OpenIncidents: open,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

func (s *Server) handleAPIAgentHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.agent == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "disabled",
			"message": "AI agent not configured. Set ai.provider in sentinel.yaml.",
		})
		return
	}
	json.NewEncoder(w).Encode(s.agent.Health())
}

func (s *Server) handleAPITools(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.agent == nil {
		json.NewEncoder(w).Encode([]interface{}{})
		return
	}
	json.NewEncoder(w).Encode(s.agent.ListTools())
}

// --- SSE Handler ---

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	client := make(chan string, 10)
	s.sseMu.Lock()
	s.sseClients[client] = true
	s.sseMu.Unlock()

	defer func() {
		s.sseMu.Lock()
		delete(s.sseClients, client)
		s.sseMu.Unlock()
	}()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-client:
			fmt.Fprint(w, msg)
			flusher.Flush()
		}
	}
}

// --- Middleware ---

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		reqID := s.reqIDGen.Next()

		// Set request ID on response header for tracing.
		w.Header().Set("X-Request-ID", reqID)

		// Wrap response writer to capture status code.
		wrapped := &statusWriter{ResponseWriter: w, status: 200}

		next.ServeHTTP(wrapped, r)

		s.logger.Debug().
			Str("request_id", reqID).
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Int("status", wrapped.status).
			Dur("duration", time.Since(start)).
			Str("remote", r.RemoteAddr).
			Msg("request")
	})
}

// statusWriter wraps http.ResponseWriter to capture the status code.
type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (sw *statusWriter) WriteHeader(code int) {
	if !sw.wrote {
		sw.status = code
		sw.wrote = true
	}
	sw.ResponseWriter.WriteHeader(code)
}

func (sw *statusWriter) Flush() {
	if f, ok := sw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, valid := s.auth.getSessionFromRequest(r)
		if !valid || session == nil {
			if r.Header.Get("HX-Request") == "true" {
				w.Header().Set("HX-Redirect", "/login")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Validate CSRF token on state-changing requests.
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "DELETE" {
			csrfToken := r.FormValue("csrf_token")
			if csrfToken == "" {
				csrfToken = r.Header.Get("X-CSRF-Token")
			}
			if !s.auth.ValidateCSRF(session.Token, csrfToken) {
				http.Error(w, "Invalid CSRF token", http.StatusForbidden)
				return
			}
		}

		next(w, r)
	}
}

// --- Template helpers ---

func severityBadge(s types.Severity) template.HTML {
	return template.HTML(fmt.Sprintf(`<span class="severity-badge severity-%s">%s</span>`, s.String(), s.String()))
}

func statusBadge(s string) template.HTML {
	return template.HTML(fmt.Sprintf(`<span class="status-badge status-%s">%s</span>`, s, s))
}

func timeAgo(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return t.Format("Jan 2 15:04")
	}
}

func jsonMarshal(v interface{}) template.JS {
	b, _ := json.Marshal(v)
	return template.JS(b)
}

// ---------------------------------------------------------------------------
// AI Agent Handlers
// ---------------------------------------------------------------------------

// ChatRequest is the JSON body for POST /api/chat.
type ChatRequest struct {
	Message   string            `json:"message"`
	SessionID string            `json:"session_id"`
	Context   map[string]string `json:"context,omitempty"`
}

// ChatResponse is the JSON response from the chat endpoint.
type ChatResponse struct {
	Response   string   `json:"response"`
	ToolsUsed  []string `json:"tools_used,omitempty"`
	Confidence float64  `json:"confidence"`
	Error      string   `json:"error,omitempty"`
}

func (s *Server) handleChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.agent == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ChatResponse{
			Error: "AI agent not configured. Set ai.provider in sentinel.yaml.",
		})
		return
	}

	var req ChatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.SessionID == "" {
		req.SessionID = fmt.Sprintf("session_%d", time.Now().UnixNano())
	}

	s.logger.Info().Str("session", req.SessionID).Str("msg", req.Message).Msg("chat request")

	response, toolCalls, err := s.agent.Chat(r.Context(), req.Message, req.SessionID)
	if err != nil {
		s.logger.Error().Err(err).Msg("agent chat error")
		errMsg := err.Error()
		// Provide a user-friendly error for common API errors.
		if contains429(errMsg) {
			errMsg = "API rate limit exceeded. Please wait a moment and try again."
		} else if len(errMsg) > 200 {
			errMsg = errMsg[:200] + "..."
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ChatResponse{Error: errMsg})
		return
	}

	var toolNames []string
	for _, tc := range toolCalls {
		toolNames = append(toolNames, tc.ToolName)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ChatResponse{
		Response:  response,
		ToolsUsed: toolNames,
	})
}

func (s *Server) handleAgentStream(w http.ResponseWriter, r *http.Request) {
	// SSE-based streaming for agent reasoning traces.
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	client := make(chan string, 20)
	s.sseMu.Lock()
	s.sseClients[client] = true
	s.sseMu.Unlock()

	defer func() {
		s.sseMu.Lock()
		delete(s.sseClients, client)
		s.sseMu.Unlock()
	}()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-client:
			fmt.Fprint(w, msg)
			flusher.Flush()
		}
	}
}

// BroadcastAgentEvent sends an agent-specific SSE event.
func (s *Server) BroadcastAgentEvent(eventType string, data interface{}) {
	jsonData, _ := json.Marshal(data)
	s.BroadcastEvent(eventType, string(jsonData))
}

// contains429 checks if an error string contains a 429 rate limit error.
func contains429(s string) bool {
	return strings.Contains(s, "429") || strings.Contains(s, "RESOURCE_EXHAUSTED") || strings.Contains(s, "rate limit") || strings.Contains(s, "quota")
}
