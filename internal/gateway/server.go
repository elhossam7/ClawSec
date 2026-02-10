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
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/sentinel-agent/sentinel/internal/config"
	"github.com/sentinel-agent/sentinel/internal/engine"
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
	templates    *template.Template
	sseClients   map[chan string]bool
	sseMu        sync.Mutex
	logger       zerolog.Logger
	startTime    time.Time
	httpServer   *http.Server
}

// NewServer creates a new gateway server.
func NewServer(cfg config.WebConfig, store *storage.SQLite, eng *engine.Engine, orch *response.Orchestrator, logger zerolog.Logger) *Server {
	return &Server{
		cfg:          cfg,
		store:        store,
		eng:          eng,
		orchestrator: orch,
		sseClients:   make(map[chan string]bool),
		logger:       logger.With().Str("component", "gateway").Logger(),
		startTime:    time.Now(),
	}
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

	// Pages (htmx).
	mux.HandleFunc("/", s.requireAuth(s.handleDashboard))
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/approval", s.requireAuth(s.handleApprovalQueue))
	mux.HandleFunc("/rules", s.requireAuth(s.handleRules))
	mux.HandleFunc("/incidents", s.requireAuth(s.handleIncidents))
	mux.HandleFunc("/audit", s.requireAuth(s.handleAuditLog))

	// API endpoints.
	mux.HandleFunc("/api/approve/", s.requireAuth(s.handleAPIApprove))
	mux.HandleFunc("/api/deny/", s.requireAuth(s.handleAPIDeny))
	mux.HandleFunc("/api/rollback/", s.requireAuth(s.handleAPIRollback))
	mux.HandleFunc("/api/rules/toggle/", s.requireAuth(s.handleAPIRuleToggle))
	mux.HandleFunc("/api/health", s.handleAPIHealth)

	// Server-Sent Events for real-time updates.
	mux.HandleFunc("/api/events/stream", s.requireAuth(s.handleSSE))

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
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

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

	data := map[string]interface{}{
		"Pending": actions,
		"Recent":  recent,
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

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// Basic login - in production use bcrypt + TOTP.
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Default admin credentials (should be changed on first run).
		if username == "admin" && password == "sentinel" {
			http.SetCookie(w, &http.Cookie{
				Name:     "session",
				Value:    "authenticated", // Simplified - use proper session tokens
				Path:     "/",
				HttpOnly: true,
				Secure:   s.cfg.TLSCert != "",
				MaxAge:   3600 * 8,
			})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		s.templates.ExecuteTemplate(w, "login", map[string]interface{}{
			"Error": "Invalid credentials",
		})
		return
	}

	s.templates.ExecuteTemplate(w, "login", nil)
}

// --- API Handlers ---

func (s *Server) handleAPIApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	actionID := r.URL.Path[len("/api/approve/"):]
	if err := s.orchestrator.Approve(actionID, "webui:admin"); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.BroadcastEvent("action_executed", actionID)

	// Return updated approval queue for htmx swap.
	s.handleApprovalQueue(w, r)
}

func (s *Server) handleAPIDeny(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	actionID := r.URL.Path[len("/api/deny/"):]
	if err := s.orchestrator.Deny(actionID, "webui:admin"); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.handleApprovalQueue(w, r)
}

func (s *Server) handleAPIRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	actionID := r.URL.Path[len("/api/rollback/"):]
	if err := s.orchestrator.Rollback(actionID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.BroadcastEvent("action_rolledback", actionID)
	s.handleApprovalQueue(w, r)
}

func (s *Server) handleAPIRuleToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

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
		next.ServeHTTP(w, r)
		s.logger.Debug().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Dur("duration", time.Since(start)).
			Msg("request")
	})
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil || cookie.Value != "authenticated" {
			if r.Header.Get("HX-Request") == "true" {
				w.Header().Set("HX-Redirect", "/login")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
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
