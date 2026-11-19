package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/eraser-privacy/eraser/internal/broker"
	"github.com/eraser-privacy/eraser/internal/browser"
	"github.com/eraser-privacy/eraser/internal/config"
	"github.com/eraser-privacy/eraser/internal/email"
	"github.com/eraser-privacy/eraser/internal/history"
	"github.com/eraser-privacy/eraser/internal/inbox"
	"github.com/eraser-privacy/eraser/internal/sendplan"
	emaTemplate "github.com/eraser-privacy/eraser/internal/template"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

//go:embed static/*
var staticFS embed.FS

//go:embed templates/*
var templatesFS embed.FS

const (
	defaultRateLimit  = 30
	defaultRateWindow = time.Minute
	defaultSessionTTL = 30 * time.Minute
)

type RateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	limit    int
	window   time.Duration
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
	go rl.cleanupLoop()
	return rl
}

func (rl *RateLimiter) filterRecent(times []time.Time, windowStart time.Time) []time.Time {
	n := 0
	for _, t := range times {
		if t.After(windowStart) {
			times[n] = t
			n++
		}
	}
	return times[:n]
}

func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	recent := rl.filterRecent(rl.requests[key], now.Add(-rl.window))

	if len(recent) >= rl.limit {
		rl.requests[key] = recent
		return false
	}
	rl.requests[key] = append(recent, now)
	return true
}

func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		windowStart := time.Now().Add(-rl.window)
		for key, times := range rl.requests {
			recent := rl.filterRecent(times, windowStart)
			if len(recent) == 0 {
				delete(rl.requests, key)
			} else {
				rl.requests[key] = recent
			}
		}
		rl.mu.Unlock()
	}
}

type Server struct {
	config       *config.Config
	configPath   string
	brokerDB     *broker.BrokerDatabase
	historyStore *history.Store
	tmplEngine   *emaTemplate.Engine
	templates    map[string]*template.Template
	httpServer   *http.Server
	port         int
	sessions     *SessionStore
	rateLimiter  *RateLimiter
	jobManager   *JobManager
	// sendMu makes "check no job is running, plan from history, start" one
	// step for "Send all" and "Send", so two requests can't plan from the
	// same history and email a broker twice.
	sendMu        sync.Mutex
	newSender     func(config.EmailConfig) (email.Sender, error) // replaced in tests
	screenshotDir string
}

func NewServer(port int, cfg *config.Config, configPath string, brokerDB *broker.BrokerDatabase, historyStore *history.Store, tmplEngine *emaTemplate.Engine) (*Server, error) {
	s := &Server{
		config:        cfg,
		configPath:    configPath,
		brokerDB:      brokerDB,
		historyStore:  historyStore,
		tmplEngine:    tmplEngine,
		port:          port,
		sessions:      NewSessionStore(defaultSessionTTL),
		rateLimiter:   NewRateLimiter(defaultRateLimit, defaultRateWindow),
		jobManager:    NewJobManager(),
		newSender:     email.NewSender,
		screenshotDir: defaultScreenshotDir(),
	}

	tmpl, err := s.parseTemplates()
	if err != nil {
		return nil, fmt.Errorf("failed to parse templates: %w", err)
	}
	s.templates = tmpl
	return s, nil
}

// parseTemplates loads and parses all HTML templates
// Each page gets its own template set to avoid "content" block conflicts
func (s *Server) parseTemplates() (map[string]*template.Template, error) {
	funcs := template.FuncMap{
		"formatTime": func(t time.Time) string {
			return t.Format("Jan 2, 2006 3:04 PM")
		},
		"formatDate": func(t time.Time) string {
			return t.Format("Jan 2, 2006")
		},
		"add": func(a, b int) int {
			return a + b
		},
	}

	// Read layout template
	layoutContent, err := templatesFS.ReadFile("templates/layout.html")
	if err != nil {
		return nil, fmt.Errorf("failed to read layout template: %w", err)
	}

	// Read all partial templates
	var partials []string
	partialTemplates := make(map[string]string)
	err = fs.WalkDir(templatesFS, "templates/partials", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".html") {
			return err
		}
		content, err := templatesFS.ReadFile(path)
		if err != nil {
			return err
		}
		partials = append(partials, string(content))
		// Also save for standalone partial templates
		name := path[len("templates/"):]
		partialTemplates[name] = string(content)
		return nil
	})
	if err != nil && !strings.Contains(err.Error(), "file does not exist") {
		return nil, fmt.Errorf("failed to read partials: %w", err)
	}

	// Map to hold all page templates
	templates := make(map[string]*template.Template)

	// Walk through all page templates and create separate template sets
	err = fs.WalkDir(templatesFS, "templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// Skip directories, partials, and layout
		if d.IsDir() || strings.Contains(path, "/partials/") || path == "templates/layout.html" {
			return nil
		}
		if !strings.HasSuffix(path, ".html") {
			return nil
		}

		content, err := templatesFS.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read template %s: %w", path, err)
		}

		// Create a new template for this page
		name := path[len("templates/"):]
		pageTmpl := template.New(name).Funcs(funcs)

		// Parse layout first
		_, err = pageTmpl.Parse(string(layoutContent))
		if err != nil {
			return fmt.Errorf("failed to parse layout for %s: %w", name, err)
		}

		// Parse partials
		for _, partial := range partials {
			_, err = pageTmpl.Parse(partial)
			if err != nil {
				return fmt.Errorf("failed to parse partial for %s: %w", name, err)
			}
		}

		// Parse the page content (this defines "content" block for this specific page)
		_, err = pageTmpl.Parse(string(content))
		if err != nil {
			return fmt.Errorf("failed to parse template %s: %w", name, err)
		}

		// Store in map
		templates[name] = pageTmpl

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Add partial templates as standalone templates (for HTMX responses)
	for name, content := range partialTemplates {
		partialTmpl := template.New(name).Funcs(funcs)
		_, err = partialTmpl.Parse(content)
		if err != nil {
			return nil, fmt.Errorf("failed to parse partial %s: %w", name, err)
		}
		templates[name] = partialTmpl
	}

	return templates, nil
}

// Start starts the web server and opens the browser
func (s *Server) Start() error {
	router := s.setupRouter()

	s.httpServer = &http.Server{
		Addr:              fmt.Sprintf("127.0.0.1:%d", s.port),
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// Longer than the slowest handler (inbox scan allows 60s), so its
		// response isn't cut off mid-write.
		WriteTimeout: 90 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	removeLegacyJobFile()

	// Open browser after a short delay
	go func() {
		time.Sleep(500 * time.Millisecond)
		url := fmt.Sprintf("http://localhost:%d", s.port)
		openBrowser(url)
	}()

	fmt.Printf("Starting Eraser web UI at http://localhost:%d\n", s.port)
	fmt.Println("Press Ctrl+C to stop")

	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// setupRouter configures all routes
func (s *Server) setupRouter() *chi.Mux {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Recoverer)
	r.Use(allowHosts(fmt.Sprintf("localhost:%d", s.port), fmt.Sprintf("127.0.0.1:%d", s.port)))
	r.Use(securityHeaders)
	// Reject cross-origin state-changing requests using the browser's
	// Sec-Fetch-Site / Origin headers; no tokens needed.
	r.Use(http.NewCrossOriginProtection().Handler)
	r.Use(middleware.Logger)
	r.Use(middleware.Compress(5))

	// Static files
	staticSub, _ := fs.Sub(staticFS, "static")
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	// Routes
	r.Get("/", s.handleDashboard)
	r.Get("/brokers", s.handleBrokers)
	r.Get("/history", s.handleHistory)
	r.Get("/settings", s.handleSettings)
	r.Post("/settings/inbox", s.handleSettingsInbox)
	r.Post("/settings/disclose", s.handleSettingsDisclose)
	r.Get("/pipeline", s.handlePipeline)
	r.Get("/tasks", s.handleTasks)
	r.Get("/tasks/{taskID}", s.handleTaskDetail)
	r.Get("/tasks/{taskID}/helper", s.handleTaskHelper)
	r.Post("/tasks/{taskID}/opened", s.handleTaskOpened)
	r.Post("/tasks/{taskID}/complete", s.handleTaskComplete)
	r.Post("/tasks/{taskID}/skip", s.handleTaskSkip)
	r.Get("/screenshots/{name}", s.handleScreenshot)
	r.Get("/forms", s.handleForms)
	r.Post("/forms/{brokerID}/complete", s.handleFormComplete)
	r.Post("/forms/{brokerID}/skip", s.handleFormSkip)

	// Setup wizard routes
	r.Route("/setup", func(r chi.Router) {
		r.Get("/", s.handleSetupWelcome)
		r.Get("/profile", s.handleSetupProfile)
		r.Post("/profile", s.handleSetupProfile)
		r.Get("/email", s.handleSetupEmail)
		r.Post("/email", s.handleSetupEmail)
		r.Get("/test", s.handleSetupTest)
		r.Post("/test/send", s.handleSetupTestSend)
		r.Get("/complete", s.handleSetupComplete)
	})

	// API routes (for HTMX)
	r.Route("/api", func(r chi.Router) {
		r.Get("/stats", s.handleAPIStats)
		r.Get("/brokers", s.handleAPIBrokers)
		r.Get("/history", s.handleAPIHistory)
		r.Delete("/history/failed", s.handleAPIDeleteFailed)
		r.Post("/send/{brokerID}", s.handleAPISendOne)
		r.Post("/send-all", s.handleAPISendAll)
		r.Get("/job/active", s.handleAPIJobActive)
		r.Get("/job/{jobID}/status", s.handleAPIJobStatus)
		r.Post("/job/{jobID}/cancel", s.handleAPIJobCancel)
		r.Get("/pipeline/stats", s.handleAPIPipelineStats)
		r.Get("/pipeline/responses", s.handleAPIResponses)
		r.Get("/pipeline/tasks", s.handleAPITasks)
		r.Post("/inbox/scan", s.handleAPIInboxScan)
		r.Post("/inbox/rescan", s.handleAPIInboxRescan)
		r.Post("/inbox/reclassify", s.handleAPIReclassify)
	})

	return r
}

// allowHosts rejects requests whose Host header isn't one of ours. The server
// only listens on 127.0.0.1, but a malicious site can point its own domain at
// 127.0.0.1 (DNS rebinding) and read responses as same-origin. Its Host header
// still carries the attacker's domain, so this blocks it.
func allowHosts(hosts ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		allowed[strings.ToLower(h)] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !allowed[strings.ToLower(r.Host)] {
				http.Error(w, "Forbidden: unexpected Host header", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// securityHeaders adds security headers to all responses
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")

		// Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Control referrer information
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Content Security Policy: everything is served locally; no third
		// parties. Scripts only from /static (all page behavior is in
		// static/js/app.js), so injected HTML can't run script. Inline styles
		// are still allowed: templates use style attributes.
		csp := "default-src 'self'; " +
			"script-src 'self'; " +
			"style-src 'self' 'unsafe-inline'; " +
			"img-src 'self' data:; " +
			"font-src 'self'; " +
			"connect-src 'self'; " +
			"object-src 'none'; " +
			"frame-ancestors 'none'; " +
			"form-action 'self'; " +
			"base-uri 'self'"
		w.Header().Set("Content-Security-Policy", csp)

		// Prevent caching of sensitive pages - credentials should never be cached
		// Static files are excluded from this via separate cache headers
		if !strings.HasPrefix(r.URL.Path, "/static/") {
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
		}

		// Disable unnecessary browser features
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")

		next.ServeHTTP(w, r)
	})
}

// openBrowser opens the default browser to the specified URL
func openBrowser(url string) {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
		args = []string{url}
	case "linux":
		cmd = "xdg-open"
		args = []string{url}
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start", url}
	default:
		return
	}

	if err := exec.Command(cmd, args...).Start(); err != nil { //nolint:gosec // G204: fixed per-OS opener with our own localhost URL
		log.Printf("Could not open a browser (%v); visit %s", err, url)
	}
}

// Handler implementations

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	// Check if config exists, redirect to setup if not
	if s.config == nil || s.config.Profile.FirstName == "" {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}

	stats := s.getStats()
	progress := percent(stats.Sent, stats.TotalBrokers)
	data := map[string]interface{}{
		"Title":         "Dashboard",
		"Profile":       s.config.Profile,
		"BrokerCount":   len(s.brokerDB.Brokers),
		"RecentHistory": s.getRecentHistory(10),
		"Stats":         stats,
		// The progress ring's circle has circumference 283 (r=45).
		"ProgressPercent": progress,
		"ProgressOffset":  283 - 283*progress/100,
		"PipelineStats":   s.getPipelineStats(),
	}

	s.render(w, "dashboard.html", data)
}

func (s *Server) handleBrokers(w http.ResponseWriter, r *http.Request) {
	search := r.URL.Query().Get("search")
	category := r.URL.Query().Get("category")
	region := r.URL.Query().Get("region")
	status := r.URL.Query().Get("status")

	brokers := s.getBrokersWithStatus(search, category, region, status)

	dailyLimit := config.DefaultDailyLimit
	if s.config != nil {
		dailyLimit = s.config.Options.EffectiveDailyLimit()
	}

	data := map[string]interface{}{
		"DailyLimit": dailyLimit,
		"Title":      "Data Brokers",
		"Brokers":    brokers,
		"Categories": s.getUniqueCategories(),
		"Regions":    s.getUniqueRegions(),
		"Search":     search,
		"Category":   category,
		"Region":     region,
		"Status":     status,
		"Total":      len(s.brokerDB.Brokers),
		"Filtered":   len(brokers),
	}
	s.render(w, "brokers.html", data)
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	statusFilter := r.URL.Query().Get("status")
	allHistory := s.getRecentHistory(1000)

	// Filter by status if specified
	var filteredHistory []history.Record
	if statusFilter == "sent" || statusFilter == "failed" {
		for _, h := range allHistory {
			if string(h.Status) == statusFilter {
				filteredHistory = append(filteredHistory, h)
			}
		}
	} else {
		filteredHistory = allHistory
	}

	sent, failed := 0, 0
	for _, h := range filteredHistory {
		if h.Status == history.StatusSent {
			sent++
		} else {
			failed++
		}
	}
	data := map[string]interface{}{
		"Title":        "History",
		"History":      filteredHistory,
		"StatusFilter": statusFilter,
		"SentCount":    sent,
		"FailedCount":  failed,
		"SuccessRate":  percent(sent, sent+failed),
	}
	s.render(w, "history.html", data)
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	s.renderSettings(w, nil)
}

// renderSettings renders the settings page with the current config plus
// any extra template data (e.g. a status message).
func (s *Server) renderSettings(w http.ResponseWriter, extra map[string]interface{}) {
	var disclose config.Disclosure
	if s.config != nil {
		disclose, _ = s.config.Options.Disclosure() // invalid values render as unchecked
	}
	data := map[string]interface{}{
		"Title":      "Settings",
		"Config":     s.config,
		"Disclosure": disclose,
	}
	for k, v := range extra {
		data[k] = v
	}
	s.render(w, "settings.html", data)
}

// handleSettingsDisclose saves which optional profile fields go into emails.
func (s *Server) handleSettingsDisclose(w http.ResponseWriter, r *http.Request) {
	msg := func(text string, ok bool) {
		s.renderSettings(w, map[string]interface{}{"DiscloseMessage": text, "DiscloseSuccess": ok})
	}
	if err := r.ParseForm(); err != nil {
		msg("Failed to parse form", false)
		return
	}
	if s.config == nil {
		msg("Complete setup first", false)
		return
	}
	disclose, err := config.ParseDisclosure(r.Form["disclose"])
	if err != nil {
		msg(err.Error(), false)
		return
	}

	updated := *s.config
	updated.Options.Disclose = disclose.Values()
	if err := config.Save(s.configPath, &updated); err != nil {
		msg("Failed to save configuration: "+err.Error(), false)
		return
	}
	s.config = &updated
	msg("Saved. Emails will include: "+strings.Join(disclose.Fields(), ", ")+".", true)
}

func (s *Server) handleSettingsInbox(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderSettingsWithMessage(w, r, "Failed to parse form", false)
		return
	}

	email := strings.TrimSpace(r.FormValue("inbox_email"))
	password := strings.TrimSpace(r.FormValue("inbox_password"))

	if s.config == nil {
		s.config = &config.Config{}
	}
	inbox := s.config.Inbox

	// The page never shows the saved password, so a blank field means "keep
	// it", but only for the same account.
	if password == "" && inbox.Password != "" && strings.EqualFold(email, inbox.Email) {
		password = inbox.Password
	}
	if email == "" || password == "" {
		s.renderSettingsWithMessage(w, r, "Email and password are required", false)
		return
	}

	// Update only the fields this form owns; keep folder and archive settings.
	inbox.Enabled = true
	inbox.Provider = "gmail"
	inbox.Email = email
	inbox.Password = password
	if inbox.Server == "" {
		inbox.Server, inbox.Port = "imap.gmail.com", 993
	}
	if inbox.Folder == "" {
		inbox.Folder = "INBOX"
	}
	s.config.Inbox = inbox

	// Save config
	if err := config.Save(s.configPath, s.config); err != nil {
		s.renderSettingsWithMessage(w, r, "Failed to save configuration: "+err.Error(), false)
		return
	}

	s.renderSettingsWithMessage(w, r, "Inbox monitoring enabled successfully!", true)
}

func (s *Server) renderSettingsWithMessage(w http.ResponseWriter, r *http.Request, message string, success bool) {
	s.renderSettings(w, map[string]interface{}{"InboxMessage": message, "InboxSuccess": success})
}

// API handlers

func (s *Server) handleAPIStats(w http.ResponseWriter, r *http.Request) {
	stats := s.getStats()
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"total_brokers":%d,"sent":%d,"failed":%d}`, stats.TotalBrokers, stats.Sent, stats.Failed)
}

func (s *Server) handleAPIBrokers(w http.ResponseWriter, r *http.Request) {
	search := r.URL.Query().Get("search")
	category := r.URL.Query().Get("category")
	region := r.URL.Query().Get("region")
	status := r.URL.Query().Get("status")

	brokers := s.getBrokersWithStatus(search, category, region, status)

	// Returns broker list as HTML fragment for HTMX
	s.renderPartial(w, "partials/broker-list.html", map[string]interface{}{
		"Brokers":  brokers,
		"Filtered": len(brokers),
		"Total":    len(s.brokerDB.Brokers),
	})
}

func (s *Server) handleAPIHistory(w http.ResponseWriter, r *http.Request) {
	// Returns history as HTML fragment for HTMX
	s.renderPartial(w, "partials/history-list.html", map[string]interface{}{
		"History": s.getRecentHistory(50),
	})
}

func (s *Server) handleAPIDeleteFailed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if s.historyStore == nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Database not available"})
		return
	}

	deleted, err := s.historyStore.DeleteByStatus(history.StatusFailed)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"deleted": deleted,
		"message": fmt.Sprintf("Deleted %d failed records", deleted),
	})
}

func (s *Server) handleAPISendOne(w http.ResponseWriter, r *http.Request) {
	// Rate limiting - prevent abuse of email sending
	if !s.rateLimiter.Allow("send") {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`<span class="text-yellow-600">Rate limit exceeded. Please wait a moment before sending more emails.</span>`))
		return
	}

	brokerID := chi.URLParam(r, "brokerID")

	br := s.brokerDB.FindByID(brokerID)
	if br == nil {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`<span class="text-red-600">Broker not found</span>`))
		return
	}
	if !br.EmailAccepted() {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`<span class="text-red-600">This broker does not process emailed requests. Use its opt-out form.</span>`))
		return
	}

	if s.config == nil || s.config.Email.Provider == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`<span class="text-red-600">Email not configured. <a href="/setup" class="underline">Configure now</a></span>`))
		return
	}

	// Held through the send, so the plan below can't go stale.
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.jobManager.GetActive() != nil {
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`<span class="text-yellow-600">A send job is running; wait for it to finish.</span>`))
		return
	}

	d, disclose, err := s.deliverer()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, `<span class="text-red-600">Error: %s</span>`, template.HTMLEscapeString(err.Error()))
		return
	}

	// Same rules as "Send all" and the CLI: config filters, resend window, daily cap.
	plan, err := sendplan.ForConfig([]broker.Broker{*br}, s.config.Options, s.historyStore, time.Now(), 0, false)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintf(w, `<span class="text-red-600">Error: %s</span>`, template.HTMLEscapeString(err.Error()))
		return
	}
	if len(plan.Send) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, `<span class="text-yellow-600">%s</span>`, template.HTMLEscapeString(skipReason(plan, s.config.Options)))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	record, err := d.Deliver(ctx, disclose, *br)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintf(w, `<span class="text-red-600">Error: %s</span>`, template.HTMLEscapeString(err.Error()))
		return
	}

	if record.Status == history.StatusSent {
		w.Write([]byte(`<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">Sent</span>`))
	} else {
		_, _ = fmt.Fprintf(w, `<span class="text-red-600" title="%s">Failed</span>`, template.HTMLEscapeString(record.Error))
	}
}

// newInboxMonitor creates a monitor that can also match replies to sent
// requests by In-Reply-To.
func (s *Server) newInboxMonitor() *inbox.Monitor {
	m := inbox.NewMonitor(s.config.Inbox, s.brokerDB.Brokers)
	if s.historyStore != nil {
		if ids, err := s.historyStore.SentMessageIDs(); err == nil {
			m.SetSentMessageIDs(ids)
		}
	}
	return m
}

// writeUnverifiedNotice explains, in a scan result, that without a known
// authserv-id no email counts as verified.
func writeUnverifiedNotice(w http.ResponseWriter, m *inbox.Monitor) {
	if m.VerifiesSenders() {
		return
	}
	_, _ = w.Write([]byte(`
		<div class="bg-yellow-100 border border-yellow-400 text-yellow-800 px-4 py-3 rounded mb-2">
			<strong>Can't verify senders.</strong> Set <code>inbox.authserv_id</code> in config.yaml
			(see config.example.yaml). Until then, links in broker email are ignored.
		</div>
	`))
}

// deliverer builds the shared send path from the current config.
func (s *Server) deliverer() (sendplan.Deliverer, config.Disclosure, error) {
	if s.historyStore == nil {
		return sendplan.Deliverer{}, config.Disclosure{}, fmt.Errorf("history database not available")
	}
	disclose, err := s.config.Options.Disclosure()
	if err != nil {
		return sendplan.Deliverer{}, config.Disclosure{}, err
	}
	sender, err := s.newSender(s.config.Email)
	if err != nil {
		return sendplan.Deliverer{}, config.Disclosure{}, err
	}
	return sendplan.Deliverer{Config: s.config, Engine: s.tmplEngine, Sender: sender, Store: s.historyStore}, disclose, nil
}

// skipReason explains why a plan has nothing to send.
func skipReason(plan sendplan.Plan, opts config.Options) string {
	switch {
	case len(plan.SkippedRecent) > 0 && plan.Deferred == 0:
		return fmt.Sprintf("Already sent within the last %d days (resend_after_days).", opts.EffectiveResendAfterDays())
	case plan.Deferred > 0:
		return fmt.Sprintf("Daily limit of %d emails per 24 hours reached (%d sent). Try again later.", opts.EffectiveDailyLimit(), plan.SentInWindow)
	default:
		return "Nothing to send: excluded by your settings (regions or excluded_brokers)."
	}
}

func (s *Server) handleAPISendAll(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	writeErr := func(code int, msg string) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
	}

	// Rate limiting - prevent abuse of bulk email sending
	if !s.rateLimiter.Allow("send-all") {
		writeErr(http.StatusTooManyRequests, "Rate limit exceeded. Please wait before sending another batch.")
		return
	}

	// Checking for a running job, planning and starting the job is one step
	// (see sendMu). A job records each send before it finishes, so a plan
	// made after it ends sees those sends.
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if activeJob := s.jobManager.GetActive(); activeJob != nil {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error":  "A send job is already in progress",
			"job_id": activeJob.ID,
		})
		return
	}

	if s.config == nil || s.config.Email.Provider == "" {
		writeErr(http.StatusBadRequest, "Email not configured. Please configure email settings first.")
		return
	}

	// Get filter parameters from form
	search := r.FormValue("search")
	category := r.FormValue("category")
	region := r.FormValue("region")
	status := r.FormValue("status")

	// If no status filter specified, default to pending (never sent)
	if status == "" {
		status = "pending"
	}

	var candidates []broker.Broker
	for _, b := range s.getBrokersWithStatus(search, category, region, status) {
		candidates = append(candidates, b.Broker)
	}

	d, disclose, err := s.deliverer()
	if err != nil {
		writeErr(http.StatusBadRequest, err.Error())
		return
	}

	// Same rules as the CLI: config filters, resend window, daily cap.
	plan, err := sendplan.ForConfig(candidates, s.config.Options, s.historyStore, time.Now(), 0, false)
	if err != nil {
		writeErr(http.StatusInternalServerError, err.Error())
		return
	}
	if len(plan.Send) == 0 {
		writeErr(http.StatusBadRequest, skipReason(plan, s.config.Options))
		return
	}

	job := s.jobManager.Create(len(plan.Send))
	job.SetDailyLimit(s.config.Options.EffectiveDailyLimit(), plan.SentInWindow)
	go s.processSendJob(job, plan.Send, d, disclose)

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"job_id":         job.ID,
		"total":          len(plan.Send),
		"skipped_recent": len(plan.SkippedRecent),
		"deferred":       plan.Deferred,
	})
}

// processSendJob runs in a background goroutine. The plan already applied the
// daily cap and resend rules; every send goes through the shared Deliverer.
func (s *Server) processSendJob(job *Job, brokers []broker.Broker, d sendplan.Deliverer, disclose config.Disclosure) {
	sent, failed := 0, 0
	rateLimit := time.Duration(s.config.Options.RateLimitMs) * time.Millisecond
	if rateLimit <= 0 {
		rateLimit = 2 * time.Second
	}

	for i, b := range brokers {
		if job.IsCancelled() {
			break
		}
		job.Update(sent, failed, b.Name)

		ctx, cancel := context.WithTimeout(job.Context(), 30*time.Second)
		record, err := d.Deliver(ctx, disclose, b)
		cancel()
		if err != nil {
			// Without a history record the send would be repeated, so stop.
			job.Update(sent, failed, "")
			job.StopWithError("history", fmt.Sprintf("Stopped: the email to %s may have been sent, but it couldn't be "+
				"recorded in history, so Eraser can't tell it was sent. Check your Sent folder before sending again. (%v)", b.Name, err))
			log.Printf("Job stopped: %v", err)
			return
		}

		if record.Status == history.StatusSent {
			sent++
			job.ResetAuthFailures()
		} else {
			failed++
			if strings.Contains(strings.ToLower(record.Error), "auth") && job.RecordAuthFailure() {
				job.Update(sent, failed, "")
				job.StopWithError("auth", "Stopped due to repeated authentication failures. Your email provider may have rate-limited or blocked your account. Please check your email settings and try again later.")
				log.Printf("Job stopped: repeated auth failures after %d sent, %d failed", sent, failed)
				return
			}
		}
		job.Update(sent, failed, b.Name)

		if i < len(brokers)-1 {
			select {
			case <-job.Context().Done():
			case <-time.After(rateLimit):
			}
		}
	}

	job.Complete()
}

// Helper methods

// percent returns part/total as a whole percentage, or 0 when total is 0.
func percent(part, total int) int {
	if total == 0 {
		return 0
	}
	return int(math.Round(float64(part) * 100 / float64(total)))
}

type Stats struct {
	TotalBrokers int
	Sent         int
	Failed       int
	Pending      int
}

// BrokerWithStatus combines broker info with history status
type BrokerWithStatus struct {
	broker.Broker
	Status    string // "never", "sent", "failed"
	LastSent  string // formatted date or empty
	TotalSent int
}

// getBrokersWithStatus returns brokers with their history status
func (s *Server) getBrokersWithStatus(search, category, region, statusFilter string) []BrokerWithStatus {
	// Get all broker statuses from history
	var brokerStatuses map[string]history.BrokerStatus
	if s.historyStore != nil {
		brokerStatuses, _ = s.historyStore.GetAllBrokerStatuses()
	}
	if brokerStatuses == nil {
		brokerStatuses = make(map[string]history.BrokerStatus)
	}

	search = strings.ToLower(strings.TrimSpace(search))
	category = strings.ToLower(strings.TrimSpace(category))
	region = strings.ToLower(strings.TrimSpace(region))
	statusFilter = strings.ToLower(strings.TrimSpace(statusFilter))

	var result []BrokerWithStatus
	for _, b := range s.brokerDB.Brokers {
		// Search filter
		if search != "" {
			name := strings.ToLower(b.Name)
			email := strings.ToLower(b.Email)
			notes := strings.ToLower(b.Notes)
			if !strings.Contains(name, search) && !strings.Contains(email, search) && !strings.Contains(notes, search) {
				continue
			}
		}

		// Category filter
		if category != "" && strings.ToLower(b.Category) != category {
			continue
		}

		// Region filter
		if region != "" && strings.ToLower(b.Region) != region {
			continue
		}

		bws := BrokerWithStatus{
			Broker: b,
			Status: "never",
		}

		if status, ok := brokerStatuses[b.ID]; ok {
			bws.Status = string(status.Status)
			bws.TotalSent = status.TotalSent
			if !status.LastSent.IsZero() {
				bws.LastSent = status.LastSent.Format("Jan 2, 2006")
			}
		}

		// Status filter - "pending" means never sent
		if statusFilter != "" {
			if statusFilter == "pending" && bws.Status != "never" {
				continue
			} else if statusFilter == "sent" && bws.Status != "sent" {
				continue
			} else if statusFilter == "failed" && bws.Status != "failed" {
				continue
			}
		}

		result = append(result, bws)
	}

	return result
}

func (s *Server) getUniqueValues(getter func(broker.Broker) string) []string {
	seen := make(map[string]bool)
	var vals []string
	for _, b := range s.brokerDB.Brokers {
		if v := getter(b); v != "" && !seen[v] {
			seen[v] = true
			vals = append(vals, v)
		}
	}
	return vals
}

func (s *Server) getUniqueCategories() []string {
	return s.getUniqueValues(func(b broker.Broker) string { return b.Category })
}

func (s *Server) getUniqueRegions() []string {
	return s.getUniqueValues(func(b broker.Broker) string { return b.Region })
}

func (s *Server) getStats() Stats {
	stats := Stats{
		TotalBrokers: len(s.brokerDB.Brokers),
	}

	if s.historyStore != nil {
		_, sent, failed, err := s.historyStore.GetStats()
		if err == nil {
			stats.Sent = sent
			stats.Failed = failed
		}
	}

	stats.Pending = stats.TotalBrokers - stats.Sent - stats.Failed
	if stats.Pending < 0 {
		stats.Pending = 0
	}

	return stats
}

func (s *Server) getRecentHistory(limit int) []history.Record {
	if s.historyStore == nil {
		return nil
	}
	records, _ := s.historyStore.GetRecentRequests(limit)
	return records
}

func (s *Server) render(w http.ResponseWriter, name string, data interface{}) {
	tmpl, ok := s.templates[name]
	if !ok {
		http.Error(w, "Template not found: "+name, http.StatusInternalServerError)
		return
	}
	err := tmpl.ExecuteTemplate(w, "layout", data)
	if err != nil {
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) renderPartial(w http.ResponseWriter, name string, data interface{}) {
	tmpl, ok := s.templates[name]
	if !ok {
		http.Error(w, "Template not found: "+name, http.StatusInternalServerError)
		return
	}
	// Execute the template directly without layout wrapper
	err := tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
	}
}

// Setup wizard handlers

func (s *Server) handleSetupWelcome(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title": "Setup",
		"Step":  "welcome",
	}
	s.render(w, "setup/welcome.html", data)
}

func (s *Server) handleSetupProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		profile := config.Profile{
			FirstName:   strings.TrimSpace(r.FormValue("first_name")),
			LastName:    strings.TrimSpace(r.FormValue("last_name")),
			Email:       strings.TrimSpace(r.FormValue("email")),
			Address:     strings.TrimSpace(r.FormValue("address")),
			City:        strings.TrimSpace(r.FormValue("city")),
			State:       strings.TrimSpace(r.FormValue("state")),
			ZipCode:     strings.TrimSpace(r.FormValue("zip_code")),
			Country:     strings.TrimSpace(r.FormValue("country")),
			Phone:       strings.TrimSpace(r.FormValue("phone")),
			DateOfBirth: strings.TrimSpace(r.FormValue("dob")),
		}

		errors := make(map[string]string)
		if profile.FirstName == "" {
			errors["first_name"] = "First name is required"
		}
		if profile.LastName == "" {
			errors["last_name"] = "Last name is required"
		}
		if profile.Email == "" {
			errors["email"] = "Email is required"
		} else if err := email.ValidateEmail(profile.Email); err != nil {
			errors["email"] = "Please enter a valid email address"
		}

		if len(errors) > 0 {
			data := map[string]interface{}{
				"Title":   "Setup - Profile",
				"Step":    "profile",
				"Profile": profile,
				"Errors":  errors,
			}
			s.render(w, "setup/profile.html", data)
			return
		}

		// Store profile in secure server-side session (not cookie)
		session := s.getOrCreateSession(w, r)
		if session == nil {
			http.Error(w, "Session error", http.StatusInternalServerError)
			return
		}
		s.updateSessionFor(session, func(sess *Session) {
			sess.Step = "email"
			sess.Profile = profile
			// Start the email step from the saved settings, so a blank
			// password field keeps the saved password.
			if sess.Email.Provider == "" && s.config != nil {
				sess.Email = s.config.Email
			}
		})
		http.Redirect(w, r, "/setup/email", http.StatusFound)
		return
	}

	session := s.getSession(r)
	var profile config.Profile
	if session != nil {
		profile = session.Profile
	} else if s.config != nil {
		profile = s.config.Profile // re-running setup: start from saved values
	}
	data := map[string]interface{}{
		"Title":   "Setup - Profile",
		"Step":    "profile",
		"Profile": profile,
	}
	s.render(w, "setup/profile.html", data)
}

func (s *Server) handleSetupEmail(w http.ResponseWriter, r *http.Request) {
	session := s.getSession(r)

	if session == nil || session.Profile.FirstName == "" {
		http.Redirect(w, r, "/setup/profile", http.StatusFound)
		return
	}

	if r.Method == "POST" {
		emailCfg := config.Email{
			Provider: "smtp",
			From:     session.Profile.Email,
		}

		errors := make(map[string]string)

		// Parse SMTP configuration (Gmail SMTP)
		emailCfg.SMTP.Host = strings.TrimSpace(r.FormValue("smtp_host"))
		emailCfg.SMTP.Port, _ = strconv.Atoi(strings.TrimSpace(r.FormValue("smtp_port"))) // invalid -> 0 -> "port is required"
		emailCfg.SMTP.Username = strings.TrimSpace(r.FormValue("smtp_username"))
		emailCfg.SMTP.Password = strings.TrimSpace(r.FormValue("smtp_password"))
		emailCfg.SMTP.UseTLS = r.FormValue("smtp_tls") == "on"

		// The form never shows the saved password, so a blank field means
		// "keep it", but only for the same account.
		saved := session.Email.SMTP
		if emailCfg.SMTP.Password == "" && saved.Password != "" &&
			strings.EqualFold(emailCfg.SMTP.Username, saved.Username) && strings.EqualFold(emailCfg.SMTP.Host, saved.Host) {
			emailCfg.SMTP.Password = saved.Password
		}

		// Validate required fields
		if emailCfg.SMTP.Host == "" {
			errors["smtp_host"] = "SMTP host is required"
		}
		if emailCfg.SMTP.Port == 0 {
			errors["smtp_port"] = "SMTP port is required"
		}
		if emailCfg.SMTP.Username == "" {
			errors["smtp_username"] = "Gmail address is required"
		}
		if emailCfg.SMTP.Password == "" {
			errors["smtp_password"] = "App password is required"
		}
		// Enforce TLS when using authentication
		if !emailCfg.SMTP.UseTLS && emailCfg.SMTP.Username != "" {
			errors["smtp_tls"] = "TLS is required for Gmail"
		}

		if len(errors) > 0 {
			data := map[string]interface{}{
				"Title":   "Setup - Gmail",
				"Step":    "email",
				"Profile": session.Profile,
				"Email":   emailCfg,
				"Errors":  errors,
			}
			s.render(w, "setup/email.html", data)
			return
		}

		// Store email config in secure server-side session
		s.updateSession(r, func(sess *Session) {
			sess.Email = emailCfg
			sess.Step = "test"
		})
		http.Redirect(w, r, "/setup/test", http.StatusFound)
		return
	}

	// Set Gmail defaults for new setups
	emailCfg := session.Email
	if emailCfg.SMTP.Host == "" {
		emailCfg.SMTP.Host = "smtp.gmail.com"
		emailCfg.SMTP.Port = 465
		emailCfg.SMTP.UseTLS = true
	}

	data := map[string]interface{}{
		"Title":   "Setup - Gmail",
		"Step":    "email",
		"Profile": session.Profile,
		"Email":   emailCfg,
	}
	s.render(w, "setup/email.html", data)
}

func (s *Server) handleSetupTest(w http.ResponseWriter, r *http.Request) {
	session := s.getSession(r)

	if session == nil || session.Profile.FirstName == "" {
		http.Redirect(w, r, "/setup/profile", http.StatusFound)
		return
	}
	if session.Email.Provider == "" {
		http.Redirect(w, r, "/setup/email", http.StatusFound)
		return
	}

	data := map[string]interface{}{
		"Title":   "Setup - Test",
		"Step":    "test",
		"Profile": session.Profile,
		"Email":   session.Email,
	}
	s.render(w, "setup/test.html", data)
}

func (s *Server) handleSetupTestSend(w http.ResponseWriter, r *http.Request) {
	session := s.getSession(r)

	if session == nil || session.Email.Provider == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`<div class="text-red-600">Email not configured. Please go back to the email step.</div>`))
		return
	}

	// Create email sender with the session config
	sender, err := s.newSender(session.Email)
	if err != nil {
		fmt.Fprintf(w, `
			<div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
				<strong>Configuration error:</strong> %s
				<p class="mt-2 text-sm">Please check your email settings and try again.</p>
			</div>
		`, template.HTMLEscapeString(err.Error()))
		return
	}

	// Send test email
	testMsg := email.Message{
		To:       session.Profile.Email,
		From:     session.Email.From,
		FromName: session.Profile.FullName(),
		Subject:  "Eraser Test Email",
		Body: fmt.Sprintf(`Hello %s,

This is a test email from Eraser to verify your email configuration is working correctly.

If you received this email, your setup is complete and you're ready to start sending data removal requests!

Best,
Eraser`, session.Profile.FirstName),
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	result := sender.Send(ctx, testMsg)
	if !result.Success {
		errMsg := "Unknown error"
		if result.Error != nil {
			errMsg = result.Error.Error()
		}
		fmt.Fprintf(w, `
			<div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
				<strong>Test failed:</strong> %s
				<p class="mt-2 text-sm">Please check your email configuration and try again.</p>
			</div>
			<div class="mt-4">
				<a href="/setup/email" class="text-indigo-600 hover:text-indigo-800 font-medium">
					Back to Email Settings
				</a>
			</div>
		`, template.HTMLEscapeString(errMsg))
		return
	}

	w.Write([]byte(`
		<div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded">
			<strong>Success!</strong> Test email sent to your address.
			<p class="mt-2 text-sm">Check your inbox (and spam folder) for the test message.</p>
		</div>
		<div class="mt-4">
			<a href="/setup/complete" class="inline-flex items-center px-6 py-3 bg-indigo-600 text-white font-medium rounded-md hover:bg-indigo-700">
				Complete Setup
			</a>
		</div>
	`))
}

func (s *Server) handleSetupComplete(w http.ResponseWriter, r *http.Request) {
	session := s.getSession(r)

	if session == nil || session.Profile.FirstName == "" || session.Email.Provider == "" {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}

	// Start from the existing config so re-running setup only changes the
	// profile and email settings it asked about (inbox, exclusions,
	// disclosure, limits, and so on are kept).
	cfg := &config.Config{Options: config.Options{Template: "generic", RateLimitMs: 2000}}
	if s.config != nil {
		existing := *s.config
		cfg = &existing
	}
	cfg.Profile = session.Profile
	cfg.Email = session.Email

	if err := config.Save(s.configPath, cfg); err != nil {
		data := map[string]interface{}{
			"Title": "Setup - Error",
			"Error": err.Error(),
		}
		s.render(w, "setup/complete.html", data)
		return
	}

	// Update server's config reference
	s.config = cfg

	// Clear session - credentials are now saved to config file
	s.clearSession(w, r)

	data := map[string]interface{}{
		"Title":   "Setup Complete",
		"Step":    "complete",
		"Profile": session.Profile,
	}
	s.render(w, "setup/complete.html", data)
}

// Secure session helpers - credentials stored server-side only
// Cookie contains only an opaque session ID, never credentials

func (s *Server) getOrCreateSession(w http.ResponseWriter, r *http.Request) *Session {
	// Check for existing session
	cookie, err := r.Cookie("eraser_session")
	if err == nil && cookie.Value != "" {
		session := s.sessions.Get(cookie.Value)
		if session != nil {
			return session
		}
	}

	// Create new session
	sessionID, err := s.sessions.Create()
	if err != nil {
		return nil
	}

	// Set secure session cookie (ID only, no credentials)
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: localhost is plain HTTP, so no Secure flag; HttpOnly and SameSite=Strict are set
		Name:     "eraser_session",
		Value:    sessionID,
		Path:     "/",
		MaxAge:   1800, // 30 minutes
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		// Note: Secure flag omitted for localhost HTTP; add for production HTTPS
	})

	return s.sessions.Get(sessionID)
}

func (s *Server) getSession(r *http.Request) *Session {
	cookie, err := r.Cookie("eraser_session")
	if err != nil || cookie.Value == "" {
		return nil
	}
	return s.sessions.Get(cookie.Value)
}

// updateSessionFor updates a session by ID. Use it right after
// getOrCreateSession: a session created in this request isn't in the
// request's cookies yet, so updateSession would silently do nothing.
func (s *Server) updateSessionFor(sess *Session, updateFn func(*Session)) bool {
	return s.sessions.Update(sess.ID, updateFn)
}

func (s *Server) updateSession(r *http.Request, updateFn func(*Session)) bool {
	cookie, err := r.Cookie("eraser_session")
	if err != nil || cookie.Value == "" {
		return false
	}
	return s.sessions.Update(cookie.Value, updateFn)
}

func (s *Server) clearSession(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("eraser_session")
	if err == nil && cookie.Value != "" {
		s.sessions.Delete(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: localhost is plain HTTP, so no Secure flag; HttpOnly and SameSite=Strict are set
		Name:     "eraser_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// ==================== Pipeline Handlers ====================

// PipelineStats holds stats for the pipeline dashboard
type PipelineStats struct {
	EmailSent            int
	AwaitingResponse     int
	FormRequired         int
	FormFilled           int
	AwaitingCaptcha      int
	CaptchaSolved        int
	AwaitingConfirmation int
	Confirmed            int
	Rejected             int
	Failed               int
	PendingTasks         int
	NeedsReview          int
}

func (s *Server) getPipelineStats() PipelineStats {
	stats := PipelineStats{}

	if s.historyStore == nil {
		return stats
	}

	// Get pipeline stage counts
	pipelineStats, err := s.historyStore.GetPipelineStats()
	if err == nil {
		stats.EmailSent = pipelineStats[history.PipelineEmailSent]
		stats.AwaitingResponse = pipelineStats[history.PipelineAwaitingResponse]
		stats.FormRequired = pipelineStats[history.PipelineFormRequired]
		stats.FormFilled = pipelineStats[history.PipelineFormFilled]
		stats.AwaitingCaptcha = pipelineStats[history.PipelineAwaitingCaptcha]
		stats.CaptchaSolved = pipelineStats[history.PipelineCaptchaSolved]
		stats.AwaitingConfirmation = pipelineStats[history.PipelineAwaitingConfirmation]
		stats.Confirmed = pipelineStats[history.PipelineConfirmed]
		stats.Rejected = pipelineStats[history.PipelineRejected]
		stats.Failed = pipelineStats[history.PipelineFailed]
	}

	// Get pending tasks count (CAPTCHAs, etc.)
	pendingTaskCount, _, _, err := s.historyStore.GetPendingTaskStats()
	if err == nil {
		stats.PendingTasks = pendingTaskCount
	}

	// Get needs review count
	responses, err := s.historyStore.GetBrokerResponses("", true, 1000)
	if err == nil {
		stats.NeedsReview = len(responses)
	}

	// Get form stats (what's actually shown on tasks page)
	pendingForms, _, _, _, _, _ := s.historyStore.GetFormStats()

	// Calculate unified "Action Needed" based on what's displayed on /tasks page:
	// - Pending forms (forms without tasks yet)
	// - Pending tasks (from pending_tasks table)
	// - Items needing review (parser was unsure)
	stats.PendingTasks = pendingForms + pendingTaskCount + stats.NeedsReview

	return stats
}

func (s *Server) handlePipeline(w http.ResponseWriter, r *http.Request) {
	if s.config == nil || s.config.Profile.FirstName == "" {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}

	pipelineStats := s.getPipelineStats()

	// Get recent responses
	var recentResponses []history.BrokerResponse
	if s.historyStore != nil {
		recentResponses, _ = s.historyStore.GetBrokerResponses("", false, 20)
	}

	// Get pending tasks
	var pendingTasks []history.PendingTask
	if s.historyStore != nil {
		pendingTasks, _ = s.historyStore.GetPendingTasks("", "pending")
	}

	data := map[string]interface{}{
		"Title":           "Pipeline Status",
		"PipelineStats":   pipelineStats,
		"RecentResponses": recentResponses,
		"PendingTasks":    pendingTasks,
		"InboxConfigured": s.config.Inbox.Enabled,
	}

	s.render(w, "pipeline.html", data)
}

func (s *Server) handleForms(w http.ResponseWriter, r *http.Request) {
	// Redirect to unified action needed page
	http.Redirect(w, r, "/tasks", http.StatusFound)
}

func (s *Server) handleFormComplete(w http.ResponseWriter, r *http.Request) {
	brokerID := chi.URLParam(r, "brokerID")

	if s.historyStore == nil {
		http.Error(w, "Database not available", http.StatusInternalServerError)
		return
	}

	// Update pipeline status to confirmed
	if err := s.historyStore.UpdatePipelineStatus(brokerID, history.PipelineConfirmed); err != nil {
		http.Error(w, "Failed to update status", http.StatusInternalServerError)
		return
	}

	// If this was an HTMX request, return updated row HTML
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/tasks")
		w.WriteHeader(http.StatusOK)
		return
	}

	http.Redirect(w, r, "/tasks", http.StatusFound)
}

func (s *Server) handleFormSkip(w http.ResponseWriter, r *http.Request) {
	brokerID := chi.URLParam(r, "brokerID")

	if s.historyStore == nil {
		http.Error(w, "Database not available", http.StatusInternalServerError)
		return
	}

	// Update pipeline status to rejected (skipped)
	if err := s.historyStore.UpdatePipelineStatus(brokerID, history.PipelineRejected); err != nil {
		http.Error(w, "Failed to update status", http.StatusInternalServerError)
		return
	}

	// If this was an HTMX request, return updated row HTML
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/tasks")
		w.WriteHeader(http.StatusOK)
		return
	}

	http.Redirect(w, r, "/tasks", http.StatusFound)
}

func (s *Server) handleTasks(w http.ResponseWriter, r *http.Request) {
	if s.config == nil || s.config.Profile.FirstName == "" {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}

	taskType := r.URL.Query().Get("type")
	status := r.URL.Query().Get("status")
	if status == "" {
		status = "pending"
	}

	var tasks []history.PendingTask
	var completedTasksList []history.PendingTask
	var forms []history.FormWithStatus
	var reviewItems []history.BrokerResponse
	if s.historyStore != nil {
		tasks, _ = s.historyStore.GetPendingTasks(history.TaskType(taskType), "pending")
		completedTasksList, _ = s.historyStore.GetPendingTasks(history.TaskType(taskType), "completed")
		forms, _ = s.historyStore.GetFormsWithStatus()
		// Get items needing review (parser was unsure)
		reviewItems, _ = s.historyStore.GetBrokerResponses("", true, 1000)
	}

	// Get task stats
	pendingTasks, completedTasksCount, skippedTasks := 0, 0, 0
	if s.historyStore != nil {
		pendingTasks, completedTasksCount, skippedTasks, _ = s.historyStore.GetPendingTaskStats()
	}

	// Get form stats
	pendingForms, filledForms, captchaForms, failedForms, skippedForms := 0, 0, 0, 0, 0
	if s.historyStore != nil {
		pendingForms, filledForms, captchaForms, failedForms, skippedForms, _ = s.historyStore.GetFormStats()
	}

	// Count forms needing action (only pending forms, not captcha since those are in pendingTasks)
	formsNeedingAction := pendingForms

	// Total action items: pending forms (without tasks) + pending tasks
	// This avoids double-counting captcha items
	totalActionItems := pendingForms + pendingTasks

	// Get items needing review count
	needsReviewCount := len(reviewItems)

	data := map[string]interface{}{
		"Title":              "Action Needed",
		"Tasks":              tasks,
		"CompletedTasksList": completedTasksList,
		"Forms":              forms,
		"ReviewItems":        reviewItems,
		"TaskType":           taskType,
		"Status":             status,
		"PendingTasks":       pendingTasks,
		"CompletedTasks":     completedTasksCount,
		"SkippedTasks":       skippedTasks,
		"PendingForms":       pendingForms,
		"FilledForms":        filledForms,
		"CaptchaForms":       captchaForms,
		"FailedForms":        failedForms,
		"SkippedForms":       skippedForms,
		"NeedsReview":        needsReviewCount,
		"FormsNeedingAction": formsNeedingAction,
		"TotalActionItems":   totalActionItems + needsReviewCount,
	}

	s.render(w, "tasks.html", data)
}

func (s *Server) handleTaskDetail(w http.ResponseWriter, r *http.Request) {
	taskIDStr := chi.URLParam(r, "taskID")
	taskID, err := strconv.ParseInt(taskIDStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if s.historyStore == nil {
		http.Error(w, "Database not available", http.StatusInternalServerError)
		return
	}

	task, err := s.historyStore.GetPendingTaskByID(taskID)
	if err != nil || task == nil {
		http.Error(w, "Task not found", http.StatusNotFound)
		return
	}

	data := map[string]interface{}{
		"Title": "Task Detail",
		"Task":  task,
	}

	s.render(w, "task-detail.html", data)
}

func (s *Server) handleTaskComplete(w http.ResponseWriter, r *http.Request) {
	taskIDStr := chi.URLParam(r, "taskID")
	taskID, err := strconv.ParseInt(taskIDStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	status := r.FormValue("status")
	if status == "" {
		status = "completed"
	}

	if s.historyStore == nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`<span class="text-red-600">Database not available</span>`))
		return
	}

	if err := s.historyStore.CompletePendingTask(taskID, status); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `<span class="text-red-600">Error: %s</span>`, template.HTMLEscapeString(err.Error()))
		return
	}

	// Redirect back to helper page to show updated status
	http.Redirect(w, r, fmt.Sprintf("/tasks/%d/helper", taskID), http.StatusFound)
}

func (s *Server) handleTaskSkip(w http.ResponseWriter, r *http.Request) {
	taskIDStr := chi.URLParam(r, "taskID")
	taskID, err := strconv.ParseInt(taskIDStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if s.historyStore == nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`<span class="text-red-600">Database not available</span>`))
		return
	}

	if err := s.historyStore.CompletePendingTask(taskID, "skipped"); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `<span class="text-red-600">Error: %s</span>`, template.HTMLEscapeString(err.Error()))
		return
	}

	// Redirect back to helper page to show updated status
	http.Redirect(w, r, fmt.Sprintf("/tasks/%d/helper", taskID), http.StatusFound)
}

// handleTaskOpened records that the helper page was opened. The page posts
// here on load: a GET must not change state, since any site can trigger one.
func (s *Server) handleTaskOpened(w http.ResponseWriter, r *http.Request) {
	taskID, err := strconv.ParseInt(chi.URLParam(r, "taskID"), 10, 64)
	if err != nil || s.historyStore == nil {
		http.NotFound(w, r)
		return
	}
	if err := s.historyStore.MarkTaskOpened(taskID); err != nil {
		log.Printf("Warning: failed to mark task %d opened: %v", taskID, err)
		http.Error(w, "Failed to record", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleTaskHelper(w http.ResponseWriter, r *http.Request) {
	taskIDStr := chi.URLParam(r, "taskID")
	taskID, err := strconv.ParseInt(taskIDStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if s.historyStore == nil {
		http.Error(w, "Database not available", http.StatusInternalServerError)
		return
	}

	task, err := s.historyStore.GetPendingTaskByID(taskID)
	if err != nil || task == nil {
		http.Error(w, "Task not found", http.StatusNotFound)
		return
	}

	// Parse profile data from BrowserState (JSON)
	profileData := make(map[string]string)
	if task.BrowserState != "" {
		if err := json.Unmarshal([]byte(task.BrowserState), &profileData); err != nil {
			log.Printf("Warning: task %d has unreadable profile data: %v", taskID, err)
		}
	}

	// Create ordered profile fields for display
	orderedFields := []struct {
		Key   string
		Label string
	}{
		{"email", "Email"},
		{"firstName", "First Name"},
		{"lastName", "Last Name"},
		{"phone", "Phone"},
		{"address", "Address"},
		{"city", "City"},
		{"state", "State"},
		{"zipCode", "ZIP Code"},
		{"country", "Country"},
	}

	// Build ordered map for template
	orderedProfile := make([]map[string]string, 0)
	for _, field := range orderedFields {
		if val, ok := profileData[field.Key]; ok && val != "" {
			orderedProfile = append(orderedProfile, map[string]string{
				"key":   field.Label,
				"value": val,
			})
		}
	}

	data := map[string]interface{}{
		"Title":          fmt.Sprintf("CAPTCHA Task: %s", task.BrokerName),
		"Task":           task,
		"ProfileData":    profileData,
		"OrderedProfile": orderedProfile,
	}

	s.render(w, "task-helper.html", data)
}

func (s *Server) handleAPIPipelineStats(w http.ResponseWriter, r *http.Request) {
	stats := s.getPipelineStats()

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{
		"email_sent": %d,
		"awaiting_response": %d,
		"form_required": %d,
		"form_filled": %d,
		"awaiting_captcha": %d,
		"captcha_solved": %d,
		"awaiting_confirmation": %d,
		"confirmed": %d,
		"rejected": %d,
		"failed": %d,
		"pending_tasks": %d,
		"needs_review": %d
	}`,
		stats.EmailSent, stats.AwaitingResponse, stats.FormRequired, stats.FormFilled,
		stats.AwaitingCaptcha, stats.CaptchaSolved, stats.AwaitingConfirmation,
		stats.Confirmed, stats.Rejected, stats.Failed, stats.PendingTasks, stats.NeedsReview)
}

func (s *Server) handleAPIResponses(w http.ResponseWriter, r *http.Request) {
	responseType := r.URL.Query().Get("type")
	needsReview := r.URL.Query().Get("needs_review") == "true"

	var responses []history.BrokerResponse
	if s.historyStore != nil {
		responses, _ = s.historyStore.GetBrokerResponses(responseType, needsReview, 50)
	}

	s.renderPartial(w, "partials/response-list.html", map[string]interface{}{
		"Responses": responses,
	})
}

func (s *Server) handleAPITasks(w http.ResponseWriter, r *http.Request) {
	taskType := r.URL.Query().Get("type")
	status := r.URL.Query().Get("status")
	if status == "" {
		status = "pending"
	}

	var tasks []history.PendingTask
	if s.historyStore != nil {
		tasks, _ = s.historyStore.GetPendingTasks(history.TaskType(taskType), status)
	}

	s.renderPartial(w, "partials/task-list.html", map[string]interface{}{
		"Tasks":    tasks,
		"TaskType": taskType,
		"Status":   status,
	})
}

func (s *Server) handleAPIInboxScan(w http.ResponseWriter, r *http.Request) {
	// Check if inbox is configured
	if s.config == nil || !s.config.Inbox.Enabled {
		w.Write([]byte(`
			<div class="bg-yellow-100 border border-yellow-400 text-yellow-800 px-4 py-3 rounded">
				<strong>Inbox monitoring not configured.</strong>
				<p class="mt-1 text-sm">Go to <a href="/settings" class="underline">Settings</a> to configure IMAP access.</p>
			</div>
		`))
		return
	}

	// Create inbox monitor
	monitor := s.newInboxMonitor()
	writeUnverifiedNotice(w, monitor)

	// Connect to IMAP
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	if err := monitor.Connect(ctx); err != nil {
		fmt.Fprintf(w, `
			<div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
				<strong>Failed to connect to inbox:</strong> %s
			</div>
		`, template.HTMLEscapeString(err.Error()))
		return
	}
	defer func() { _ = monitor.Disconnect() }()

	// Fetch emails from last 7 days - check both INBOX and archive folder
	emails, err := monitor.FetchBrokerEmails(ctx, 7)
	if err != nil {
		fmt.Fprintf(w, `
			<div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
				<strong>Failed to fetch emails:</strong> %s
			</div>
		`, template.HTMLEscapeString(err.Error()))
		return
	}

	// Also check archive folder if configured
	if s.config.Inbox.ArchiveFolder != "" {
		archiveEmails, err := monitor.FetchBrokerEmailsFromFolder(ctx, s.config.Inbox.ArchiveFolder, 7)
		if err != nil {
			log.Printf("Warning: failed to fetch from archive folder %s: %v", s.config.Inbox.ArchiveFolder, err)
		} else {
			emails = append(emails, archiveEmails...)
		}
	}

	if len(emails) == 0 {
		w.Write([]byte(`
			<div class="bg-blue-100 border border-blue-400 text-blue-700 px-4 py-3 rounded">
				<strong>No new broker emails found.</strong>
				<p class="mt-1 text-sm">No emails from known data brokers in the last 7 days.</p>
			</div>
		`))
		return
	}

	// Classify and store each email
	var success, formRequired, confirmRequired, rejected, unknown int
	for _, email := range emails {
		classified := inbox.ClassifyResponse(&email)

		if s.historyStore != nil {
			if _, err := inbox.Record(s.historyStore, &email, classified); err != nil {
				log.Printf("Warning: %v", err)
			}
		}

		// Count by type
		switch classified.Type {
		case inbox.ResponseSuccess:
			success++
		case inbox.ResponseFormRequired:
			formRequired++
		case inbox.ResponseConfirmationRequired:
			confirmRequired++
		case inbox.ResponseRejected:
			rejected++
		default:
			unknown++
		}
	}

	// Auto-archive processed emails to the Eraser folder. Only messages
	// fetched from the inbox are moved (UIDs are per-folder).
	if s.config.Inbox.AutoArchive {
		if n, err := monitor.ArchiveEmails(emails, s.config.Inbox.ArchiveFolder); err != nil {
			log.Printf("Warning: failed to archive emails: %v", err)
		} else if n > 0 {
			log.Printf("Archived %d emails to %s folder", n, s.config.Inbox.ArchiveFolder)
		}
	}

	// Return summary HTML
	fmt.Fprintf(w, `
		<div class="bg-green-100 border border-green-400 text-green-800 px-4 py-3 rounded">
			<strong>Scan complete!</strong> Found %d broker emails.
			<div class="mt-2 text-sm grid grid-cols-2 gap-2">
				<div>Success: <span class="font-semibold">%d</span></div>
				<div>Form required: <span class="font-semibold">%d</span></div>
				<div>Confirm required: <span class="font-semibold">%d</span></div>
				<div>Rejected: <span class="font-semibold">%d</span></div>
				<div>Unknown: <span class="font-semibold">%d</span></div>
			</div>
			<p class="mt-2 text-sm">
				<a href="/tasks" class="underline font-medium">View pending tasks</a> |
				<a href="/pipeline" class="underline">Refresh page</a>
			</p>
		</div>
	`, len(emails), success, formRequired, confirmRequired, rejected, unknown)
}

// handleAPIInboxRescan rescans all emails and reclassifies them with the improved classifier
func (s *Server) handleAPIInboxRescan(w http.ResponseWriter, r *http.Request) {
	// Check if inbox is configured
	if s.config == nil || !s.config.Inbox.Enabled {
		w.Write([]byte(`
			<div class="bg-yellow-100 border border-yellow-400 text-yellow-800 px-4 py-3 rounded">
				<strong>Inbox monitoring not configured.</strong>
				<p class="mt-1 text-sm">Go to <a href="/settings" class="underline">Settings</a> to configure IMAP access.</p>
			</div>
		`))
		return
	}

	// Check if clear flag is set
	clearFirst := r.URL.Query().Get("clear") == "true"
	if clearFirst && s.historyStore != nil {
		if err := s.historyStore.ClearBrokerResponses(); err != nil {
			fmt.Fprintf(w, `
				<div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
					<strong>Failed to clear responses:</strong> %s
				</div>
			`, template.HTMLEscapeString(err.Error()))
			return
		}
	}

	// Create inbox monitor
	monitor := s.newInboxMonitor()
	writeUnverifiedNotice(w, monitor)

	// Connect to IMAP with longer timeout for full rescan
	ctx, cancel := context.WithTimeout(r.Context(), 180*time.Second)
	defer cancel()

	if err := monitor.Connect(ctx); err != nil {
		fmt.Fprintf(w, `
			<div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
				<strong>Failed to connect to inbox:</strong> %s
			</div>
		`, template.HTMLEscapeString(err.Error()))
		return
	}
	defer func() { _ = monitor.Disconnect() }()

	// Fetch emails from last 30 days for full rescan - check both INBOX and archive folder
	emails, err := monitor.FetchBrokerEmails(ctx, 30)
	if err != nil {
		fmt.Fprintf(w, `
			<div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
				<strong>Failed to fetch emails:</strong> %s
			</div>
		`, template.HTMLEscapeString(err.Error()))
		return
	}

	// Also check archive folder if configured
	if s.config.Inbox.ArchiveFolder != "" {
		archiveEmails, err := monitor.FetchBrokerEmailsFromFolder(ctx, s.config.Inbox.ArchiveFolder, 30)
		if err != nil {
			log.Printf("Warning: failed to fetch from archive folder %s: %v", s.config.Inbox.ArchiveFolder, err)
		} else {
			emails = append(emails, archiveEmails...)
		}
	}

	if len(emails) == 0 {
		w.Write([]byte(`
			<div class="bg-blue-100 border border-blue-400 text-blue-700 px-4 py-3 rounded">
				<strong>No broker emails found.</strong>
				<p class="mt-1 text-sm">No emails from known data brokers in the last 30 days.</p>
			</div>
		`))
		return
	}

	// Classify and store/update each email
	var success, formRequired, confirmRequired, rejected, pending, unknown int
	var updated, inserted int
	for _, email := range emails {
		classified := inbox.ClassifyResponse(&email)

		if s.historyStore != nil {
			isNew, err := inbox.Record(s.historyStore, &email, classified)
			switch {
			case err != nil:
				log.Printf("Warning: %v", err)
			case isNew:
				inserted++
			default:
				updated++
			}
		}

		// Count by type
		switch classified.Type {
		case inbox.ResponseSuccess:
			success++
		case inbox.ResponseFormRequired:
			formRequired++
		case inbox.ResponseConfirmationRequired:
			confirmRequired++
		case inbox.ResponseRejected:
			rejected++
		case inbox.ResponsePending:
			pending++
		default:
			unknown++
		}
	}

	// Return summary HTML
	fmt.Fprintf(w, `
		<div class="bg-green-100 border border-green-400 text-green-800 px-4 py-3 rounded">
			<strong>Rescan complete!</strong> Processed %d broker emails.
			<div class="mt-2 text-sm grid grid-cols-2 gap-2">
				<div>Updated: <span class="font-semibold">%d</span></div>
				<div>New: <span class="font-semibold">%d</span></div>
			</div>
			<div class="mt-2 text-sm grid grid-cols-3 gap-2">
				<div>Success: <span class="font-semibold">%d</span></div>
				<div>Form required: <span class="font-semibold">%d</span></div>
				<div>Confirm required: <span class="font-semibold">%d</span></div>
				<div>Pending: <span class="font-semibold">%d</span></div>
				<div>Rejected: <span class="font-semibold">%d</span></div>
				<div>Unknown: <span class="font-semibold">%d</span></div>
			</div>
			<p class="mt-2 text-sm">
				<a href="/tasks" class="underline font-medium">View action items</a> |
				<a href="/pipeline" class="underline">Refresh page</a>
			</p>
		</div>
	`, len(emails), updated, inserted, success, formRequired, confirmRequired, pending, rejected, unknown)
}

// handleAPIReclassify reclassifies all existing database records using subject-only patterns
func (s *Server) handleAPIReclassify(w http.ResponseWriter, r *http.Request) {
	if s.historyStore == nil {
		w.Write([]byte(`
			<div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
				<strong>Database not available.</strong>
			</div>
		`))
		return
	}

	// Get all broker responses
	responses, err := s.historyStore.GetAllBrokerResponses()
	if err != nil {
		fmt.Fprintf(w, `
			<div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
				<strong>Failed to get responses:</strong> %s
			</div>
		`, template.HTMLEscapeString(err.Error()))
		return
	}

	if len(responses) == 0 {
		w.Write([]byte(`
			<div class="bg-blue-100 border border-blue-400 text-blue-700 px-4 py-3 rounded">
				<strong>No responses to reclassify.</strong>
			</div>
		`))
		return
	}

	// Check how many records are missing email bodies
	var missingBodies int
	for _, resp := range responses {
		if resp.EmailBody == "" {
			missingBodies++
		}
	}

	// If there are records missing bodies, try to fetch from IMAP
	var bodiesUpdated int
	if missingBodies > 0 && s.config.Inbox.Server != "" && s.brokerDB != nil {
		log.Printf("Found %d records missing email bodies, fetching from IMAP...", missingBodies)

		monitor := s.newInboxMonitor()

		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		if err := monitor.Connect(ctx); err != nil {
			log.Printf("Warning: failed to connect to IMAP for body fetch: %v", err)
		} else {
			defer func() { _ = monitor.Disconnect() }()

			// Fetch emails from both INBOX and archive folder
			var allEmails []inbox.Email

			// Fetch from INBOX
			emails, err := monitor.FetchBrokerEmails(ctx, 30) // 30 days
			if err != nil {
				log.Printf("Warning: failed to fetch from INBOX: %v", err)
			} else {
				allEmails = append(allEmails, emails...)
			}

			// Also fetch from archive folder if configured
			if s.config.Inbox.ArchiveFolder != "" {
				archiveEmails, err := monitor.FetchBrokerEmailsFromFolder(ctx, s.config.Inbox.ArchiveFolder, 30)
				if err != nil {
					log.Printf("Warning: failed to fetch from archive folder: %v", err)
				} else {
					allEmails = append(allEmails, archiveEmails...)
				}
			}

			log.Printf("Fetched %d emails from IMAP", len(allEmails))

			// Build lookup map: key = "broker_id|subject" -> fetched email
			fetched := make(map[string]inbox.Email)
			for _, email := range allEmails {
				if email.Body != "" || email.HTMLBody != "" {
					fetched[email.BrokerID+"|"+email.Subject] = email
				}
			}

			// Fill in records with missing bodies. Record replaces the whole
			// row, so the body and its authenticated flag come from the same
			// email.
			for _, resp := range responses {
				if resp.EmailBody != "" {
					continue // Already has body
				}
				email, ok := fetched[resp.BrokerID+"|"+resp.EmailSubject]
				if !ok {
					continue
				}
				if _, err := inbox.Record(s.historyStore, &email, inbox.ClassifyResponse(&email)); err != nil {
					log.Printf("Warning: failed to store body for response %d: %v", resp.ID, err)
					continue
				}
				bodiesUpdated++
			}
			if bodiesUpdated > 0 {
				if reloaded, err := s.historyStore.GetAllBrokerResponses(); err == nil {
					responses = reloaded
				}
			}
			log.Printf("Updated %d records with email bodies from IMAP", bodiesUpdated)
		}
	}

	// Reclassify each response - use full classifier if body available, otherwise subject-only
	var updated, unchanged int
	var pending, rejected, success, formRequired, confirmRequired, unknown int

	for _, resp := range responses {
		var newType inbox.ResponseType
		var confidence float64
		var needsReview bool
		var formURL, confirmURL string

		if resp.EmailBody != "" {
			// Use full classifier with body
			// Links are only taken from email whose sender was verified
			// when it was fetched.
			email := &inbox.Email{
				From:          resp.EmailFrom,
				Subject:       resp.EmailSubject,
				Body:          resp.EmailBody,
				Authenticated: resp.Authenticated,
			}
			classified := inbox.ClassifyResponse(email)
			newType = classified.Type
			confidence = classified.Confidence
			needsReview = classified.NeedsReview
			formURL = classified.FormURL
			confirmURL = classified.ConfirmURL
		} else {
			// Fall back to subject-only classification
			newType, confidence, needsReview = inbox.ClassifyBySubjectOnly(resp.EmailSubject)
			if resp.Authenticated {
				formURL = resp.FormURL
				confirmURL = resp.ConfirmURL
			}
		}

		// Only update if classification changed or was unknown
		if string(newType) != resp.ResponseType || (resp.ResponseType == "unknown" && newType != inbox.ResponseUnknown) {
			err := s.historyStore.UpdateBrokerResponseClassification(
				resp.ID,
				string(newType),
				formURL,
				confirmURL,
				confidence,
				needsReview,
				resp.Authenticated,
			)
			if err == nil {
				updated++
			}
		} else {
			unchanged++
		}

		// Count by final type
		switch newType {
		case inbox.ResponseSuccess:
			success++
		case inbox.ResponseFormRequired:
			formRequired++
		case inbox.ResponseConfirmationRequired:
			confirmRequired++
		case inbox.ResponseRejected:
			rejected++
		case inbox.ResponsePending:
			pending++
		default:
			unknown++
		}
	}

	// Return summary HTML
	fmt.Fprintf(w, `
		<div class="bg-green-100 border border-green-400 text-green-800 px-4 py-3 rounded">
			<strong>Reclassification complete!</strong> Processed %d records.
			<div class="mt-2 text-sm grid grid-cols-2 gap-2">
				<div>Updated: <span class="font-semibold">%d</span></div>
				<div>Unchanged: <span class="font-semibold">%d</span></div>
			</div>
			<div class="mt-2 text-sm grid grid-cols-3 gap-2">
				<div>Pending: <span class="font-semibold">%d</span></div>
				<div>Rejected: <span class="font-semibold">%d</span></div>
				<div>Success: <span class="font-semibold">%d</span></div>
				<div>Form required: <span class="font-semibold">%d</span></div>
				<div>Confirm required: <span class="font-semibold">%d</span></div>
				<div>Unknown: <span class="font-semibold">%d</span></div>
			</div>
			<p class="mt-2 text-sm">
				<a href="/tasks" class="underline font-medium">View action items</a> |
				<a href="/pipeline" class="underline">Refresh page</a>
			</p>
		</div>
	`, len(responses), updated, unchanged, pending, rejected, success, formRequired, confirmRequired, unknown)
}

// handleAPIJobActive returns the currently running job (if any)
func (s *Server) handleAPIJobActive(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	job := s.jobManager.GetActive()
	if job == nil {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"job": nil})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{"job": job.ToJSON()})
}

// handleAPIJobStatus returns the status of a specific job
func (s *Server) handleAPIJobStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	jobID := chi.URLParam(r, "jobID")
	job := s.jobManager.Get(jobID)

	if job == nil {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "job not found"})
		return
	}

	_ = json.NewEncoder(w).Encode(job.ToJSON())
}

// handleAPIJobCancel cancels a running job
func (s *Server) handleAPIJobCancel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	jobID := chi.URLParam(r, "jobID")
	job := s.jobManager.Get(jobID)

	if job == nil {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "job not found"})
		return
	}

	job.Cancel()
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "cancelled"})
}

// removeLegacyJobFile deletes pending_job.json left by older versions, which
// auto-resumed bulk sends on startup. Send history now makes resuming
// unnecessary: "Send all" skips brokers already sent to.
func removeLegacyJobFile() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	path := filepath.Join(home, ".eraser", "pending_job.json")
	if err := os.Remove(path); err == nil {
		log.Printf("Removed %s; interrupted sends are no longer auto-resumed. Use \"Send all\" to continue.", path)
	}
}

func defaultScreenshotDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".eraser", "screenshots")
}

// handleScreenshot serves a form screenshot for the task pages. Only names
// produced by browser.ScreenshotName are served, so nothing else in or
// around the folder is reachable.
func (s *Server) handleScreenshot(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if s.screenshotDir == "" || !browser.ScreenshotNamePattern.MatchString(name) {
		http.NotFound(w, r)
		return
	}
	// name matched ScreenshotNamePattern above: no separators or "..".
	path := filepath.Join(s.screenshotDir, name)
	if _, err := os.Stat(path); err != nil { //nolint:gosec // G703: name validated above
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	http.ServeFile(w, r, path) //nolint:gosec // G703: name validated above
}
