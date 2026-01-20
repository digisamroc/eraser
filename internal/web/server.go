package web

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/csrf"
	"github.com/eraser-privacy/eraser/internal/broker"
	"github.com/eraser-privacy/eraser/internal/config"
	"github.com/eraser-privacy/eraser/internal/email"
	"github.com/eraser-privacy/eraser/internal/history"
	"github.com/eraser-privacy/eraser/internal/inbox"
	emaTemplate "github.com/eraser-privacy/eraser/internal/template"
)

//go:embed static/*
var staticFS embed.FS

//go:embed templates/*
var templatesFS embed.FS

const (
	defaultRateLimit   = 30
	defaultRateWindow  = time.Minute
	defaultSessionTTL  = 30 * time.Minute
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
	config         *config.Config
	configPath     string
	brokerDB       *broker.BrokerDatabase
	historyStore   *history.Store
	tmplEngine     *emaTemplate.Engine
	templates      map[string]*template.Template
	httpServer     *http.Server
	port           int
	csrfKey        []byte
	sessions       *SessionStore
	rateLimiter    *RateLimiter
	jobManager     *JobManager
	jobPersistence *JobPersistence
}

func NewServer(port int, cfg *config.Config, configPath string, brokerDB *broker.BrokerDatabase, historyStore *history.Store, tmplEngine *emaTemplate.Engine) (*Server, error) {
	csrfKey := make([]byte, 32)
	if _, err := rand.Read(csrfKey); err != nil {
		return nil, fmt.Errorf("failed to generate CSRF key: %w", err)
	}

	// Get data directory for job persistence
	home, _ := os.UserHomeDir()
	dataDir := filepath.Join(home, ".eraser")

	s := &Server{
		config:         cfg,
		configPath:     configPath,
		brokerDB:       brokerDB,
		historyStore:   historyStore,
		tmplEngine:     tmplEngine,
		port:           port,
		csrfKey:        csrfKey,
		sessions:       NewSessionStore(defaultSessionTTL),
		rateLimiter:    NewRateLimiter(defaultRateLimit, defaultRateWindow),
		jobManager:     NewJobManager(),
		jobPersistence: NewJobPersistence(dataDir),
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
		Addr:         fmt.Sprintf("127.0.0.1:%d", s.port),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Check for pending job and offer to resume
	s.checkPendingJob()

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

// checkPendingJob checks for an incomplete job from a previous session and resumes it
func (s *Server) checkPendingJob() {
	state, err := s.jobPersistence.Load()
	if err != nil {
		log.Printf("Warning: failed to load pending job: %v", err)
		return
	}

	if state == nil || len(state.RemainingBrokers) == 0 {
		return // No pending job
	}

	fmt.Printf("\nFound incomplete send job: %d of %d brokers remaining\n", len(state.RemainingBrokers), state.Total)
	fmt.Printf("Already sent: %d, failed: %d\n", state.Sent, state.Failed)

	// Auto-resume the job
	go s.resumePendingJob(state)
}

// resumePendingJob resumes processing of an incomplete job
func (s *Server) resumePendingJob(state *PersistentJobState) {
	// Wait a moment for the server to fully start
	time.Sleep(2 * time.Second)

	if s.config == nil || s.config.Email.Provider == "" {
		log.Printf("Cannot resume job: email not configured")
		s.jobPersistence.Clear()
		return
	}

	// Create email sender
	sender, err := email.NewSender(s.config.Email)
	if err != nil {
		log.Printf("Cannot resume job: failed to create email sender: %v", err)
		s.jobPersistence.Clear()
		return
	}

	// Build broker list from remaining IDs
	brokerMap := make(map[string]broker.Broker)
	for _, b := range s.brokerDB.Brokers {
		brokerMap[b.ID] = b
	}

	var toSend []BrokerWithStatus
	for _, id := range state.RemainingBrokers {
		if b, ok := brokerMap[id]; ok {
			toSend = append(toSend, BrokerWithStatus{Broker: b, Status: "never"})
		}
	}

	if len(toSend) == 0 {
		log.Printf("No valid brokers remaining in pending job")
		s.jobPersistence.Clear()
		return
	}

	// Create a new job to continue processing
	job := s.jobManager.Create(state.Total)
	job.Sent = state.Sent
	job.Failed = state.Failed
	job.Progress = ((state.Sent + state.Failed) * 100) / state.Total

	fmt.Printf("Resuming send job: %d brokers remaining...\n", len(toSend))

	// Process remaining brokers
	s.processSendJob(job, toSend, sender)
}

// setupRouter configures all routes
func (s *Server) setupRouter() *chi.Mux {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Compress(5))
	r.Use(securityHeaders)

	// CSRF protection - secure for localhost only
	csrfMiddleware := csrf.Protect(
		s.csrfKey,
		csrf.Secure(false), // Allow HTTP for localhost
		csrf.Path("/"),
		csrf.HttpOnly(true),
		csrf.SameSite(csrf.SameSiteLaxMode), // Lax mode for form submissions
		csrf.RequestHeader("X-CSRF-Token"),  // For HTMX AJAX requests
		csrf.TrustedOrigins([]string{"localhost", "127.0.0.1", fmt.Sprintf("localhost:%d", s.port), fmt.Sprintf("127.0.0.1:%d", s.port)}),
	)
	r.Use(csrfMiddleware)

	// Static files
	staticSub, _ := fs.Sub(staticFS, "static")
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	// Routes
	r.Get("/", s.handleDashboard)
	r.Get("/brokers", s.handleBrokers)
	r.Get("/history", s.handleHistory)
	r.Get("/settings", s.handleSettings)
	r.Post("/settings/inbox", s.handleSettingsInbox)
	r.Get("/pipeline", s.handlePipeline)
	r.Get("/tasks", s.handleTasks)
	r.Get("/tasks/{taskID}", s.handleTaskDetail)
	r.Get("/tasks/{taskID}/helper", s.handleTaskHelper)
	r.Post("/tasks/{taskID}/complete", s.handleTaskComplete)
	r.Post("/tasks/{taskID}/skip", s.handleTaskSkip)
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

// securityHeaders adds security headers to all responses
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")

		// Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Control referrer information
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Content Security Policy - restrict resource loading
		// 'unsafe-inline' needed for Tailwind CSS and inline scripts (HTMX attributes)
		// CDN domains allowed for Tailwind, HTMX, and Google Fonts
		csp := "default-src 'self'; " +
			"script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://unpkg.com; " +
			"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
			"img-src 'self' data:; " +
			"font-src 'self' https://fonts.gstatic.com; " +
			"connect-src 'self'; " +
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

	exec.Command(cmd, args...).Start()
}

// Handler implementations

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	// Check if config exists, redirect to setup if not
	if s.config == nil || s.config.Profile.FirstName == "" {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}

	data := map[string]interface{}{
		"Title":         "Dashboard",
		"Profile":       s.config.Profile,
		"BrokerCount":   len(s.brokerDB.Brokers),
		"RecentHistory": s.getRecentHistory(10),
		"Stats":         s.getStats(),
		"PipelineStats": s.getPipelineStats(),
	}

	s.renderWithCSRF(w, r, "dashboard.html", data)
}

func (s *Server) handleBrokers(w http.ResponseWriter, r *http.Request) {
	search := r.URL.Query().Get("search")
	category := r.URL.Query().Get("category")
	region := r.URL.Query().Get("region")
	status := r.URL.Query().Get("status")

	brokers := s.getBrokersWithStatus(search, category, region, status)

	data := map[string]interface{}{
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
	s.renderWithCSRF(w, r, "brokers.html", data)
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

	data := map[string]interface{}{
		"Title":        "History",
		"History":      filteredHistory,
		"StatusFilter": statusFilter,
	}
	s.renderWithCSRF(w, r, "history.html", data)
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title":  "Settings",
		"Config": s.config,
	}
	s.renderWithCSRF(w, r, "settings.html", data)
}

func (s *Server) handleSettingsInbox(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderSettingsWithMessage(w, r, "Failed to parse form", false)
		return
	}

	email := r.FormValue("inbox_email")
	password := r.FormValue("inbox_password")

	// Validate required fields
	if email == "" || password == "" {
		s.renderSettingsWithMessage(w, r, "Email and password are required", false)
		return
	}

	// Update config with inbox settings
	if s.config == nil {
		s.config = &config.Config{}
	}

	s.config.Inbox = config.InboxConfig{
		Enabled:  true,
		Provider: "gmail",
		Email:    email,
		Password: password,
	}

	// Save config
	if err := config.Save(s.configPath, s.config); err != nil {
		s.renderSettingsWithMessage(w, r, "Failed to save configuration: "+err.Error(), false)
		return
	}

	s.renderSettingsWithMessage(w, r, "Inbox monitoring enabled successfully!", true)
}

func (s *Server) renderSettingsWithMessage(w http.ResponseWriter, r *http.Request, message string, success bool) {
	data := map[string]interface{}{
		"Title":        "Settings",
		"Config":       s.config,
		"InboxMessage": message,
		"InboxSuccess": success,
	}
	s.renderWithCSRF(w, r, "settings.html", data)
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
		json.NewEncoder(w).Encode(map[string]string{"error": "Database not available"})
		return
	}

	deleted, err := s.historyStore.DeleteByStatus(history.StatusFailed)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
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

	if s.config == nil || s.config.Email.Provider == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`<span class="text-red-600">Email not configured. <a href="/setup" class="underline">Configure now</a></span>`))
		return
	}

	// Create email sender
	sender, err := email.NewSender(s.config.Email)
	if err != nil {
		w.Write([]byte(fmt.Sprintf(`<span class="text-red-600">Error: %s</span>`, template.HTMLEscapeString(err.Error()))))
		return
	}

	// Generate email content using template engine
	rendered, err := s.tmplEngine.Render("generic", s.config.Profile, *br)
	if err != nil {
		w.Write([]byte(fmt.Sprintf(`<span class="text-red-600">Template error: %s</span>`, template.HTMLEscapeString(err.Error()))))
		return
	}

	msg := email.Message{
		To:      br.Email,
		From:    s.config.Email.From,
		Subject: rendered.Subject,
		Body:    rendered.Body,
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	result := sender.Send(ctx, msg)

	// Record in history
	record := &history.Record{
		BrokerID:   br.ID,
		BrokerName: br.Name,
		Email:      br.Email,
		Template:   "generic",
		SentAt:     time.Now(),
	}

	if result.Success {
		record.Status = history.StatusSent
		record.MessageID = result.MessageID
	} else {
		record.Status = history.StatusFailed
		if result.Error != nil {
			record.Error = result.Error.Error()
		}
	}

	if s.historyStore != nil {
		s.historyStore.Add(record)
	}

	if result.Success {
		w.Write([]byte(`<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">Sent</span>`))
	} else {
		errMsg := "Unknown error"
		if result.Error != nil {
			errMsg = result.Error.Error()
		}
		w.Write([]byte(fmt.Sprintf(`<span class="text-red-600" title="%s">Failed</span>`, template.HTMLEscapeString(errMsg))))
	}
}

func (s *Server) handleAPISendAll(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Rate limiting - prevent abuse of bulk email sending
	if !s.rateLimiter.Allow("send-all") {
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]string{"error": "Rate limit exceeded. Please wait before sending another batch."})
		return
	}

	// Check if a job is already running
	if activeJob := s.jobManager.GetActive(); activeJob != nil {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":  "A send job is already in progress",
			"job_id": activeJob.ID,
		})
		return
	}

	if s.config == nil || s.config.Email.Provider == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Email not configured. Please configure email settings first."})
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

	toSend := s.getBrokersWithStatus(search, category, region, status)

	if len(toSend) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "No pending brokers to send to."})
		return
	}

	// Create email sender (validate config before starting job)
	sender, err := email.NewSender(s.config.Email)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// Create a new job
	job := s.jobManager.Create(len(toSend))

	// Extract broker IDs for persistence
	brokerIDs := make([]string, len(toSend))
	for i, b := range toSend {
		brokerIDs[i] = b.ID
	}

	// Save initial job state
	jobState := &PersistentJobState{
		ID:               job.ID,
		Status:           job.Status,
		Sent:             0,
		Failed:           0,
		Total:            len(toSend),
		StartedAt:        job.StartedAt,
		RemainingBrokers: brokerIDs,
		Search:           search,
		Category:         category,
		Region:           region,
		StatusFilter:     status,
	}
	if err := s.jobPersistence.Save(jobState); err != nil {
		log.Printf("Warning: failed to save job state: %v", err)
	}

	// Start background goroutine to process emails
	go s.processSendJob(job, toSend, sender)

	// Return job ID immediately
	json.NewEncoder(w).Encode(map[string]interface{}{
		"job_id": job.ID,
		"total":  len(toSend),
	})
}

// Daily send limits by provider to avoid rate limiting
const (
	DailyLimitSMTP     = 250 // Gmail/SMTP: stay well under 500/day
	DailyLimitSendGrid = 500 // SendGrid free tier
	DailyLimitResend   = 500 // Resend reasonable daily batch
)

// processSendJob runs in a background goroutine to send emails
func (s *Server) processSendJob(job *Job, toSend []BrokerWithStatus, sender email.Sender) {
	sent := 0
	failed := 0
	rateLimitMs := s.config.Options.RateLimitMs
	if rateLimitMs == 0 {
		rateLimitMs = 2000 // Default 2 second delay
	}

	// Set daily limit based on provider
	dailyLimit := DailyLimitSMTP // Default for SMTP
	if s.config.Email.Provider == "sendgrid" {
		dailyLimit = DailyLimitSendGrid
	} else if s.config.Email.Provider == "resend" {
		dailyLimit = DailyLimitResend
	}
	job.DailyLimit = dailyLimit

	// Track remaining brokers for persistence
	remaining := make([]string, len(toSend))
	for i, b := range toSend {
		remaining[i] = b.ID
	}

	for i, b := range toSend {
		// Check if job was cancelled
		if job.IsCancelled() {
			break
		}

		// Check daily limit
		if sent >= dailyLimit {
			job.DaySent = sent
			job.Status = JobStatusPaused
			job.Error = fmt.Sprintf("Daily limit of %d emails reached. Remaining %d brokers will be sent when you restart tomorrow.", dailyLimit, len(remaining))
			s.saveJobProgress(job, sent, failed, remaining)
			log.Printf("Job paused: daily limit of %d reached, %d remaining", dailyLimit, len(remaining))
			return
		}

		// Update current broker
		job.Update(sent, failed, b.Name)

		// Generate email
		rendered, err := s.tmplEngine.Render("generic", s.config.Profile, b.Broker)
		if err != nil {
			failed++
			job.Update(sent, failed, b.Name)
			// Remove from remaining even on failure
			remaining = remaining[1:]
			s.saveJobProgress(job, sent, failed, remaining)
			continue
		}

		msg := email.Message{
			To:      b.Email,
			From:    s.config.Email.From,
			Subject: rendered.Subject,
			Body:    rendered.Body,
		}

		// Use job's context with timeout for cancellation support
		ctx, cancel := context.WithTimeout(job.Context(), 30*time.Second)
		result := sender.Send(ctx, msg)
		cancel()

		// Record in history
		record := &history.Record{
			BrokerID:   b.ID,
			BrokerName: b.Name,
			Email:      b.Email,
			Template:   "generic",
			SentAt:     time.Now(),
		}

		if result.Success {
			record.Status = history.StatusSent
			record.MessageID = result.MessageID
			sent++
			job.ResetAuthFailures() // Reset on success
		} else {
			record.Status = history.StatusFailed
			errMsg := ""
			if result.Error != nil {
				errMsg = result.Error.Error()
				record.Error = errMsg
			}
			failed++

			// Check for auth failures and stop if too many consecutive
			if strings.Contains(strings.ToLower(errMsg), "auth") {
				if job.RecordAuthFailure() {
					// Stop job due to auth errors
					if s.historyStore != nil {
						s.historyStore.Add(record)
					}
					remaining = remaining[1:]
					s.saveJobProgress(job, sent, failed, remaining)
					job.StopWithError("auth", "Stopped due to repeated authentication failures. Your email provider may have rate-limited or blocked your account. Please check your email settings and try again later.")
					log.Printf("Job stopped: repeated auth failures after %d sent, %d failed", sent, failed)
					return
				}
			}
		}

		if s.historyStore != nil {
			s.historyStore.Add(record)
		}

		// Update job progress
		job.Update(sent, failed, b.Name)

		// Remove processed broker from remaining and save state
		remaining = remaining[1:]
		s.saveJobProgress(job, sent, failed, remaining)

		// Rate limit delay (skip on last item)
		if i < len(toSend)-1 && !job.IsCancelled() {
			time.Sleep(time.Duration(rateLimitMs) * time.Millisecond)
		}
	}

	// Mark job as complete and clear persisted state
	job.Complete()
	if err := s.jobPersistence.Clear(); err != nil {
		log.Printf("Warning: failed to clear job state: %v", err)
	}
}

// saveJobProgress saves the current job progress to disk
func (s *Server) saveJobProgress(job *Job, sent, failed int, remaining []string) {
	state := &PersistentJobState{
		ID:               job.ID,
		Status:           job.Status,
		Sent:             sent,
		Failed:           failed,
		Total:            job.Total,
		StartedAt:        job.StartedAt,
		RemainingBrokers: remaining,
	}
	if err := s.jobPersistence.Save(state); err != nil {
		log.Printf("Warning: failed to save job progress: %v", err)
	}
}

// Helper methods

type Stats struct {
	TotalBrokers int
	Sent         int
	Failed       int
	Pending      int
}

// BrokerWithStatus combines broker info with history status
type BrokerWithStatus struct {
	broker.Broker
	Status     string // "never", "sent", "failed"
	LastSent   string // formatted date or empty
	TotalSent  int
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
			if !strings.Contains(name, search) && !strings.Contains(email, search) {
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

func (s *Server) renderWithCSRF(w http.ResponseWriter, r *http.Request, name string, data map[string]interface{}) {
	// Add CSRF token to data
	data["CSRFToken"] = csrf.Token(r)
	data["CSRFField"] = template.HTML(fmt.Sprintf(`<input type="hidden" name="gorilla.csrf.Token" value="%s">`, csrf.Token(r)))

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

// Setup wizard handlers

func (s *Server) handleSetupWelcome(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title": "Setup",
		"Step":  "welcome",
	}
	s.renderWithCSRF(w, r, "setup/welcome.html", data)
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
			s.renderWithCSRF(w, r, "setup/profile.html", data)
			return
		}

		// Store profile in secure server-side session (not cookie)
		session := s.getOrCreateSession(w, r)
		if session == nil {
			http.Error(w, "Session error", http.StatusInternalServerError)
			return
		}
		s.updateSession(r, func(sess *Session) {
			sess.Step = "email"
			sess.Profile = profile
		})
		http.Redirect(w, r, "/setup/email", http.StatusFound)
		return
	}

	session := s.getSession(r)
	var profile config.Profile
	if session != nil {
		profile = session.Profile
	}
	data := map[string]interface{}{
		"Title":   "Setup - Profile",
		"Step":    "profile",
		"Profile": profile,
	}
	s.renderWithCSRF(w, r, "setup/profile.html", data)
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
		fmt.Sscanf(r.FormValue("smtp_port"), "%d", &emailCfg.SMTP.Port)
		emailCfg.SMTP.Username = strings.TrimSpace(r.FormValue("smtp_username"))
		emailCfg.SMTP.Password = strings.TrimSpace(r.FormValue("smtp_password"))
		emailCfg.SMTP.UseTLS = r.FormValue("smtp_tls") == "on"

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
			s.renderWithCSRF(w, r, "setup/email.html", data)
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
	s.renderWithCSRF(w, r, "setup/email.html", data)
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
	s.renderWithCSRF(w, r, "setup/test.html", data)
}

func (s *Server) handleSetupTestSend(w http.ResponseWriter, r *http.Request) {
	session := s.getSession(r)

	if session == nil || session.Email.Provider == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`<div class="text-red-600">Email not configured. Please go back to the email step.</div>`))
		return
	}

	// Create email sender with the session config
	sender, err := email.NewSender(session.Email)
	if err != nil {
		w.Write([]byte(fmt.Sprintf(`
			<div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
				<strong>Configuration error:</strong> %s
				<p class="mt-2 text-sm">Please check your email settings and try again.</p>
			</div>
		`, template.HTMLEscapeString(err.Error()))))
		return
	}

	// Send test email
	testMsg := email.Message{
		To:      session.Profile.Email,
		From:    session.Email.From,
		Subject: "Eraser Test Email",
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
		w.Write([]byte(fmt.Sprintf(`
			<div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
				<strong>Test failed:</strong> %s
				<p class="mt-2 text-sm">Please check your email configuration and try again.</p>
			</div>
			<div class="mt-4">
				<a href="/setup/email" class="text-indigo-600 hover:text-indigo-800 font-medium">
					Back to Email Settings
				</a>
			</div>
		`, template.HTMLEscapeString(errMsg))))
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

	cfg := &config.Config{
		Profile: session.Profile,
		Email:   session.Email,
		Options: config.Options{
			Template:    "generic",
			RateLimitMs: 2000,
		},
	}

	if err := config.Save(s.configPath, cfg); err != nil {
		data := map[string]interface{}{
			"Title": "Setup - Error",
			"Error": err.Error(),
		}
		s.renderWithCSRF(w, r, "setup/complete.html", data)
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
	s.renderWithCSRF(w, r, "setup/complete.html", data)
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
	http.SetCookie(w, &http.Cookie{
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

	http.SetCookie(w, &http.Cookie{
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

	s.renderWithCSRF(w, r, "pipeline.html", data)
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

	s.renderWithCSRF(w, r, "tasks.html", data)
}

func (s *Server) handleTaskDetail(w http.ResponseWriter, r *http.Request) {
	taskIDStr := chi.URLParam(r, "taskID")
	var taskID int64
	fmt.Sscanf(taskIDStr, "%d", &taskID)

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

	s.renderWithCSRF(w, r, "task-detail.html", data)
}

func (s *Server) handleTaskComplete(w http.ResponseWriter, r *http.Request) {
	taskIDStr := chi.URLParam(r, "taskID")
	var taskID int64
	fmt.Sscanf(taskIDStr, "%d", &taskID)

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
		w.Write([]byte(fmt.Sprintf(`<span class="text-red-600">Error: %s</span>`, template.HTMLEscapeString(err.Error()))))
		return
	}

	// Redirect back to helper page to show updated status
	http.Redirect(w, r, fmt.Sprintf("/tasks/%d/helper", taskID), http.StatusFound)
}

func (s *Server) handleTaskSkip(w http.ResponseWriter, r *http.Request) {
	taskIDStr := chi.URLParam(r, "taskID")
	var taskID int64
	fmt.Sscanf(taskIDStr, "%d", &taskID)

	if s.historyStore == nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`<span class="text-red-600">Database not available</span>`))
		return
	}

	if err := s.historyStore.CompletePendingTask(taskID, "skipped"); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf(`<span class="text-red-600">Error: %s</span>`, template.HTMLEscapeString(err.Error()))))
		return
	}

	// Redirect back to helper page to show updated status
	http.Redirect(w, r, fmt.Sprintf("/tasks/%d/helper", taskID), http.StatusFound)
}

func (s *Server) handleTaskHelper(w http.ResponseWriter, r *http.Request) {
	taskIDStr := chi.URLParam(r, "taskID")
	var taskID int64
	fmt.Sscanf(taskIDStr, "%d", &taskID)

	if s.historyStore == nil {
		http.Error(w, "Database not available", http.StatusInternalServerError)
		return
	}

	task, err := s.historyStore.GetPendingTaskByID(taskID)
	if err != nil || task == nil {
		http.Error(w, "Task not found", http.StatusNotFound)
		return
	}

	// Mark task as opened (sets opened_at timestamp if not already set)
	s.historyStore.MarkTaskOpened(taskID)

	// Re-fetch task to get updated opened_at
	task, _ = s.historyStore.GetPendingTaskByID(taskID)

	// Parse profile data from BrowserState (JSON)
	profileData := make(map[string]string)
	if task.BrowserState != "" {
		json.Unmarshal([]byte(task.BrowserState), &profileData)
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

	s.renderWithCSRF(w, r, "task-helper.html", data)
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
	monitor := inbox.NewMonitor(s.config.Inbox, s.brokerDB.Brokers)

	// Connect to IMAP
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	if err := monitor.Connect(ctx); err != nil {
		w.Write([]byte(fmt.Sprintf(`
			<div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
				<strong>Failed to connect to inbox:</strong> %s
			</div>
		`, template.HTMLEscapeString(err.Error()))))
		return
	}
	defer monitor.Disconnect()

	// Fetch emails from last 7 days - check both INBOX and archive folder
	emails, err := monitor.FetchBrokerEmails(ctx, 7)
	if err != nil {
		w.Write([]byte(fmt.Sprintf(`
			<div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
				<strong>Failed to fetch emails:</strong> %s
			</div>
		`, template.HTMLEscapeString(err.Error()))))
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
	var processedUIDs []uint32 // Track UIDs for archiving
	for _, email := range emails {
		classified := inbox.ClassifyResponse(&email)
		processedUIDs = append(processedUIDs, email.UID)

		// Get body content (prefer plain text, fall back to HTML)
		bodyContent := email.Body
		if bodyContent == "" {
			bodyContent = email.HTMLBody
		}

		// Store in database
		brokerResp := &history.BrokerResponse{
			BrokerID:     email.BrokerID,
			BrokerName:   email.BrokerName,
			ResponseType: string(classified.Type),
			EmailFrom:    email.From,
			EmailSubject: email.Subject,
			EmailBody:    bodyContent,
			FormURL:      classified.FormURL,
			ConfirmURL:   classified.ConfirmURL,
			Confidence:   classified.Confidence,
			NeedsReview:  classified.NeedsReview,
			ReceivedAt:   email.ReceivedAt,
		}

		if s.historyStore != nil {
			s.historyStore.AddBrokerResponse(brokerResp)
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

	// Auto-archive processed emails to the Eraser folder
	var archived int
	if s.config.Inbox.AutoArchive && len(processedUIDs) > 0 {
		if err := monitor.ArchiveEmails(processedUIDs, s.config.Inbox.ArchiveFolder); err != nil {
			log.Printf("Warning: failed to archive emails: %v", err)
		} else {
			archived = len(processedUIDs)
			log.Printf("Archived %d emails to %s folder", archived, s.config.Inbox.ArchiveFolder)
		}
	}

	// Return summary HTML
	w.Write([]byte(fmt.Sprintf(`
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
				<a href="/pipeline" class="underline" onclick="window.location.reload()">Refresh page</a>
			</p>
		</div>
	`, len(emails), success, formRequired, confirmRequired, rejected, unknown)))
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
			w.Write([]byte(fmt.Sprintf(`
				<div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
					<strong>Failed to clear responses:</strong> %s
				</div>
			`, template.HTMLEscapeString(err.Error()))))
			return
		}
	}

	// Create inbox monitor
	monitor := inbox.NewMonitor(s.config.Inbox, s.brokerDB.Brokers)

	// Connect to IMAP with longer timeout for full rescan
	ctx, cancel := context.WithTimeout(r.Context(), 180*time.Second)
	defer cancel()

	if err := monitor.Connect(ctx); err != nil {
		w.Write([]byte(fmt.Sprintf(`
			<div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
				<strong>Failed to connect to inbox:</strong> %s
			</div>
		`, template.HTMLEscapeString(err.Error()))))
		return
	}
	defer monitor.Disconnect()

	// Fetch emails from last 30 days for full rescan - check both INBOX and archive folder
	emails, err := monitor.FetchBrokerEmails(ctx, 30)
	if err != nil {
		w.Write([]byte(fmt.Sprintf(`
			<div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
				<strong>Failed to fetch emails:</strong> %s
			</div>
		`, template.HTMLEscapeString(err.Error()))))
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

		// Get body content (prefer plain text, fall back to HTML)
		bodyContent := email.Body
		if bodyContent == "" {
			bodyContent = email.HTMLBody
		}

		// Check if this response already exists
		if s.historyStore != nil {
			existing, _ := s.historyStore.FindBrokerResponseBySubject(email.BrokerID, email.Subject)
			if existing != nil {
				// Update existing response classification
				err := s.historyStore.UpdateBrokerResponseClassification(
					existing.ID,
					string(classified.Type),
					classified.FormURL,
					classified.ConfirmURL,
					classified.Confidence,
					classified.NeedsReview,
				)
				if err == nil {
					updated++
				}
				// Also update the body if it was empty
				if existing.EmailBody == "" && bodyContent != "" {
					s.historyStore.UpdateBrokerResponseBody(existing.ID, bodyContent)
				}
			} else {
				// Insert new response
				brokerResp := &history.BrokerResponse{
					BrokerID:     email.BrokerID,
					BrokerName:   email.BrokerName,
					ResponseType: string(classified.Type),
					EmailFrom:    email.From,
					EmailSubject: email.Subject,
					EmailBody:    bodyContent,
					FormURL:      classified.FormURL,
					ConfirmURL:   classified.ConfirmURL,
					Confidence:   classified.Confidence,
					NeedsReview:  classified.NeedsReview,
					ReceivedAt:   email.ReceivedAt,
				}
				if err := s.historyStore.AddBrokerResponse(brokerResp); err == nil {
					inserted++
				}
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
	w.Write([]byte(fmt.Sprintf(`
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
				<a href="/pipeline" class="underline" onclick="window.location.reload()">Refresh page</a>
			</p>
		</div>
	`, len(emails), updated, inserted, success, formRequired, confirmRequired, pending, rejected, unknown)))
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
		w.Write([]byte(fmt.Sprintf(`
			<div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
				<strong>Failed to get responses:</strong> %s
			</div>
		`, template.HTMLEscapeString(err.Error()))))
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

		monitor := inbox.NewMonitor(s.config.Inbox, s.brokerDB.Brokers)

		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		if err := monitor.Connect(ctx); err != nil {
			log.Printf("Warning: failed to connect to IMAP for body fetch: %v", err)
		} else {
			defer monitor.Disconnect()

			// Fetch emails from both INBOX and archive folder
			var allEmails []inbox.Email

			// Fetch from INBOX
			emails, err := monitor.FetchRecentEmails(ctx, 30) // 30 days
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

			// Build lookup map: key = "broker_id|subject" -> email body
			emailBodies := make(map[string]string)
			for _, email := range allEmails {
				if email.BrokerID == "" {
					continue // Not matched to a broker
				}
				key := email.BrokerID + "|" + email.Subject
				body := email.Body
				if body == "" {
					body = email.HTMLBody
				}
				if body != "" {
					emailBodies[key] = body
				}
			}

			// Update database records with missing bodies
			for _, resp := range responses {
				if resp.EmailBody != "" {
					continue // Already has body
				}
				key := resp.BrokerID + "|" + resp.EmailSubject
				if body, ok := emailBodies[key]; ok {
					err := s.historyStore.UpdateBrokerResponseBody(resp.ID, body)
					if err == nil {
						bodiesUpdated++
						// Update the in-memory response too for reclassification
						for i := range responses {
							if responses[i].ID == resp.ID {
								responses[i].EmailBody = body
								break
							}
						}
					}
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
			email := &inbox.Email{
				From:    resp.EmailFrom,
				Subject: resp.EmailSubject,
				Body:    resp.EmailBody,
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
			formURL = resp.FormURL
			confirmURL = resp.ConfirmURL
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
	w.Write([]byte(fmt.Sprintf(`
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
				<a href="/pipeline" class="underline" onclick="window.location.reload()">Refresh page</a>
			</p>
		</div>
	`, len(responses), updated, unchanged, pending, rejected, success, formRequired, confirmRequired, unknown)))
}

// handleAPIJobActive returns the currently running job (if any)
func (s *Server) handleAPIJobActive(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	job := s.jobManager.GetActive()
	if job == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"job": nil})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"job": job.ToJSON()})
}

// handleAPIJobStatus returns the status of a specific job
func (s *Server) handleAPIJobStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	jobID := chi.URLParam(r, "jobID")
	job := s.jobManager.Get(jobID)

	if job == nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "job not found"})
		return
	}

	json.NewEncoder(w).Encode(job.ToJSON())
}

// handleAPIJobCancel cancels a running job
func (s *Server) handleAPIJobCancel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	jobID := chi.URLParam(r, "jobID")
	job := s.jobManager.Get(jobID)

	if job == nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "job not found"})
		return
	}

	job.Cancel()
	json.NewEncoder(w).Encode(map[string]string{"status": "cancelled"})
}

