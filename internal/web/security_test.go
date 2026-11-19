package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/eraser-privacy/eraser/internal/broker"
	"github.com/eraser-privacy/eraser/internal/config"
	"github.com/eraser-privacy/eraser/internal/history"
)

const testPort = 8080

// Fake credentials; tests check they never appear in a rendered page.
const (
	smtpSecret  = "smtp-app-password-123"  //nolint:gosec // G101: fake test value
	inboxSecret = "inbox-app-password-456" //nolint:gosec // G101: fake test value
)

// sessionCookie is attached to test requests; Secure/HttpOnly/SameSite only
// matter on cookies a server sets, not ones a client sends.
func sessionCookie(sid string) *http.Cookie {
	return &http.Cookie{Name: "eraser_session", Value: sid} //nolint:gosec // G124: request-side cookie
}

func testConfig() *config.Config {
	return &config.Config{
		Profile: config.Profile{FirstName: "Jane", LastName: "Doe", Email: "jane@example.com"},
		Email: config.EmailConfig{Provider: "smtp", From: "jane@example.com",
			SMTP: config.SMTPConfig{Host: "smtp.example.com", Port: 465, Username: "jane@example.com", Password: smtpSecret, UseTLS: true}},
		Inbox: config.InboxConfig{Enabled: true, Provider: "gmail", Email: "jane@example.com", Password: inboxSecret},
	}
}

func newTestServer(t *testing.T, cfg *config.Config) (*Server, http.Handler) {
	t.Helper()
	db := &broker.BrokerDatabase{Brokers: []broker.Broker{{ID: "acme", Name: "Acme", Email: "privacy@acme.example", Region: "us"}}}
	s, err := NewServer(testPort, cfg, filepath.Join(t.TempDir(), "config.yaml"), db, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s, s.setupRouter()
}

// do sends a request with a legitimate local Host unless the caller overrides it.
func do(h http.Handler, method, target string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	req.Host = "localhost:8080"
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHostHeaderAllowlist(t *testing.T) {
	_, h := newTestServer(t, testConfig())
	tests := map[string]int{
		"localhost:8080":      http.StatusOK,
		"127.0.0.1:8080":      http.StatusOK,
		"LOCALHOST:8080":      http.StatusOK,
		"evil.example":        http.StatusForbidden, // DNS rebinding: attacker's name, our IP
		"evil.example:8080":   http.StatusForbidden,
		"localhost:9999":      http.StatusForbidden,
		"localhost.evil.test": http.StatusForbidden,
		"":                    http.StatusForbidden,
	}
	for host, want := range tests {
		rec := do(h, http.MethodGet, "/settings", func(r *http.Request) { r.Host = host })
		if rec.Code != want {
			t.Errorf("Host %q: got %d, want %d", host, rec.Code, want)
		}
	}
}

func TestCrossOriginPostsRejected(t *testing.T) {
	_, h := newTestServer(t, testConfig())
	tests := []struct {
		name    string
		headers map[string]string
		blocked bool
	}{
		{"cross-site fetch", map[string]string{"Sec-Fetch-Site": "cross-site"}, true},
		{"same-site other port", map[string]string{"Sec-Fetch-Site": "same-site"}, true},
		{"foreign origin", map[string]string{"Origin": "http://evil.example"}, true},
		{"same origin", map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "http://localhost:8080"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := do(h, http.MethodDelete, "/api/history/failed", func(r *http.Request) {
				for k, v := range tt.headers {
					r.Header.Set(k, v)
				}
			})
			if got := rec.Code == http.StatusForbidden; got != tt.blocked {
				t.Fatalf("status %d; blocked = %v, want %v", rec.Code, got, tt.blocked)
			}
		})
	}
}

func TestCSPAllowsNoThirdParties(t *testing.T) {
	_, h := newTestServer(t, testConfig())
	csp := do(h, http.MethodGet, "/settings", nil).Header().Get("Content-Security-Policy")
	for _, bad := range []string{"https:", "http:", "unsafe-eval", "*"} {
		if strings.Contains(csp, bad) {
			t.Errorf("CSP contains %q: %s", bad, csp)
		}
	}
	for _, want := range []string{"default-src 'self'", "object-src 'none'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP missing %q: %s", want, csp)
		}
	}
}

func readCloser(s string) io.ReadCloser { return io.NopCloser(strings.NewReader(s)) }

var externalAsset = regexp.MustCompile(`(?i)<(script|link)[^>]+(src|href)="(https?:)?//`)

func TestPagesLoadOnlyLocalAssets(t *testing.T) {
	_, h := newTestServer(t, testConfig())
	for _, path := range []string{"/", "/brokers", "/settings", "/history", "/setup/"} {
		rec := do(h, http.MethodGet, path, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", path, rec.Code)
		}
		body := rec.Body.String()
		if m := externalAsset.FindString(body); m != "" {
			t.Errorf("%s loads an external asset: %s", path, m)
		}
		for _, want := range []string{`/static/css/app.css`, `/static/js/htmx.min.js`} {
			if !strings.Contains(body, want) {
				t.Errorf("%s missing %s", path, want)
			}
		}
	}
}

func TestStaticAssetsServed(t *testing.T) {
	_, h := newTestServer(t, testConfig())
	for path, ctype := range map[string]string{
		"/static/css/app.css":    "text/css",
		"/static/js/htmx.min.js": "javascript",
	} {
		rec := do(h, http.MethodGet, path, nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Content-Type"), ctype) {
			t.Errorf("%s: status %d, Content-Type %q", path, rec.Code, rec.Header().Get("Content-Type"))
		}
	}
}

func TestPagesNeverContainPasswords(t *testing.T) {
	s, h := newTestServer(t, testConfig())

	// Setup wizard holding SMTP credentials in its session.
	sid, err := s.sessions.Create()
	if err != nil {
		t.Fatal(err)
	}
	s.sessions.Update(sid, func(sess *Session) {
		sess.Profile = testConfig().Profile
		sess.Email = testConfig().Email
	})
	withSession := func(r *http.Request) { r.AddCookie(sessionCookie(sid)) }

	for _, path := range []string{"/settings", "/setup/email", "/setup/test"} {
		body := do(h, http.MethodGet, path, withSession).Body.String()
		for _, secret := range []string{smtpSecret, inboxSecret} {
			if strings.Contains(body, secret) {
				t.Errorf("%s contains a stored password", path)
			}
		}
	}
}

func TestSettingsInboxKeepsPasswordWhenLeftBlank(t *testing.T) {
	s, h := newTestServer(t, testConfig())
	form := url.Values{"inbox_email": {"jane@example.com"}, "inbox_password": {""}}
	rec := do(h, http.MethodPost, "/settings/inbox", func(r *http.Request) {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Body = readCloser(form.Encode())
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if s.cfg().Inbox.Password != inboxSecret {
		t.Fatalf("blank password field overwrote the saved password")
	}
}

func TestSetupEmailKeepsPasswordWhenLeftBlank(t *testing.T) {
	s, h := newTestServer(t, testConfig())
	sid, err := s.sessions.Create()
	if err != nil {
		t.Fatal(err)
	}
	s.sessions.Update(sid, func(sess *Session) {
		sess.Profile = testConfig().Profile
		sess.Email = testConfig().Email
	})
	form := url.Values{
		"smtp_host": {"smtp.example.com"}, "smtp_port": {"465"}, "smtp_username": {"jane@example.com"},
		"smtp_password": {""}, "smtp_tls": {"on"},
	}
	rec := do(h, http.MethodPost, "/setup/email", func(r *http.Request) {
		r.AddCookie(sessionCookie(sid))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Body = readCloser(form.Encode())
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if got := s.sessions.Get(sid).Email.SMTP.Password; got != smtpSecret {
		t.Fatalf("password = %q, want the previously saved one", got)
	}
}

func TestScreenshotRouteServesOnlyScreenshots(t *testing.T) {
	s, h := newTestServer(t, testConfig())
	s.screenshotDir = t.TempDir()
	name := "acme_filled_1700000000.png"
	if err := os.WriteFile(filepath.Join(s.screenshotDir, name), []byte("\x89PNG\r\n\x1a\nfake"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A file next to the screenshot folder that must stay unreachable.
	if err := os.WriteFile(filepath.Join(filepath.Dir(s.screenshotDir), "config.yaml"), []byte("password: x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if rec := do(h, http.MethodGet, "/screenshots/"+name, nil); rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("valid screenshot: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	for _, bad := range []string{
		"/screenshots/..%2fconfig.yaml",
		"/screenshots/%2e%2e%2fconfig.yaml",
		"/screenshots/config.yaml",
		"/screenshots/acme_filled_1700000000.png.txt",
		"/screenshots/missing_filled_1.png",
	} {
		rec := do(h, http.MethodGet, bad, nil)
		if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "password") {
			t.Errorf("%s: status %d", bad, rec.Code)
		}
	}
}

// Opening the helper page must not change anything on a GET: cross-origin
// protection only covers state-changing methods, so any site could trigger
// it with an <img>. The page records "opened" with a same-origin POST.
func TestTaskOpenedOnlyBySameOriginPost(t *testing.T) {
	f := newSendFixture(t, config.Options{}, brokersN("a"))
	task := &history.PendingTask{BrokerID: "a", BrokerName: "A", TaskType: history.TaskCaptcha,
		FormURL: "https://a.example/form", Status: "pending"}
	if err := f.store.AddPendingTask(task); err != nil {
		t.Fatal(err)
	}
	opened := func() bool {
		got, err := f.store.GetPendingTaskByID(task.ID)
		if err != nil || got == nil {
			t.Fatalf("GetPendingTaskByID: %v", err)
		}
		return got.OpenedAt.Valid
	}
	id := strconv.FormatInt(task.ID, 10)

	if rec := do(f.h, http.MethodGet, "/tasks/"+id+"/helper", nil); rec.Code != http.StatusOK {
		t.Fatalf("helper page: status %d", rec.Code)
	}
	if opened() {
		t.Fatal("a GET of the helper page marked the task opened")
	}
	crossSite := func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }
	if rec := do(f.h, http.MethodPost, "/tasks/"+id+"/opened", crossSite); rec.Code != http.StatusForbidden || opened() {
		t.Fatalf("cross-site POST: status %d, opened=%v", rec.Code, opened())
	}
	if rec := do(f.h, http.MethodPost, "/tasks/"+id+"/opened", sameOrigin); rec.Code != http.StatusNoContent || !opened() {
		t.Fatalf("same-origin POST: status %d, opened=%v", rec.Code, opened())
	}
}
