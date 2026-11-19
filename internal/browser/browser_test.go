package browser

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/eraser-privacy/eraser/internal/config"
)

// These tests drive real headless Chrome against local pages. They skip with
// -short (the pre-commit hook) and when Chrome isn't installed, except in CI,
// where a missing Chrome must fail rather than silently skip.
func requireChrome(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("drives a real browser; skipped with -short")
	}
	defer func() {
		if t.Skipped() && os.Getenv("CI") != "" {
			t.Fatal("Chrome is required in CI")
		}
	}()
	for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"} {
		if _, err := exec.LookPath(name); err == nil {
			return
		}
	}
	if runtime.GOOS == "darwin" {
		if _, err := os.Stat("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"); err == nil {
			return
		}
	}
	t.Skip("Chrome not installed")
}

const formPage = `<!doctype html><html><body>
<form method="POST" action="/submitted">
  <label for="email">Email</label><input type="email" id="email" name="email">
  <label for="first_name">First name</label><input id="first_name" name="first_name">
  <label for="last_name">Last name</label><input id="last_name" name="last_name">
  <label for="phone">Phone</label><input type="tel" id="phone" name="phone">
  <label for="dob">Date of birth</label><input id="dob" name="dob">
  <button type="submit">Submit request</button>
</form></body></html>`

// A form without a submit control, next to an unrelated button that must
// never be clicked.
const noButtonPage = `<!doctype html><html><body>
<header><button onclick="fetch('/danger', {method: 'POST'})">Delete my account</button></header>
<form method="POST" action="/submitted">
  <label for="email">Email</label><input type="email" id="email" name="email">
  <label for="first_name">First name</label><input id="first_name" name="first_name">
</form></body></html>`

const captchaPage = `<!doctype html><html><body>
<form method="POST" action="/submitted">
  <label for="email">Email</label><input type="email" id="email" name="email">
  <div class="g-recaptcha" data-sitekey="test-key" style="width:300px;height:80px"></div>
  <button type="submit">Submit request</button>
</form></body></html>`

type formSite struct {
	*httptest.Server
	mu          sync.Mutex
	submissions []url.Values
	dangerHits  int
}

func (f *formSite) submitted() []url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]url.Values(nil), f.submissions...)
}

func newFormSite(t *testing.T) *formSite {
	t.Helper()
	f := &formSite{}
	mux := http.NewServeMux()
	page := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprint(w, body) }
	}
	mux.HandleFunc("/form", page(formPage))
	mux.HandleFunc("/no-button", page(noButtonPage))
	mux.HandleFunc("/captcha", page(captchaPage))
	mux.HandleFunc("/danger", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.dangerHits++
		f.mu.Unlock()
	})
	mux.HandleFunc("/submitted", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		f.submissions = append(f.submissions, r.PostForm)
		f.mu.Unlock()
		_, _ = fmt.Fprint(w, "<html><body>Thank you</body></html>")
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

var testProfile = config.Profile{
	FirstName: "Jane", LastName: "Doe", Email: "jane@example.com",
	Phone: "555-0100", DateOfBirth: "1990-01-01",
}

func newTestBrowser(t *testing.T) *Browser {
	t.Helper()
	requireChrome(t)
	cfg := DefaultConfig()
	cfg.Timeout = 30 * time.Second
	b, err := New(cfg, &testProfile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return b
}

func TestFillAndSubmit(t *testing.T) {
	site := newFormSite(t)
	b := newTestBrowser(t)

	res, err := b.NavigateAndFill(site.URL+"/form", "acme", true)
	if err != nil {
		t.Fatalf("NavigateAndFill: %v (%s)", err, res.ErrorMessage)
	}
	if !res.SubmitAttempted {
		t.Fatalf("form not submitted: %+v", res)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(site.submitted()) == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	subs := site.submitted()
	if len(subs) != 1 {
		t.Fatalf("server received %d submissions, want 1", len(subs))
	}
	if got := subs[0].Get("email"); got != "jane@example.com" {
		t.Errorf("email = %q", got)
	}
	if got := subs[0].Get("first_name"); got != "Jane" {
		t.Errorf("first_name = %q", got)
	}
}

// A form with no submit button must not be reported as submitted.
func TestNoSubmitButtonIsNotReportedAsSubmitted(t *testing.T) {
	site := newFormSite(t)
	b := newTestBrowser(t)

	res, _ := b.NavigateAndFill(site.URL+"/no-button", "acme", true)
	if res.SubmitAttempted {
		t.Errorf("reported as submitted without a submit button: %+v", res)
	}
	time.Sleep(500 * time.Millisecond)
	if n := len(site.submitted()); n != 0 {
		t.Errorf("server received %d submissions", n)
	}
	site.mu.Lock()
	defer site.mu.Unlock()
	if site.dangerHits != 0 {
		t.Error("clicked an unrelated 'Delete my account' button outside the form")
	}
}

// fill --pending processes several forms with one browser.
func TestSeveralFormsWithOneBrowser(t *testing.T) {
	site := newFormSite(t)
	b := newTestBrowser(t)

	for i := range 2 {
		res, err := b.NavigateAndFill(site.URL+"/form", "acme", false)
		if err != nil || len(res.FieldsFilled) == 0 {
			t.Fatalf("form %d: err=%v result=%+v", i+1, err, res)
		}
	}
}

// A form CAPTCHA must stop automatic submission (the user solves it).
func TestCaptchaFormIsNotSubmitted(t *testing.T) {
	site := newFormSite(t)
	b := newTestBrowser(t)

	res, err := b.NavigateAndFill(site.URL+"/captcha", "acme", true)
	if err != nil {
		t.Fatal(err)
	}
	if !res.CaptchaFound || res.SubmitAttempted {
		t.Fatalf("CaptchaFound=%v SubmitAttempted=%v (%s)", res.CaptchaFound, res.SubmitAttempted, res.ErrorMessage)
	}
	time.Sleep(500 * time.Millisecond)
	if n := len(site.submitted()); n != 0 {
		t.Errorf("server received %d submissions", n)
	}
}
