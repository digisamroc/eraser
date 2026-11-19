package browser

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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
	mux.HandleFunc("/redirect-away", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://evil.test:"+r.URL.Query().Get("port")+"/form", http.StatusFound) //nolint:gosec // G710: test fixture redirects on purpose
	})
	mux.HandleFunc("/js-away", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `<html><body><script>location.href = "http://evil.test:%s/form";</script></body></html>`, //nolint:gosec // G705: test fixture
			r.URL.Query().Get("port"))
	})
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
	return newTestBrowserWith(t, DefaultConfig())
}

// newTestBrowserWith starts Chrome with *.test names resolving to localhost,
// so tests can use distinct host names for one local server.
func newTestBrowserWith(t *testing.T, cfg BrowserConfig) *Browser {
	t.Helper()
	requireChrome(t)
	cfg.Timeout = 30 * time.Second
	cfg.hostResolverRules = "MAP *.test 127.0.0.1"
	b, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return b
}

// fillReq builds a request allowed only for the test server's own address.
func fillReq(site *formSite, path string, submit bool) FillRequest {
	return FillRequest{
		URL: site.URL + path, BrokerID: "acme", Profile: testProfile, Submit: submit,
		Allowed: func(u *url.URL) bool { return u.Host == mustHost(nil, site.URL) },
	}
}

func TestFillAndSubmit(t *testing.T) {
	site := newFormSite(t)
	b := newTestBrowser(t)

	res, err := b.NavigateAndFill(fillReq(site, "/form", true))
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

	res, _ := b.NavigateAndFill(fillReq(site, "/no-button", true))
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
		res, err := b.NavigateAndFill(fillReq(site, "/form", false))
		if err != nil || len(res.FieldsFilled) == 0 {
			t.Fatalf("form %d: err=%v result=%+v", i+1, err, res)
		}
	}
}

// A form CAPTCHA must stop automatic submission (the user solves it).
func TestCaptchaFormIsNotSubmitted(t *testing.T) {
	site := newFormSite(t)
	b := newTestBrowser(t)

	res, err := b.NavigateAndFill(fillReq(site, "/captcha", true))
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

// The page must stay on an allowed domain: a redirect (HTTP or script) to
// another site means nothing is filled or submitted.
func TestFillRefusesToLeaveAllowedDomain(t *testing.T) {
	site := newFormSite(t)
	b := newTestBrowserWith(t, DefaultConfig())
	port := mustURL(t, site.URL).Port()

	for _, path := range []string{"/redirect-away", "/js-away"} {
		t.Run(path, func(t *testing.T) {
			res, err := b.NavigateAndFill(FillRequest{
				URL: "http://broker.test:" + port + path + "?port=" + port, BrokerID: "acme",
				Profile: testProfile, Submit: true,
				Allowed: func(u *url.URL) bool { return u.Hostname() == "broker.test" },
			})
			if !errors.Is(err, ErrLeftAllowedDomain) {
				t.Fatalf("err = %v (result %+v), want ErrLeftAllowedDomain", err, res)
			}
			if len(res.FieldsFilled) > 0 || res.SubmitAttempted {
				t.Fatalf("filled %v / submitted %v on another domain", res.FieldsFilled, res.SubmitAttempted)
			}
		})
	}
	time.Sleep(500 * time.Millisecond)
	if n := len(site.submitted()); n != 0 {
		t.Fatalf("server received %d submissions", n)
	}
}

func TestFillRefusesDisallowedStartURL(t *testing.T) {
	site := newFormSite(t)
	b := newTestBrowser(t)
	req := fillReq(site, "/form", true)
	req.Allowed = func(*url.URL) bool { return false }
	if _, err := b.NavigateAndFill(req); !errors.Is(err, ErrLeftAllowedDomain) {
		t.Fatalf("err = %v, want ErrLeftAllowedDomain", err)
	}
}

func TestFillOnlyUsesGivenProfileFields(t *testing.T) {
	site := newFormSite(t)
	b := newTestBrowser(t)
	req := fillReq(site, "/form", true)
	req.Profile = config.Disclosure{}.Apply(testProfile) // name and email only

	if _, err := b.NavigateAndFill(req); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(site.submitted()) == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	subs := site.submitted()
	if len(subs) != 1 {
		t.Fatalf("got %d submissions", len(subs))
	}
	if subs[0].Get("phone") != "" || subs[0].Get("dob") != "" {
		t.Errorf("undisclosed fields sent: phone=%q dob=%q", subs[0].Get("phone"), subs[0].Get("dob"))
	}
	if subs[0].Get("email") != testProfile.Email {
		t.Errorf("email = %q", subs[0].Get("email"))
	}
}

func TestScreenshotsArePrivateAndStayInTheirFolder(t *testing.T) {
	site := newFormSite(t)
	dir := filepath.Join(t.TempDir(), "shots")
	cfg := DefaultConfig()
	cfg.ScreenshotDir = dir
	b := newTestBrowserWith(t, cfg)

	req := fillReq(site, "/form", false)
	req.BrokerID = "../../escape"
	res, err := b.NavigateAndFill(req)
	if err != nil || res.ScreenshotPath == "" {
		t.Fatalf("err=%v screenshot=%q", err, res.ScreenshotPath)
	}
	if strings.ContainsAny(res.ScreenshotPath, `/\`) || strings.Contains(res.ScreenshotPath, "..") {
		t.Fatalf("screenshot name %q can escape its folder", res.ScreenshotPath)
	}
	info, err := os.Stat(filepath.Join(dir, res.ScreenshotPath))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("screenshot permissions %04o, want 0600", perm)
	}
	if dinfo, _ := os.Stat(dir); dinfo.Mode().Perm() != 0o700 {
		t.Errorf("screenshot folder permissions %04o, want 0700", dinfo.Mode().Perm())
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
