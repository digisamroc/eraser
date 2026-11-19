package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/eraser-privacy/eraser/internal/config"
)

func postForm(h http.Handler, path string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	return do(h, http.MethodPost, path, func(r *http.Request) {
		sameOrigin(r)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Body = readCloser(form.Encode())
		for _, c := range cookies {
			r.AddCookie(c)
		}
	})
}

func existingConfig() *config.Config {
	cfg := testConfig()
	cfg.Options = config.Options{
		Template: "ccpa", ExcludedBrokers: []string{"spokeo"}, Disclose: []string{"location"},
		DailyLimit: 100, Regions: []string{"us"},
	}
	return cfg
}

// Re-running the wizard must change only what it asks about.
func TestSetupWizardKeepsExistingSettings(t *testing.T) {
	s, h := newTestServer(t, existingConfig())

	// Start the wizard: the profile step creates the session.
	rec := postForm(h, "/setup/profile", url.Values{
		"first_name": {"Janet"}, "last_name": {"Doe"}, "email": {"janet@example.com"},
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("profile: status %d: %s", rec.Code, rec.Body.String())
	}
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "eraser_session" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no session cookie")
	}

	// Email step with the password left blank keeps the saved password.
	rec = postForm(h, "/setup/email", url.Values{
		"smtp_host": {"smtp.example.com"}, "smtp_port": {"465"}, "smtp_username": {"jane@example.com"},
		"smtp_password": {""}, "smtp_tls": {"on"},
	}, cookie)
	if rec.Code != http.StatusFound {
		t.Fatalf("email: status %d: %s", rec.Code, rec.Body.String())
	}

	// A GET must not save (any page can trigger one); completing is a POST.
	rec = do(h, http.MethodGet, "/setup/complete", func(r *http.Request) { r.AddCookie(cookie) })
	if rec.Code != http.StatusFound || s.cfg().Profile.FirstName == "Janet" {
		t.Fatalf("GET /setup/complete: status %d, first name %q; it must redirect without saving", rec.Code, s.cfg().Profile.FirstName)
	}
	if _, err := config.Load(s.configPath); err == nil {
		t.Fatal("GET /setup/complete wrote the config file")
	}

	rec = postForm(h, "/setup/complete", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("complete: status %d", rec.Code)
	}

	got := s.cfg()
	if got.Profile.FirstName != "Janet" {
		t.Errorf("profile not updated: %+v", got.Profile)
	}
	if got.Email.SMTP.Password != smtpSecret {
		t.Error("saved SMTP password lost")
	}
	want := existingConfig()
	if !reflect.DeepEqual(got.Options, want.Options) {
		t.Errorf("options changed:\n got %+v\nwant %+v", got.Options, want.Options)
	}
	if got.Inbox != want.Inbox {
		t.Errorf("inbox settings changed: %+v", got.Inbox)
	}

	saved, err := config.Load(s.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(saved.Options.ExcludedBrokers, []string{"spokeo"}) || saved.Inbox.Password != inboxSecret {
		t.Errorf("saved config lost settings: %+v", saved.Options)
	}
}

func TestSettingsDisclosure(t *testing.T) {
	s, h := newTestServer(t, testConfig())

	rec := postForm(h, "/settings/disclose", url.Values{"disclose": {"date_of_birth", "location"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if got := s.cfg().Options.Disclose; !reflect.DeepEqual(got, []string{"location", "date_of_birth"}) {
		t.Fatalf("Disclose = %v", got)
	}
	if saved, err := config.Load(s.configPath); err != nil || len(saved.Options.Disclose) != 2 {
		t.Fatalf("not saved: %v %v", saved, err)
	}

	page := do(h, http.MethodGet, "/settings", nil).Body.String()
	for _, v := range []string{"location", "date_of_birth"} {
		if !strings.Contains(page, `value="`+v+`" checked`) {
			t.Errorf("settings page doesn't show %s as checked", v)
		}
	}
	if strings.Contains(page, `value="phone" checked`) {
		t.Error("phone shown as checked")
	}

	// Clearing every box returns to name and email only.
	postForm(h, "/settings/disclose", url.Values{})
	if got := s.cfg().Options.Disclose; len(got) != 0 {
		t.Fatalf("Disclose = %v, want none", got)
	}

	// Unknown values are rejected and change nothing.
	postForm(h, "/settings/disclose", url.Values{"disclose": {"location"}})
	rec = postForm(h, "/settings/disclose", url.Values{"disclose": {"ssn"}})
	if !strings.Contains(rec.Body.String(), "unknown disclose value") {
		t.Errorf("no error shown for invalid value")
	}
	if got := s.cfg().Options.Disclose; !reflect.DeepEqual(got, []string{"location"}) {
		t.Fatalf("invalid post changed Disclose to %v", got)
	}
}

// Settings saved at the same time must all stick, in memory and on disk,
// while other requests read the config (run with -race).
func TestConcurrentSettingsSavesKeepEachOther(t *testing.T) {
	s, h := newTestServer(t, existingConfig())
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(3)
		go func() {
			defer wg.Done()
			postForm(h, "/settings/disclose", url.Values{"disclose": {"date_of_birth"}})
		}()
		go func() {
			defer wg.Done()
			postForm(h, "/settings/inbox", url.Values{"inbox_email": {fmt.Sprintf("inbox%d@example.com", i)}, "inbox_password": {"pw"}})
		}()
		go func() {
			defer wg.Done()
			do(h, http.MethodGet, "/settings", nil)
		}()
	}
	wg.Wait()

	saved, err := config.Load(s.configPath)
	if err != nil {
		t.Fatal(err)
	}
	for name, cfg := range map[string]*config.Config{"memory": s.cfg(), "disk": saved} {
		if !reflect.DeepEqual(cfg.Options.Disclose, []string{"date_of_birth"}) {
			t.Errorf("%s: disclose = %v, a concurrent save lost it", name, cfg.Options.Disclose)
		}
		if !cfg.Inbox.Enabled || !strings.HasPrefix(cfg.Inbox.Email, "inbox") {
			t.Errorf("%s: inbox = %+v, a concurrent save lost it", name, cfg.Inbox)
		}
	}
	if s.cfg().Inbox.Email != saved.Inbox.Email {
		t.Errorf("memory has inbox %q, disk has %q", s.cfg().Inbox.Email, saved.Inbox.Email)
	}
}

// startWizard posts the profile step and returns the session cookie.
func startWizard(t *testing.T, h http.Handler) *http.Cookie {
	t.Helper()
	rec := postForm(h, "/setup/profile", url.Values{
		"first_name": {"Janet"}, "last_name": {"Doe"}, "email": {"janet@example.com"},
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("profile: status %d: %s", rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "eraser_session" {
			return c
		}
	}
	t.Fatal("no session cookie")
	return nil
}

// The email step must work with any SMTP server, not just Gmail.
func TestSetupEmailAcceptsAnySMTPServer(t *testing.T) {
	s, h := newTestServer(t, testConfig())
	cookie := startWizard(t, h)

	page := do(h, http.MethodGet, "/setup/email", func(r *http.Request) { r.AddCookie(cookie) }).Body.String()
	if strings.Contains(page, `type="hidden" name="smtp_host"`) || strings.Contains(page, `type="hidden" name="smtp_port"`) {
		t.Fatal("SMTP host and port are hidden; users can't change them")
	}
	for _, want := range []string{`name="smtp_host"`, `name="smtp_port"`, `value="smtp.example.com"`} {
		if !strings.Contains(page, want) {
			t.Errorf("email step lacks %s", want)
		}
	}

	rec := postForm(h, "/setup/email", url.Values{
		"smtp_host": {"mail.privateemail.com"}, "smtp_port": {"587"}, "smtp_username": {"janet@example.com"},
		"smtp_password": {"mailbox-password"}, "smtp_tls": {"on"},
	}, cookie)
	if rec.Code != http.StatusFound {
		t.Fatalf("email: status %d: %s", rec.Code, rec.Body.String())
	}

	page = do(h, http.MethodGet, "/setup/test", func(r *http.Request) { r.AddCookie(cookie) }).Body.String()
	if !strings.Contains(page, "mail.privateemail.com:587") || strings.Contains(page, "Gmail") {
		t.Error("test step doesn't show the chosen server")
	}

	if rec := postForm(h, "/setup/complete", nil, cookie); rec.Code != http.StatusOK {
		t.Fatalf("complete: status %d", rec.Code)
	}
	got := s.cfg().Email.SMTP
	if got.Host != "mail.privateemail.com" || got.Port != 587 || got.Password != "mailbox-password" || !got.UseTLS {
		t.Errorf("saved SMTP = %+v", got)
	}
}

func TestSetupEmailRejectsBadPort(t *testing.T) {
	_, h := newTestServer(t, testConfig())
	cookie := startWizard(t, h)

	for _, port := range []string{"", "abc", "0", "-1", "70000"} {
		rec := postForm(h, "/setup/email", url.Values{
			"smtp_host": {"mail.example.com"}, "smtp_port": {port}, "smtp_username": {"janet@example.com"},
			"smtp_password": {"pw"}, "smtp_tls": {"on"},
		}, cookie)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "between 1 and 65535") {
			t.Errorf("port %q: status %d; want the form again with a port error", port, rec.Code)
		}
	}
}
