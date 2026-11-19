package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
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

	rec = do(h, http.MethodGet, "/setup/complete", func(r *http.Request) { r.AddCookie(cookie) })
	if rec.Code != http.StatusOK {
		t.Fatalf("complete: status %d", rec.Code)
	}

	got := s.config
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
	if got := s.config.Options.Disclose; !reflect.DeepEqual(got, []string{"location", "date_of_birth"}) {
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
	if got := s.config.Options.Disclose; len(got) != 0 {
		t.Fatalf("Disclose = %v, want none", got)
	}

	// Unknown values are rejected and change nothing.
	postForm(h, "/settings/disclose", url.Values{"disclose": {"location"}})
	rec = postForm(h, "/settings/disclose", url.Values{"disclose": {"ssn"}})
	if !strings.Contains(rec.Body.String(), "unknown disclose value") {
		t.Errorf("no error shown for invalid value")
	}
	if got := s.config.Options.Disclose; !reflect.DeepEqual(got, []string{"location"}) {
		t.Fatalf("invalid post changed Disclose to %v", got)
	}
}
