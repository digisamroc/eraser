package browser

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

func TestClickConfirmationLinkChecksEveryHop(t *testing.T) {
	var foreignHits atomic.Int32
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreignHits.Add(1)
		_, _ = fmt.Fprint(w, "Your request has been confirmed")
	}))
	t.Cleanup(foreign.Close)

	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			_, _ = fmt.Fprint(w, "Your request has been confirmed")
		case "/hop":
			http.Redirect(w, r, "/ok", http.StatusFound)
		case "/away":
			http.Redirect(w, r, foreign.URL+"/collect?token=abc", http.StatusFound)
		}
	}))
	t.Cleanup(broker.Close)

	brokerHost := mustHost(t, broker.URL)
	allowed := func(u *url.URL) bool { return u.Host == brokerHost }
	h := NewConfirmationHandler()

	if res, err := h.ClickConfirmationLink(broker.URL+"/ok", allowed); err != nil || res.Outcome != ConfirmConfirmed {
		t.Fatalf("/ok: res=%+v err=%v", res, err)
	}
	if res, err := h.ClickConfirmationLink(broker.URL+"/hop", allowed); err != nil || res.Outcome != ConfirmConfirmed {
		t.Fatalf("same-host redirect: res=%+v err=%v", res, err)
	}

	res, err := h.ClickConfirmationLink(broker.URL+"/away", allowed)
	if err == nil || res.Outcome == ConfirmConfirmed {
		t.Fatalf("redirect to another host was followed: res=%+v", res)
	}
	if foreignHits.Load() != 0 {
		t.Fatal("request reached the foreign host")
	}

	if _, err := h.ClickConfirmationLink(foreign.URL+"/collect", allowed); err == nil {
		t.Fatal("disallowed first URL was requested")
	}
	if foreignHits.Load() != 0 {
		t.Fatal("request reached the foreign host")
	}
}

// Only a page that clearly says it worked counts as confirmed. Words inside
// scripts don't count, and a page with mixed or no signals is unknown, so the
// broker's status is left alone.
func TestClassifyConfirmation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   ConfirmOutcome
	}{
		{"confirmed", 200, "<h1>Your request has been confirmed</h1>", ConfirmConfirmed},
		{"plain text", 200, "Opt-out complete.", ConfirmConfirmed},
		{"error page that says thank you", 200, "<p>Something went wrong. Thank you for your patience.</p>", ConfirmFailed},
		{"expired", 200, "<p>This link has expired.</p>", ConfirmFailed},
		{"no signal", 200, "<title>Acme</title><p>Welcome to Acme</p>", ConfirmUnknown},
		{"mixed signals", 200, "<p>Your request could not be confirmed.</p>", ConfirmUnknown},
		{"already confirmed", 200, "<p>This request was already confirmed.</p>", ConfirmUnknown},
		{"script words ignored", 200, "<p>Request confirmed</p><script>console.error('request failed')</script>", ConfirmConfirmed},
		{"style words ignored", 200, "<style>.failed{color:red}</style><p>Welcome</p>", ConfirmUnknown},
		{"error status", 404, "<p>Confirmed</p>", ConfirmFailed},
		{"server error", 500, "", ConfirmFailed},
	} {
		if got := classifyConfirmation(tc.status, tc.body); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A 200 page that doesn't say whether it worked is not reported as confirmed.
func TestClickConfirmationLinkWithoutSignalIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "<html><body><p>Welcome to Acme</p></body></html>")
	}))
	t.Cleanup(srv.Close)
	host := mustHost(t, srv.URL)

	res, err := NewConfirmationHandler().ClickConfirmationLink(srv.URL, func(u *url.URL) bool { return u.Host == host })
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != ConfirmUnknown {
		t.Errorf("Outcome = %v, want unknown", res.Outcome)
	}
}

// mustHost returns raw's host:port; raw always comes from httptest.
func mustHost(_ *testing.T, raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u.Host
}
