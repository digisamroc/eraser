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

	if res, err := h.ClickConfirmationLink(broker.URL+"/ok", allowed); err != nil || !res.Success {
		t.Fatalf("/ok: res=%+v err=%v", res, err)
	}
	if res, err := h.ClickConfirmationLink(broker.URL+"/hop", allowed); err != nil || !res.Success {
		t.Fatalf("same-host redirect: res=%+v err=%v", res, err)
	}

	res, err := h.ClickConfirmationLink(broker.URL+"/away", allowed)
	if err == nil || res.Success {
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

// mustHost returns raw's host:port; raw always comes from httptest.
func mustHost(_ *testing.T, raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u.Host
}
