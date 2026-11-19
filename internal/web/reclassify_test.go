package web

import (
	"net/http"
	"testing"
	"time"

	"github.com/eraser-privacy/eraser/internal/config"
	"github.com/eraser-privacy/eraser/internal/history"
	"github.com/eraser-privacy/eraser/internal/inbox"
)

// Reclassify only has the stored row, which can't tell an HTML body from
// plain text and has no sender domain. The links were taken from the real
// email when it was fetched, so reclassifying must keep them: re-extracting
// them from the row turned "&amp;" into part of the URL and broke the token.
func TestReclassifyKeepsStoredLinks(t *testing.T) {
	f := newSendFixture(t, config.Options{}, brokersN("acme"))
	const confirm = "https://acme.example/confirm?id=1&token=abc"
	html := `<p>Please confirm your request.</p>` +
		`<a href="https://help.other.example/x">help</a> ` +
		`<a href="https://acme.example/confirm?id=1&amp;token=abc">Confirm</a>`
	resp := &history.BrokerResponse{
		BrokerID: "acme", BrokerName: "ACME", ResponseType: string(inbox.ResponseUnknown),
		EmailFrom: "privacy@acme.example", EmailSubject: "Please confirm your request",
		EmailBody: html, ConfirmURL: confirm, Authenticated: true,
		ReceivedAt: time.Now(), MessageID: "<1@acme.example>",
	}
	if err := f.store.AddBrokerResponse(resp); err != nil {
		t.Fatal(err)
	}

	if rec := do(f.h, http.MethodPost, "/api/inbox/reclassify", sameOrigin); rec.Code != http.StatusOK {
		t.Fatalf("reclassify: %d %s", rec.Code, rec.Body.String())
	}

	got, err := f.store.GetAllBrokerResponses()
	if err != nil || len(got) != 1 {
		t.Fatalf("responses = %v, %v", got, err)
	}
	if got[0].ResponseType != string(inbox.ResponseConfirmationRequired) {
		t.Errorf("type = %q, want it reclassified as %q", got[0].ResponseType, inbox.ResponseConfirmationRequired)
	}
	if got[0].ConfirmURL != confirm {
		t.Errorf("ConfirmURL = %q, want the stored %q", got[0].ConfirmURL, confirm)
	}
}
