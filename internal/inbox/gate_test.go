package inbox

import (
	"strings"
	"testing"
)

const formReply = "We do not process requests via email. Please complete our opt-out form: https://acme.example/opt-out and confirm here https://acme.example/confirm?token=abc"

func TestUnauthenticatedEmailLinksAreDropped(t *testing.T) {
	e := &Email{From: "privacy@acme.example", FromDomain: "acme.example", Subject: "Your request", Body: formReply}

	got := ClassifyResponse(e)
	if got.FormURL != "" || got.ConfirmURL != "" || len(got.URLs.AllURLs) != 0 {
		t.Errorf("links kept from an unverified sender: form=%q confirm=%q all=%v", got.FormURL, got.ConfirmURL, got.URLs.AllURLs)
	}
	if !got.NeedsReview || !strings.Contains(got.Reason, "not verified") {
		t.Errorf("NeedsReview=%v Reason=%q", got.NeedsReview, got.Reason)
	}

	e.Authenticated = true
	got = ClassifyResponse(e)
	if got.FormURL != "https://acme.example/opt-out" || got.ConfirmURL == "" {
		t.Errorf("authenticated email lost its links: form=%q confirm=%q", got.FormURL, got.ConfirmURL)
	}
}

// Eraser's own test email goes to the user's address and never matches a
// broker, so "test email" wording in broker mail means nothing.
func TestTestEmailWordingIsNotSuccess(t *testing.T) {
	e := &Email{From: "privacy@acme.example", FromDomain: "acme.example", Authenticated: true,
		Subject: "Eraser Test Email", Body: "This is a test email. Please confirm: https://acme.example/confirm?token=abc"}
	if got := ClassifyResponse(e); got.Type == ResponseSuccess {
		t.Fatalf("broker email with test-email wording classified as success: %+v", got)
	}
}

func TestInfoRequired(t *testing.T) {
	for _, body := range []string{
		"We were unable to locate your records with the information provided. Please provide your full mailing address.",
		"In order to locate your information, we need additional details such as your date of birth.",
		"We require more information to process your request. Please reply with your phone number.",
		"Could not find a profile matching your name. Please send your address so we can search again.",
	} {
		e := &Email{From: "privacy@acme.example", FromDomain: "acme.example", Subject: "Re: deletion request", Body: body, Authenticated: true}
		if got := ClassifyResponse(e); got.Type != ResponseInfoRequired {
			t.Errorf("%q\n  classified as %s, want %s", body, got.Type, ResponseInfoRequired)
		}
	}
}

func TestInfoRequiredDoesNotSwallowRejections(t *testing.T) {
	e := &Email{From: "privacy@acme.example", FromDomain: "acme.example", Subject: "Re: request", Authenticated: true,
		Body: "We do not have any data about you. No records found in our database."}
	if got := ClassifyResponse(e); got.Type != ResponseRejected {
		t.Errorf("classified as %s, want %s", got.Type, ResponseRejected)
	}
}
