package inbox

import (
	"errors"
	"testing"

	"github.com/eraser-privacy/eraser/internal/broker"
)

func bounceBrokers() *broker.BrokerDatabase {
	return &broker.BrokerDatabase{Brokers: []broker.Broker{
		{ID: "acme", Name: "Acme", Email: "privacy@acme.example"},
		{ID: "beta", Name: "Beta", Email: "privacy@beta.example"},
	}}
}

var sentRequests = map[string]string{"<sent-acme@me.example>": "acme", "<sent-beta@me.example>": "beta"}

func TestVerifyBounce(t *testing.T) {
	const failedText = "Delivery to the following recipient failed permanently: privacy@acme.example"
	tests := []struct {
		name    string
		email   Email
		want    string // broker ID, or "" for rejected
		wantErr error
	}{
		{"real bounce returning our message",
			Email{From: "mailer-daemon@googlemail.com", Authenticated: true, Body: failedText,
				ReturnedMessageIDs: []string{"<sent-acme@me.example>"}, FailedRecipients: []string{"privacy@acme.example"}},
			"acme", nil},
		{"real bounce referencing our message by In-Reply-To",
			Email{From: "mailer-daemon@googlemail.com", Authenticated: true, Body: failedText, InReplyTo: "<sent-acme@me.example>"},
			"acme", nil},
		{"real bounce referencing our message by References",
			Email{From: "mailer-daemon@googlemail.com", Authenticated: true, Body: failedText,
				References: []string{"<other@x.example>", "<sent-acme@me.example>"}},
			"acme", nil},
		// Anyone can authenticate mail from their own domain and name a broker.
		{"forged bounce from an authenticated attacker domain",
			Email{From: "mailer-daemon@attacker.example", Authenticated: true, Body: failedText,
				FailedRecipients: []string{"privacy@acme.example"}},
			"", ErrBounceNotOurs},
		{"returned message we never sent",
			Email{From: "mailer-daemon@attacker.example", Authenticated: true, Body: failedText,
				ReturnedMessageIDs: []string{"<guess@me.example>"}},
			"", ErrBounceNotOurs},
		{"our message, but a different failed recipient",
			Email{From: "mailer-daemon@googlemail.com", Authenticated: true, Body: failedText,
				ReturnedMessageIDs: []string{"<sent-acme@me.example>"}, FailedRecipients: []string{"privacy@beta.example"}},
			"", ErrBounceWrongRecipient},
		{"unauthenticated",
			Email{From: "mailer-daemon@googlemail.com", Body: failedText, ReturnedMessageIDs: []string{"<sent-acme@me.example>"}},
			"", ErrBounceUnverified},
		{"refers to two different brokers",
			Email{From: "mailer-daemon@googlemail.com", Authenticated: true, Body: failedText,
				ReturnedMessageIDs: []string{"<sent-acme@me.example>", "<sent-beta@me.example>"}},
			"", ErrBounceNotOurs},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := VerifyBounce(&tt.email, sentRequests, bounceBrokers())
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) || b != nil {
					t.Fatalf("VerifyBounce() = %v, %v; want error %v", b, err, tt.wantErr)
				}
				return
			}
			if err != nil || b == nil || b.ID != tt.want {
				t.Fatalf("VerifyBounce() = %v, %v; want %s", b, err, tt.want)
			}
		})
	}
}
