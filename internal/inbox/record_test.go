package inbox

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eraser-privacy/eraser/internal/history"
)

func newStore(t *testing.T) *history.Store {
	t.Helper()
	s, err := history.NewStore(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Add(&history.Record{BrokerID: "acme", BrokerName: "Acme", Email: "privacy@acme.example",
		Template: "generic", Status: history.StatusSent, SentAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	return s
}

func pipelineStatus(t *testing.T, s *history.Store) history.PipelineStatus {
	t.Helper()
	stats, err := s.GetPipelineStats()
	if err != nil {
		t.Fatal(err)
	}
	for status, n := range stats {
		if n > 0 {
			return status
		}
	}
	return ""
}

const removedBody = "We have removed your information. Your data has been deleted."

func TestRecordUpdatesPipelineOnlyForAuthenticatedMail(t *testing.T) {
	s := newStore(t)
	spoof := &Email{BrokerID: "acme", BrokerName: "Acme", From: "privacy@acme.example", FromDomain: "acme.example",
		Subject: "Done", Body: removedBody}
	if _, err := Record(s, spoof, ClassifyResponse(spoof)); err != nil {
		t.Fatal(err)
	}
	if got := pipelineStatus(t, s); got == history.PipelineConfirmed {
		t.Fatal("unverified 'removal complete' email marked the broker confirmed")
	}

	real := *spoof
	real.Authenticated = true
	real.Subject = "Done (verified)"
	if _, err := Record(s, &real, ClassifyResponse(&real)); err != nil {
		t.Fatal(err)
	}
	if got := pipelineStatus(t, s); got != history.PipelineConfirmed {
		t.Fatalf("pipeline status = %q, want confirmed", got)
	}

	all, _ := s.GetAllBrokerResponses()
	if len(all) != 2 {
		t.Fatalf("stored %d responses, want 2", len(all))
	}
}

func TestRecordUpdatesInsteadOfDuplicating(t *testing.T) {
	s := newStore(t)
	e := &Email{BrokerID: "acme", BrokerName: "Acme", From: "privacy@acme.example", FromDomain: "acme.example",
		Subject: "Your request", Body: formReply}

	inserted, err := Record(s, e, ClassifyResponse(e))
	if err != nil || !inserted {
		t.Fatalf("first Record: inserted=%v err=%v", inserted, err)
	}
	// The same email seen again, now verified: update in place.
	e.Authenticated = true
	inserted, err = Record(s, e, ClassifyResponse(e))
	if err != nil || inserted {
		t.Fatalf("second Record: inserted=%v err=%v", inserted, err)
	}
	all, _ := s.GetAllBrokerResponses()
	if len(all) != 1 || !all[0].Authenticated || all[0].FormURL == "" {
		t.Fatalf("responses = %+v", all)
	}
}

// A stored body must come from the same email as the stored authenticated
// flag: reclassification takes links from the body whenever the flag is set.
func assertBodiesMatchVerification(t *testing.T, s *history.Store, attackerURL string) {
	t.Helper()
	all, err := s.GetAllBrokerResponses()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range all {
		c := ClassifyResponse(&Email{From: r.EmailFrom, Subject: r.EmailSubject, Body: r.EmailBody, Authenticated: r.Authenticated})
		if strings.Contains(c.ConfirmURL+c.FormURL, attackerURL) {
			t.Errorf("row %d (authenticated=%v) yields the spoofed link on reclassification: body=%q", r.ID, r.Authenticated, r.EmailBody)
		}
	}
}

const spoofedConfirm = "Please confirm: https://acme.example/attacker-chosen/confirm?token=x"

func TestRecordNeverPairsSpoofedBodyWithVerifiedFlag(t *testing.T) {
	for _, withIDs := range []bool{true, false} {
		t.Run(fmt.Sprintf("message-ids=%v", withIDs), func(t *testing.T) {
			s := newStore(t)
			spoof := &Email{BrokerID: "acme", BrokerName: "Acme", From: "privacy@acme.example", FromDomain: "acme.example",
				Subject: "Re: Personal Data Removal Request", Body: spoofedConfirm}
			real := &Email{BrokerID: "acme", BrokerName: "Acme", From: "privacy@acme.example", FromDomain: "acme.example",
				Subject: spoof.Subject, Body: removedBody, Authenticated: true}
			if withIDs {
				spoof.MessageID, real.MessageID = "<spoof@evil.example>", "<real@acme.example>"
			}
			for _, e := range []*Email{spoof, real} {
				if _, err := Record(s, e, ClassifyResponse(e)); err != nil {
					t.Fatal(err)
				}
			}
			assertBodiesMatchVerification(t, s, "attacker-chosen")
		})
	}
}

// Brokers often send "received" and later "completed" with the same subject.
// Each is its own response, and each keeps its own body.
func TestRecordKeepsDistinctEmailsWithTheSameSubject(t *testing.T) {
	s := newStore(t)
	received := &Email{BrokerID: "acme", BrokerName: "Acme", From: "privacy@acme.example", FromDomain: "acme.example",
		Subject: "Re: Personal Data Removal Request", MessageID: "<1@acme.example>", Authenticated: true,
		Body: "We have received your request and will process it within 45 days."}
	done := *received
	done.MessageID, done.Body = "<2@acme.example>", removedBody
	for _, e := range []*Email{received, &done} {
		if _, err := Record(s, e, ClassifyResponse(e)); err != nil {
			t.Fatal(err)
		}
	}
	all, _ := s.GetAllBrokerResponses()
	if len(all) != 2 {
		t.Fatalf("stored %d responses, want 2", len(all))
	}
	bodies := map[string]bool{all[0].EmailBody: true, all[1].EmailBody: true}
	if !bodies[received.Body] || !bodies[removedBody] {
		t.Errorf("bodies = %v", bodies)
	}
}

// An unverified email reusing a verified email's Message-ID is a forgery; it
// must not replace the verified response.
func TestRecordUnverifiedNeverReplacesVerified(t *testing.T) {
	s := newStore(t)
	real := &Email{BrokerID: "acme", BrokerName: "Acme", From: "privacy@acme.example", FromDomain: "acme.example",
		Subject: "Confirm your request", MessageID: "<1@acme.example>", Authenticated: true,
		Body: "Please confirm: https://acme.example/confirm?token=real"}
	forged := *real
	forged.Authenticated, forged.Body = false, "Nothing to see here."
	for _, e := range []*Email{real, &forged} {
		if _, err := Record(s, e, ClassifyResponse(e)); err != nil {
			t.Fatal(err)
		}
	}
	all, _ := s.GetAllBrokerResponses()
	if len(all) != 1 || !all[0].Authenticated || all[0].EmailBody != real.Body || all[0].ConfirmURL == "" {
		t.Fatalf("responses = %+v", all)
	}
}
