package inbox

import (
	"path/filepath"
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
