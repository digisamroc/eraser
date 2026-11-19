package history

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func add(t *testing.T, s *Store, brokerID string, status Status, at time.Time) {
	t.Helper()
	if err := s.Add(&Record{BrokerID: brokerID, BrokerName: brokerID, Email: brokerID + "@example.com",
		Template: "generic", Status: status, SentAt: at}); err != nil {
		t.Fatal(err)
	}
}

func TestGetAllBrokerStatusesRoundTrip(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	add(t, s, "acme", StatusSent, now.Add(-time.Hour))
	add(t, s, "acme", StatusFailed, now)

	statuses, err := s.GetAllBrokerStatuses()
	if err != nil {
		t.Fatalf("GetAllBrokerStatuses: %v", err)
	}
	got := statuses["acme"]
	if got.Status != StatusFailed || got.TotalSent != 2 {
		t.Errorf("status = %+v", got)
	}
	if d := got.LastSent.Sub(now); d < -time.Second || d > time.Second {
		t.Errorf("LastSent = %v, want ~%v", got.LastSent, now)
	}
}

func TestBrokerResponseRoundTrip(t *testing.T) {
	s := newTestStore(t)
	received := time.Now().Add(-2 * time.Hour)
	in := &BrokerResponse{
		BrokerID: "acme", BrokerName: "Acme", ResponseType: "info_required",
		EmailFrom: "privacy@acme.example", EmailSubject: "Re: request", EmailBody: "Please send your address.",
		FormURL: "https://acme.example/dsr", Confidence: 0.8, NeedsReview: true, Authenticated: true,
		ReceivedAt: received, MessageID: "<r1@acme.example>",
	}
	if err := s.AddBrokerResponse(in); err != nil {
		t.Fatalf("AddBrokerResponse: %v", err)
	}
	all, err := s.GetAllBrokerResponses()
	if err != nil || len(all) != 1 {
		t.Fatalf("GetAllBrokerResponses = %v, %v", all, err)
	}
	got := all[0]
	if got.EmailBody != in.EmailBody || !got.Authenticated || got.FormURL != in.FormURL || !got.NeedsReview ||
		got.MessageID != in.MessageID {
		t.Errorf("round trip lost fields: %+v", got)
	}
	if d := got.ReceivedAt.Sub(received); d < -time.Second || d > time.Second {
		t.Errorf("ReceivedAt = %v, want ~%v", got.ReceivedAt, received)
	}
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt not parsed")
	}
}

// Databases created by older versions have no email_body, authenticated or
// message_id column; opening them must add all three.
func TestMigrateAddsBrokerResponseColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.db")
	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(`CREATE TABLE broker_responses (
		id INTEGER PRIMARY KEY AUTOINCREMENT, broker_id TEXT NOT NULL, broker_name TEXT NOT NULL,
		response_type TEXT NOT NULL, email_from TEXT, email_subject TEXT, form_url TEXT, confirm_url TEXT,
		confidence REAL, needs_review INTEGER DEFAULT 0, received_at DATETIME, processed_at DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	_ = old.Close()

	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if err := s.AddBrokerResponse(&BrokerResponse{BrokerID: "a", BrokerName: "A", ResponseType: "success", EmailBody: "b",
		Authenticated: true, MessageID: "<m@a.example>"}); err != nil {
		t.Fatalf("insert into migrated table: %v", err)
	}
}

func TestBrokerResponseBodyIsCapped(t *testing.T) {
	s := newTestStore(t)
	big := strings.Repeat("x", MaxStoredBodyBytes+500)
	if err := s.AddBrokerResponse(&BrokerResponse{BrokerID: "a", BrokerName: "A", ResponseType: "unknown", EmailBody: big}); err != nil {
		t.Fatal(err)
	}
	all, _ := s.GetAllBrokerResponses()
	if n := len(all[0].EmailBody); n != MaxStoredBodyBytes {
		t.Fatalf("stored body is %d bytes, want %d", n, MaxStoredBodyBytes)
	}
}

func TestSentMessageIDs(t *testing.T) {
	s := newTestStore(t)
	for _, r := range []*Record{
		{BrokerID: "acme", BrokerName: "Acme", Email: "p@acme.example", Template: "generic", Status: StatusSent, MessageID: "<abc@me.example>", SentAt: time.Now()},
		{BrokerID: "beta", BrokerName: "Beta", Email: "p@beta.example", Template: "generic", Status: StatusFailed, MessageID: "", SentAt: time.Now()},
	} {
		if err := s.Add(r); err != nil {
			t.Fatal(err)
		}
	}
	ids, err := s.SentMessageIDs()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids["<abc@me.example>"] != "acme" {
		t.Fatalf("SentMessageIDs = %v", ids)
	}
}

func TestLastSuccessfulSends(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	add(t, s, "sent-twice", StatusSent, now.Add(-48*time.Hour))
	add(t, s, "sent-twice", StatusSent, now.Add(-time.Hour))
	add(t, s, "failed-only", StatusFailed, now)

	last, err := s.LastSuccessfulSends()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := last["failed-only"]; ok {
		t.Error("failed sends must not count as sent")
	}
	if d := last["sent-twice"].Sub(now.Add(-time.Hour)); d < -time.Second || d > time.Second {
		t.Errorf("last sent = %v, want the most recent send", last["sent-twice"])
	}
}

func TestCountSentSince(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	add(t, s, "a", StatusSent, now.Add(-30*time.Hour))
	add(t, s, "b", StatusSent, now.Add(-time.Minute))
	add(t, s, "c", StatusSent, now)
	add(t, s, "d", StatusFailed, now)

	n, err := s.CountSentSince(now.Add(-24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("CountSentSince = %d, want 2", n)
	}
}

func TestCountSentSinceAcrossTimeZones(t *testing.T) {
	s := newTestStore(t)
	// The same instant recorded in different zones must compare by instant,
	// not by string.
	tokyo := time.FixedZone("JST", 9*3600)
	cutoff := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	add(t, s, "before", StatusSent, cutoff.Add(-time.Hour).In(tokyo)) // 20:00 JST, earlier instant
	add(t, s, "after", StatusSent, cutoff.Add(time.Hour))             // 13:00 UTC

	n, err := s.CountSentSince(cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("CountSentSince = %d, want 1", n)
	}
}
