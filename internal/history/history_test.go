package history

import (
	"path/filepath"
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
