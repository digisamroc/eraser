package sendplan

import (
	"reflect"
	"testing"
	"time"

	"github.com/eraser-privacy/eraser/internal/broker"
)

func brokers(ids ...string) []broker.Broker {
	out := make([]broker.Broker, len(ids))
	for i, id := range ids {
		out[i] = broker.Broker{ID: id}
	}
	return out
}

func ids(bs []broker.Broker) []string {
	out := []string{}
	for _, b := range bs {
		out = append(out, b.ID)
	}
	return out
}

var now = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

func TestBuildSkipsRecentlySent(t *testing.T) {
	last := map[string]time.Time{
		"recent": now.Add(-10 * 24 * time.Hour),
		"old":    now.Add(-40 * 24 * time.Hour),
	}
	p := Build(brokers("recent", "old", "never"), last, 0, Options{Now: now, ResendAfterDays: 30, DailyLimit: 250})
	if got, want := ids(p.Send), []string{"old", "never"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Send = %v, want %v", got, want)
	}
	if got, want := ids(p.SkippedRecent), []string{"recent"}; !reflect.DeepEqual(got, want) {
		t.Errorf("SkippedRecent = %v, want %v", got, want)
	}
}

func TestBuildForceResendIgnoresHistory(t *testing.T) {
	last := map[string]time.Time{"recent": now.Add(-time.Hour)}
	p := Build(brokers("recent"), last, 0, Options{Now: now, ResendAfterDays: 30, DailyLimit: 250, ForceResend: true})
	if len(p.Send) != 1 || len(p.SkippedRecent) != 0 {
		t.Fatalf("plan = %+v", p)
	}
}

func TestBuildDailyCapCountsEarlierSends(t *testing.T) {
	p := Build(brokers("a", "b", "c", "d"), nil, 248, Options{Now: now, ResendAfterDays: 30, DailyLimit: 250})
	if got, want := ids(p.Send), []string{"a", "b"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Send = %v, want %v", got, want)
	}
	if p.Deferred != 2 || p.RemainingToday != 2 {
		t.Errorf("Deferred = %d RemainingToday = %d, want 2, 2", p.Deferred, p.RemainingToday)
	}
}

func TestBuildDailyCapAlreadyReached(t *testing.T) {
	p := Build(brokers("a"), nil, 300, Options{Now: now, ResendAfterDays: 30, DailyLimit: 250})
	if len(p.Send) != 0 || p.Deferred != 1 || p.RemainingToday != 0 {
		t.Fatalf("plan = %+v", p)
	}
}

func TestBuildLimit(t *testing.T) {
	p := Build(brokers("a", "b", "c"), nil, 0, Options{Now: now, ResendAfterDays: 30, DailyLimit: 250, Limit: 1})
	if got, want := ids(p.Send), []string{"a"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Send = %v, want %v", got, want)
	}
	if p.Deferred != 2 {
		t.Errorf("Deferred = %d, want 2", p.Deferred)
	}
}

func TestWindowStart(t *testing.T) {
	if got, want := WindowStart(now), now.Add(-24*time.Hour); !got.Equal(want) {
		t.Fatalf("WindowStart = %v, want %v", got, want)
	}
}
