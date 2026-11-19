package sendplan

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eraser-privacy/eraser/internal/broker"
	"github.com/eraser-privacy/eraser/internal/config"
	"github.com/eraser-privacy/eraser/internal/email"
	"github.com/eraser-privacy/eraser/internal/history"
	"github.com/eraser-privacy/eraser/internal/template"
)

type fakeHistory struct {
	last   map[string]time.Time
	window int
}

func (f fakeHistory) LastSuccessfulSends() (map[string]time.Time, error) { return f.last, nil }
func (f fakeHistory) CountSentSince(time.Time) (int, error)              { return f.window, nil }

func TestForConfigAppliesFiltersThenRules(t *testing.T) {
	candidates := []broker.Broker{
		{ID: "keep", Name: "Keep", Region: "us"},
		{ID: "excluded", Name: "Excluded", Region: "us"},
		{ID: "eu-only", Name: "EU", Region: "eu"},
		{ID: "form", Name: "Form", Region: "us", Tags: []string{broker.TagFormOnly}},
		{ID: "recent", Name: "Recent", Region: "us"},
		{ID: "global", Name: "Global", Region: "global"},
	}
	opts := config.Options{Regions: []string{"us"}, ExcludedBrokers: []string{"excluded"}}
	h := fakeHistory{last: map[string]time.Time{"recent": now.Add(-time.Hour)}, window: 5}

	p, err := ForConfig(candidates, opts, h, now, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := ids(p.Send), []string{"keep", "global"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("Send = %v, want %v", got, want)
	}
	if got := ids(p.SkippedRecent); len(got) != 1 || got[0] != "recent" {
		t.Errorf("SkippedRecent = %v", got)
	}
	if p.SentInWindow != 5 || p.RemainingToday != config.DefaultDailyLimit-5 {
		t.Errorf("SentInWindow=%d RemainingToday=%d", p.SentInWindow, p.RemainingToday)
	}
}

type fakeSender struct {
	sent []email.Message
	fail error
}

func (f *fakeSender) Name() string { return "fake" }
func (f *fakeSender) Send(_ context.Context, m email.Message) email.Result {
	f.sent = append(f.sent, m)
	if f.fail != nil {
		return email.Result{Error: f.fail}
	}
	return email.Result{Success: true, MessageID: "<id@example.com>"}
}

func newDeliverer(t *testing.T, sender email.Sender, opts config.Options) Deliverer {
	t.Helper()
	store, err := history.NewStore(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	engine, err := template.NewEngine()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Profile: config.Profile{FirstName: "Jane", LastName: "Doe", Email: "jane@example.com", DateOfBirth: "1990-01-01"},
		Email:   config.EmailConfig{From: "jane@example.com"},
		Options: opts,
	}
	return Deliverer{Config: cfg, Engine: engine, Sender: sender, Store: store}
}

var acme = broker.Broker{ID: "acme", Name: "Acme", Email: "privacy@acme.example", Region: "us"}

func TestDeliverSendsAndRecords(t *testing.T) {
	sender := &fakeSender{}
	d := newDeliverer(t, sender, config.Options{Template: "ccpa"})

	rec, err := d.Deliver(context.Background(), config.Disclosure{}, acme)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != history.StatusSent || rec.MessageID != "<id@example.com>" || rec.Template != "ccpa" {
		t.Errorf("record = %+v", rec)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("sent %d messages", len(sender.sent))
	}
	m := sender.sent[0]
	if m.To != acme.Email || m.FromName != "Jane Doe" || !strings.Contains(m.Body, "California") {
		t.Errorf("message = %+v (want the configured ccpa template)", m)
	}
	if strings.Contains(m.Body, "1990-01-01") {
		t.Error("date of birth sent without being disclosed")
	}
	last, err := d.Store.LastSuccessfulSends()
	if err != nil || last["acme"].IsZero() {
		t.Fatalf("send not recorded in history: %v %v", last, err)
	}
}

func TestDeliverRecordsFailures(t *testing.T) {
	d := newDeliverer(t, &fakeSender{fail: errors.New("SMTP authentication failed")}, config.Options{})

	rec, err := d.Deliver(context.Background(), config.Disclosure{}, acme)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != history.StatusFailed || !strings.Contains(rec.Error, "authentication") || rec.Template != "generic" {
		t.Errorf("record = %+v", rec)
	}
	if last, _ := d.Store.LastSuccessfulSends(); !last["acme"].IsZero() {
		t.Error("failed send counted as successful")
	}
}

func TestDeliverRefusesFormOnly(t *testing.T) {
	sender := &fakeSender{}
	d := newDeliverer(t, sender, config.Options{})
	form := acme
	form.Tags = []string{broker.TagFormOnly}

	if _, err := d.Deliver(context.Background(), config.Disclosure{}, form); err == nil {
		t.Fatal("expected error for a form-only broker")
	}
	if len(sender.sent) != 0 {
		t.Fatal("form-only broker was emailed")
	}
}
