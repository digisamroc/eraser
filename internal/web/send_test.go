package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eraser-privacy/eraser/internal/broker"
	"github.com/eraser-privacy/eraser/internal/config"
	"github.com/eraser-privacy/eraser/internal/email"
	"github.com/eraser-privacy/eraser/internal/history"
	emaTemplate "github.com/eraser-privacy/eraser/internal/template"
)

type recordingSender struct {
	mu   sync.Mutex
	sent []email.Message
}

func (r *recordingSender) Name() string { return "recording" }
func (r *recordingSender) Send(_ context.Context, m email.Message) email.Result {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, m)
	return email.Result{Success: true, MessageID: fmt.Sprintf("<%d@example.com>", len(r.sent))}
}

func (r *recordingSender) recipients() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, m := range r.sent {
		out = append(out, m.To)
	}
	sort.Strings(out)
	return out
}

func (r *recordingSender) bodies() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, m := range r.sent {
		out = append(out, m.Body)
	}
	return out
}

type sendFixture struct {
	s      *Server
	h      http.Handler
	sender *recordingSender
	store  *history.Store
}

func newSendFixture(t *testing.T, opts config.Options, brokers []broker.Broker) *sendFixture {
	t.Helper()
	store, err := history.NewStore(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	engine, err := emaTemplate.NewEngine()
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig()
	opts.RateLimitMs = 1
	cfg.Options = opts
	s, err := NewServer(testPort, cfg, filepath.Join(t.TempDir(), "config.yaml"),
		&broker.BrokerDatabase{Brokers: brokers}, store, engine)
	if err != nil {
		t.Fatal(err)
	}
	sender := &recordingSender{}
	s.newSender = func(config.EmailConfig) (email.Sender, error) { return sender, nil }
	return &sendFixture{s: s, h: s.setupRouter(), sender: sender, store: store}
}

func sameOrigin(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-origin") }

func (f *sendFixture) sendAll(t *testing.T) (map[string]any, int) {
	t.Helper()
	rec := do(f.h, http.MethodPost, "/api/send-all", sameOrigin)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return body, rec.Code
}

func (f *sendFixture) waitForJob(t *testing.T, id string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		job := f.s.jobManager.Get(id)
		if job == nil {
			t.Fatalf("job %s not found", id)
		}
		if st := job.ToJSON(); st["status"] != JobStatusRunning {
			return st
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("job did not finish")
	return nil
}

func brokersN(ids ...string) []broker.Broker {
	var out []broker.Broker
	for _, id := range ids {
		out = append(out, broker.Broker{ID: id, Name: strings.ToUpper(id), Email: "privacy@" + id + ".example", Region: "us"})
	}
	return out
}

func TestSendAllUsesSharedRules(t *testing.T) {
	bs := brokersN("keep", "excluded", "recent")
	bs = append(bs,
		broker.Broker{ID: "eu", Name: "EU", Email: "privacy@eu.example", Region: "eu"},
		broker.Broker{ID: "form", Name: "FORM", Email: "privacy@form.example", Region: "us", Tags: []string{broker.TagFormOnly}},
	)
	f := newSendFixture(t, config.Options{Template: "ccpa", Regions: []string{"us"}, ExcludedBrokers: []string{"excluded"}}, bs)
	// "recent" was sent successfully yesterday, inside the 30-day window.
	if err := f.store.Add(&history.Record{BrokerID: "recent", BrokerName: "RECENT", Email: "privacy@recent.example",
		Template: "generic", Status: history.StatusSent, SentAt: time.Now().Add(-24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}

	// The broker page's default "pending" filter would already hide "recent";
	// ask for every status so the resend window is what excludes it.
	rec := do(f.h, http.MethodPost, "/api/send-all", func(r *http.Request) {
		sameOrigin(r)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Body = readCloser("status=all")
	})
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %v", rec.Code, body)
	}
	f.waitForJob(t, body["job_id"].(string))

	if got := f.sender.recipients(); strings.Join(got, ",") != "privacy@keep.example" {
		t.Fatalf("sent to %v, want only privacy@keep.example", got)
	}
	if b := f.sender.bodies()[0]; !strings.Contains(b, "California") {
		t.Error("send-all ignored the configured ccpa template")
	}
}

func TestSendOneRefusesWhatSendAllWouldSkip(t *testing.T) {
	f := newSendFixture(t, config.Options{ExcludedBrokers: []string{"excluded"}}, brokersN("ok", "excluded", "recent"))
	if err := f.store.Add(&history.Record{BrokerID: "recent", BrokerName: "RECENT", Email: "privacy@recent.example",
		Template: "generic", Status: history.StatusSent, SentAt: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]string{"excluded": "excluded", "recent": "already sent"} {
		rec := do(f.h, http.MethodPost, "/api/send/"+id, sameOrigin)
		if rec.Code != http.StatusBadRequest || !strings.Contains(strings.ToLower(rec.Body.String()), want) {
			t.Errorf("%s: got %d %q, want 400 mentioning %q", id, rec.Code, rec.Body.String(), want)
		}
	}
	if rec := do(f.h, http.MethodPost, "/api/send/ok", sameOrigin); rec.Code != http.StatusOK {
		t.Fatalf("ok: got %d %s", rec.Code, rec.Body.String())
	}
	if got := f.sender.recipients(); strings.Join(got, ",") != "privacy@ok.example" {
		t.Fatalf("sent to %v", got)
	}
}

func TestSendAllRespectsDailyLimit(t *testing.T) {
	f := newSendFixture(t, config.Options{DailyLimit: 2}, brokersN("a", "b", "c", "d"))
	body, code := f.sendAll(t)
	if code != http.StatusOK {
		t.Fatalf("status %d: %v", code, body)
	}
	f.waitForJob(t, body["job_id"].(string))
	if n := len(f.sender.recipients()); n != 2 {
		t.Fatalf("sent %d, want 2 (daily limit)", n)
	}
	// A second click within 24h sends nothing more.
	if body, code := f.sendAll(t); code != http.StatusBadRequest {
		t.Fatalf("second send-all: status %d %v, want 400", code, body)
	}
}

// Run with -race: the job goroutine writes progress while handlers read it.
func TestJobStatusPollingIsRaceFree(t *testing.T) {
	var ids []string
	for i := range 20 {
		ids = append(ids, fmt.Sprintf("b%02d", i))
	}
	f := newSendFixture(t, config.Options{}, brokersN(ids...))
	body, code := f.sendAll(t)
	if code != http.StatusOK {
		t.Fatalf("status %d: %v", code, body)
	}
	jobID := body["job_id"].(string)

	// Poll until the job has finished, so reads overlap every write,
	// including the final status change.
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				do(f.h, http.MethodGet, "/api/job/active", nil)
				do(f.h, http.MethodGet, "/api/job/"+jobID+"/status", nil)
			}
		}
	}()
	f.waitForJob(t, jobID)
	time.Sleep(20 * time.Millisecond) // keep polling across the final update
	close(stop)
	<-done
}
