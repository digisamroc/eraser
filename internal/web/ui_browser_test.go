package web

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"

	"github.com/eraser-privacy/eraser/internal/broker"
	"github.com/eraser-privacy/eraser/internal/config"
	"github.com/eraser-privacy/eraser/internal/email"
	"github.com/eraser-privacy/eraser/internal/history"
	emaTemplate "github.com/eraser-privacy/eraser/internal/template"
)

// requireChrome skips with -short and when Chrome isn't installed, except in
// CI, where a missing Chrome must fail (as in internal/browser).
func requireChrome(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("drives a real browser; skipped with -short")
	}
	defer func() {
		if t.Skipped() && os.Getenv("CI") != "" {
			t.Fatal("Chrome is required in CI")
		}
	}()
	for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"} {
		if _, err := exec.LookPath(name); err == nil {
			return
		}
	}
	if runtime.GOOS == "darwin" {
		if _, err := os.Stat("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"); err == nil {
			return
		}
	}
	t.Skip("Chrome not installed")
}

// watchPage runs before any page script: it records CSP violations and
// script errors, and accepts confirm() dialogs (which would block the test).
const watchPage = `
window.__problems = [];
document.addEventListener('securitypolicyviolation', function(e) {
  window.__problems.push('CSP ' + e.violatedDirective + ' ' + e.blockedURI + ' ' + (e.sample || ''));
});
window.addEventListener('error', function(e) { window.__problems.push('error: ' + e.message); });
window.confirm = function() { return true; };
`

type uiFixture struct {
	base   string
	store  *history.Store
	sender *recordingSender
	ctx    context.Context
}

func newUIFixture(t *testing.T) *uiFixture {
	t.Helper()
	requireChrome(t)

	store, err := history.NewStore(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	engine, err := emaTemplate.NewEngine()
	if err != nil {
		t.Fatal(err)
	}

	// The Host check needs the real port, so listen first.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	cfg := testConfig()
	cfg.Options.RateLimitMs = 1
	s, err := NewServer(port, cfg, filepath.Join(t.TempDir(), "config.yaml"),
		&broker.BrokerDatabase{Brokers: brokersN("a", "b", "c")}, store, engine)
	if err != nil {
		t.Fatal(err)
	}
	sender := &recordingSender{}
	s.newSender = func(config.EmailConfig) (email.Sender, error) { return sender, nil }
	srv := &http.Server{Handler: s.setupRouter(), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), chromedp.DefaultExecAllocatorOptions[:]...)
	t.Cleanup(cancelAlloc)
	ctx, cancel := chromedp.NewContext(allocCtx)
	t.Cleanup(cancel)
	_, err = chromedp.Run(ctx, chromedp.Action[page.AddScriptToEvaluateOnNewDocumentResult](
		func(ctx context.Context, tg *chromedp.Target) (page.AddScriptToEvaluateOnNewDocumentResult, error) {
			return cdp.Call(ctx, tg, page.AddScriptToEvaluateOnNewDocument, page.AddScriptToEvaluateOnNewDocumentParams{Source: watchPage})
		}))
	if err != nil {
		t.Fatal(err)
	}
	return &uiFixture{base: fmt.Sprintf("http://localhost:%d", port), store: store, sender: sender, ctx: ctx}
}

// visit loads a page and fails on any CSP violation or script error so far.
func (f *uiFixture) visit(t *testing.T, path string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.ctx, 15*time.Second)
	defer cancel()
	if _, err := chromedp.Run(ctx, chromedp.Navigate(f.base+path)); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	f.noProblems(t, path)
}

func (f *uiFixture) noProblems(t *testing.T, where string) {
	t.Helper()
	if problems := eval[[]string](t, f, "window.__problems"); len(problems) > 0 {
		t.Errorf("%s: %q", where, problems)
	}
}

func eval[T any](t *testing.T, f *uiFixture, js string) T {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
	defer cancel()
	v, err := chromedp.Run(ctx, chromedp.Evaluate[T](js))
	if err != nil {
		t.Fatalf("evaluate %s: %v", js, err)
	}
	return v
}

// click clicks the element as a user would trigger it (a dispatched click).
func (f *uiFixture) click(t *testing.T, selector string) {
	t.Helper()
	if !eval[bool](t, f, fmt.Sprintf(`(function(){ var el = document.querySelector(%q); if (!el) return false; el.click(); return true; })()`, selector)) {
		t.Fatalf("no element %s", selector)
	}
}

func (f *uiFixture) waitFor(t *testing.T, what, js string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !eval[bool](t, f, js) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Every page must run under the CSP (no inline scripts), and every action
// that used to be an inline handler must still work.
func TestUIWorksUnderCSP(t *testing.T) {
	f := newUIFixture(t)
	for _, r := range []*history.Record{
		{BrokerID: "a", BrokerName: "A", Email: "privacy@a.example", Template: "generic", Status: history.StatusSent, SentAt: time.Now()},
		{BrokerID: "b", BrokerName: "B", Email: "privacy@b.example", Template: "generic", Status: history.StatusFailed, SentAt: time.Now()},
	} {
		if err := f.store.Add(r); err != nil {
			t.Fatal(err)
		}
	}
	task := &history.PendingTask{BrokerID: "a", BrokerName: "A", TaskType: history.TaskCaptcha,
		FormURL: "https://a.example/form", Status: "pending", BrowserState: `{"email":"jane@example.com"}`}
	if err := f.store.AddPendingTask(task); err != nil {
		t.Fatal(err)
	}

	// Dashboard: progress computed server-side (1 of 3 sent).
	f.visit(t, "/")
	if got := eval[string](t, f, `document.getElementById('progress-percent').textContent`); got != "33%" {
		t.Errorf("dashboard progress = %q, want 33%%", got)
	}

	// Theme toggle and the inbox settings toggle.
	f.visit(t, "/settings")
	light := eval[bool](t, f, `document.documentElement.classList.contains('light')`)
	f.click(t, "#theme-toggle")
	if eval[bool](t, f, `document.documentElement.classList.contains('light')`) == light {
		t.Error("theme toggle did nothing")
	}
	hidden := eval[bool](t, f, `document.getElementById('inbox-form').classList.contains('hidden')`)
	f.click(t, `[data-action="toggle"][data-target="inbox-form"]`)
	if eval[bool](t, f, `document.getElementById('inbox-form').classList.contains('hidden')`) == hidden {
		t.Error("inbox settings toggle did nothing")
	}
	f.noProblems(t, "/settings after clicks")

	// History: counts computed server-side, then "Clear Failed".
	f.visit(t, "/history")
	if got := eval[string](t, f, `document.getElementById('success-rate').textContent`); got != "50%" {
		t.Errorf("success rate = %q, want 50%%", got)
	}
	f.click(t, `[data-action="clear-failed"]`)
	f.waitFor(t, "clear-failed result", `document.getElementById('clear-result').textContent.includes('Refresh page')`)
	f.noProblems(t, "/history after clear")

	// Filters.
	f.visit(t, "/tasks")
	f.click(t, `.filter-btn[data-filter="completed"]`)
	if !eval[bool](t, f, `document.querySelector('.filter-btn[data-filter="completed"]').classList.contains('active')`) {
		t.Error("tasks filter did nothing")
	}
	f.visit(t, "/pipeline")

	// Task helper: the page records "opened" with an htmx POST on load.
	f.visit(t, "/tasks/"+strconv.FormatInt(task.ID, 10)+"/helper")
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, err := f.store.GetPendingTaskByID(task.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.OpenedAt.Valid {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("helper page never recorded the task as opened")
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Send to All: the job runs and the page shows its result. Pending are c
	// (never sent) and b (its failed record was cleared above).
	f.visit(t, "/brokers")
	f.click(t, `[data-action="send-all"]`)
	f.waitFor(t, "send-all completion", `document.getElementById('send-all-progress').textContent.includes('Complete!')`)
	if got := f.sender.recipients(); !slices.Equal(got, []string{"privacy@b.example", "privacy@c.example"}) {
		t.Errorf("sent to %v, want b and c", got)
	}
	f.noProblems(t, "/brokers after send-all")
}

// A send job stopped by an error shows that error, not "Complete!".
func TestUIShowsSendJobError(t *testing.T) {
	f := newUIFixture(t)
	f.visit(t, "/brokers")
	f.sender.setOnSend(func() { _ = f.store.Close() })

	f.click(t, `[data-action="send-all"]`)
	f.waitFor(t, "send-all to stop", `document.getElementById('send-all-progress').textContent.includes('Stopped')`)
	text := eval[string](t, f, `document.getElementById('send-all-progress').textContent`)
	if strings.Contains(text, "Complete!") || !strings.Contains(text, "may have been sent") {
		t.Errorf("progress area = %q", text)
	}
	f.noProblems(t, "/brokers after a failed send-all")
}
