package inbox

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/backend"
	"github.com/emersion/go-imap/backend/memory"
	"github.com/emersion/go-imap/server"
	"github.com/eraser-privacy/eraser/internal/broker"
	"github.com/eraser-privacy/eraser/internal/config"
)

// fetchLog records every FETCH the client sends, so tests can check that
// bodies are only requested with PEEK and only for broker messages.
type fetchLog struct {
	mu      sync.Mutex
	fetches []fetchCall

	// backend serializes access to the memory backend, which has no locking
	// of its own; tests add messages while the server reads.
	backend  sync.Mutex
	selects  int    // mailbox Status calls (one per SELECT/EXAMINE), under mu
	onSearch func() // if set, runs (once) before the next SEARCH, under mu
}

type fetchCall struct {
	mailbox string
	seqSet  string
	items   []imap.FetchItem
}

func (l *fetchLog) bodyFetches(mailbox string) []fetchCall {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []fetchCall
	for _, f := range l.fetches {
		if f.mailbox != mailbox {
			continue
		}
		for _, it := range f.items {
			if strings.HasPrefix(string(it), "BODY") || strings.HasPrefix(string(it), "RFC822") {
				out = append(out, f)
				break
			}
		}
	}
	return out
}

type recBackend struct {
	*memory.Backend
	log     *fetchLog
	updates chan backend.Update // pushed to clients, e.g. during IDLE
}

func (b recBackend) Updates() <-chan backend.Update { return b.updates }

func (b recBackend) Login(ci *imap.ConnInfo, user, pass string) (backend.User, error) {
	u, err := b.Backend.Login(ci, user, pass)
	if err != nil {
		return nil, err
	}
	return recUser{u, b.log}, nil
}

type recUser struct {
	backend.User
	log *fetchLog
}

func (u recUser) GetMailbox(name string) (backend.Mailbox, error) {
	mb, err := u.User.GetMailbox(name)
	if err != nil {
		return nil, err
	}
	return recMailbox{mb, u.log}, nil
}

type recMailbox struct {
	backend.Mailbox
	log *fetchLog
}

func (m recMailbox) ListMessages(uid bool, seq *imap.SeqSet, items []imap.FetchItem, ch chan<- *imap.Message) error {
	m.log.mu.Lock()
	m.log.fetches = append(m.log.fetches, fetchCall{m.Name(), seq.String(), append([]imap.FetchItem(nil), items...)})
	m.log.mu.Unlock()
	m.log.backend.Lock()
	defer m.log.backend.Unlock()
	return m.Mailbox.ListMessages(uid, seq, items, ch)
}

func (m recMailbox) Info() (*imap.MailboxInfo, error) {
	m.log.backend.Lock()
	defer m.log.backend.Unlock()
	return m.Mailbox.Info()
}

func (m recMailbox) Status(items []imap.StatusItem) (*imap.MailboxStatus, error) {
	m.log.mu.Lock()
	m.log.selects++
	m.log.mu.Unlock()
	m.log.backend.Lock()
	defer m.log.backend.Unlock()
	return m.Mailbox.Status(items)
}

func (m recMailbox) SearchMessages(uid bool, criteria *imap.SearchCriteria) ([]uint32, error) {
	m.log.mu.Lock()
	hook := m.log.onSearch
	m.log.onSearch = nil
	m.log.mu.Unlock()
	if hook != nil {
		hook()
	}
	m.log.backend.Lock()
	defer m.log.backend.Unlock()
	return m.Mailbox.SearchMessages(uid, criteria)
}

func (m recMailbox) CreateMessage(flags []string, date time.Time, body imap.Literal) error {
	m.log.backend.Lock()
	defer m.log.backend.Unlock()
	return m.Mailbox.CreateMessage(flags, date, body)
}

func (m recMailbox) UpdateMessagesFlags(uid bool, seq *imap.SeqSet, op imap.FlagsOp, flags []string) error {
	m.log.backend.Lock()
	defer m.log.backend.Unlock()
	return m.Mailbox.UpdateMessagesFlags(uid, seq, op, flags)
}

func (m recMailbox) CopyMessages(uid bool, seq *imap.SeqSet, dest string) error {
	m.log.backend.Lock()
	defer m.log.backend.Unlock()
	return m.Mailbox.CopyMessages(uid, seq, dest)
}

func (m recMailbox) Expunge() error {
	m.log.backend.Lock()
	defer m.log.backend.Unlock()
	return m.Mailbox.Expunge()
}

func testTLS(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:   time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, IsCA: true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}, pool
}

type imapFixture struct {
	backend recBackend
	monitor *Monitor
	cfg     config.InboxConfig
	tls     *tls.Config
	user    backend.User
	log     *fetchLog
	uids    map[string]uint32 // message label -> UID in INBOX
}

func message(from, subject string, extraHeaders []string, body string) string {
	var b strings.Builder
	for _, h := range extraHeaders {
		b.WriteString(h + "\r\n")
	}
	fmt.Fprintf(&b, "From: %s\r\nTo: me@example.com\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%d@test>\r\nContent-Type: text/plain\r\n\r\n%s",
		from, subject, time.Now().Format(time.RFC1123Z), time.Now().UnixNano(), body)
	return b.String()
}

func addMessage(t *testing.T, u backend.User, mailbox, raw string) uint32 {
	t.Helper()
	mb, err := u.GetMailbox(mailbox)
	if err != nil {
		t.Fatal(err)
	}
	if err := mb.CreateMessage(nil, time.Now(), bytes.NewBufferString(raw)); err != nil {
		t.Fatal(err)
	}
	rec := mb.(recMailbox)
	rec.log.backend.Lock()
	defer rec.log.backend.Unlock()
	mem := rec.Mailbox.(*memory.Mailbox)
	return mem.Messages[len(mem.Messages)-1].Uid
}

func newIMAPFixture(t *testing.T) *imapFixture {
	t.Helper()
	log := &fetchLog{}
	be := recBackend{memory.New(), log, make(chan backend.Update, 16)}
	tlsCfg, pool := testTLS(t)

	srv := server.New(be)
	srv.TLSConfig = tlsCfg
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	u, err := be.Login(nil, "username", "password")
	if err != nil {
		t.Fatal(err)
	}
	f := &imapFixture{backend: be, user: u, log: log, uids: map[string]uint32{}}

	// INBOX already holds one personal message (UID 6) from the memory backend.
	f.uids["friend"] = addMessage(t, u, "INBOX", message("Friend <friend@gmail.com>", "dinner?", nil,
		"Here's the menu: https://example.org/opt-out-of-dinner"))
	f.uids["acme"] = addMessage(t, u, "INBOX", message("Acme Privacy <privacy@acme.example>", "Your request",
		[]string{"Authentication-Results: mx.test; dkim=pass header.d=acme.example; dmarc=pass header.from=acme.example"},
		formReply))
	f.uids["spoof"] = addMessage(t, u, "INBOX", message("Acme Privacy <privacy@acme.example>", "Action required",
		[]string{
			"Authentication-Results: mx.test; spf=fail smtp.mailfrom=evil.example; dmarc=fail header.from=acme.example",
			"Authentication-Results: mx.test; dmarc=pass header.from=acme.example", // forged by the sender
		},
		"Please complete our opt-out form: https://evil.example/opt-out"))
	f.uids["reply"] = addMessage(t, u, "INBOX", message("Support <support@helpdesk.example>", "Re: Personal Data Removal Request",
		[]string{"In-Reply-To: <sent1@me.example>", "Authentication-Results: mx.test; dkim=pass header.d=helpdesk.example"},
		"We were unable to locate your records. Please provide your full mailing address."))

	// The archive folder has its own UIDs, overlapping INBOX's (including 6).
	if err := u.CreateMailbox("Eraser"); err != nil {
		t.Fatal(err)
	}
	for i := range 10 {
		addMessage(t, u, "Eraser", message("Acme Privacy <privacy@acme.example>", fmt.Sprintf("Old %d", i),
			[]string{"Authentication-Results: mx.test; dmarc=pass header.from=acme.example"}, "Request completed."))
	}

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	f.cfg = config.InboxConfig{Server: "127.0.0.1", Port: port, Email: "username", Password: "password", Folder: "INBOX",
		AuthServID: "mx.test"}
	f.tls = &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}
	f.monitor = f.connect(t, f.cfg)
	return f
}

// connect opens a monitor on the fixture's server with the given settings.
func (f *imapFixture) connect(t *testing.T, cfg config.InboxConfig) *Monitor {
	t.Helper()
	m := NewMonitor(cfg, []broker.Broker{
		{ID: "acme", Name: "Acme", Email: "privacy@acme.example", Website: "https://www.acme.example"},
		{ID: "beta", Name: "Beta", Email: "privacy@beta.example"},
		{ID: "freemail", Name: "Freemail Broker", Email: "somebroker@gmail.com"}, // must never match gmail senders
	})
	m.tlsConfig = f.tls
	m.SetSentMessageIDs(map[string]string{"<sent1@me.example>": "beta"})
	if err := m.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Disconnect() })
	return m
}

func byUID(emails []Email) map[uint32]Email {
	out := map[uint32]Email{}
	for _, e := range emails {
		out[e.UID] = e
	}
	return out
}

func TestFetchBrokerEmails(t *testing.T) {
	f := newIMAPFixture(t)
	emails, err := f.monitor.FetchBrokerEmails(context.Background(), 7)
	if err != nil {
		t.Fatal(err)
	}
	got := byUID(emails)

	if _, ok := got[f.uids["friend"]]; ok {
		t.Error("personal Gmail message treated as a broker email")
	}
	if _, ok := got[6]; ok {
		t.Error("unrelated message treated as a broker email")
	}

	acme := got[f.uids["acme"]]
	if acme.BrokerID != "acme" || !acme.Authenticated || !strings.Contains(acme.Body, "opt-out form") || acme.Folder != "INBOX" {
		t.Errorf("acme email = %+v", acme)
	}

	spoof := got[f.uids["spoof"]]
	if spoof.BrokerID != "acme" || spoof.Authenticated {
		t.Errorf("spoofed email must match the broker but not be authenticated (forged lower header): %+v", spoof)
	}
	if c := ClassifyResponse(&spoof); c.FormURL != "" || !c.NeedsReview {
		t.Errorf("spoofed email produced form URL %q", c.FormURL)
	}

	reply := got[f.uids["reply"]]
	if reply.BrokerID != "beta" || !reply.Authenticated {
		t.Errorf("reply matched by In-Reply-To = %+v", reply)
	}
	if c := ClassifyResponse(&reply); c.Type != ResponseInfoRequired {
		t.Errorf("reply classified as %s, want info_required", c.Type)
	}
}

func TestFetchNeverMarksReadAndOnlyDownloadsBrokerBodies(t *testing.T) {
	f := newIMAPFixture(t)
	if _, err := f.monitor.FetchBrokerEmails(context.Background(), 7); err != nil {
		t.Fatal(err)
	}
	bodies := f.log.bodyFetches("INBOX")
	if len(bodies) == 0 {
		t.Fatal("no body fetches recorded")
	}
	for _, call := range bodies {
		for _, it := range call.items {
			s := string(it)
			if (strings.HasPrefix(s, "BODY[") || strings.HasPrefix(s, "RFC822")) && !strings.HasPrefix(s, "RFC822.SIZE") {
				t.Errorf("non-PEEK body fetch %q would mark mail as read", s)
			}
		}
		set, _ := imap.ParseSeqSet(call.seqSet)
		for _, private := range []uint32{6, f.uids["friend"]} {
			if set.Contains(private) {
				t.Errorf("downloaded the body of non-broker message UID %d (fetch %s %v)", private, call.seqSet, call.items)
			}
		}
	}
}

func TestArchiveOnlyMovesMessagesFromTheirOwnFolder(t *testing.T) {
	f := newIMAPFixture(t)
	ctx := context.Background()
	inbox, err := f.monitor.FetchBrokerEmails(ctx, 7)
	if err != nil {
		t.Fatal(err)
	}
	archived, err := f.monitor.FetchBrokerEmailsFromFolder(ctx, "Eraser", 7)
	if err != nil {
		t.Fatal(err)
	}
	all := append(inbox, archived...)

	n, err := f.monitor.ArchiveEmails(all, "Eraser")
	if err != nil {
		t.Fatal(err)
	}
	if n != len(inbox) {
		t.Errorf("archived %d, want %d (only INBOX messages)", n, len(inbox))
	}

	mb, _ := f.user.GetMailbox("INBOX")
	remaining := map[uint32]bool{}
	for _, msg := range mb.(recMailbox).Mailbox.(*memory.Mailbox).Messages {
		remaining[msg.Uid] = true
	}
	for _, uid := range []uint32{6, f.uids["friend"]} {
		if !remaining[uid] {
			t.Errorf("personal message UID %d was moved out of INBOX", uid)
		}
	}
	for _, label := range []string{"acme", "spoof", "reply"} {
		if remaining[f.uids[label]] {
			t.Errorf("%s message was not archived", label)
		}
	}
}

func TestFetchSinceUIDOnlyReturnsNewMessages(t *testing.T) {
	f := newIMAPFixture(t)
	ctx := context.Background()
	_, next, err := f.monitor.fetchSince(ctx, "INBOX", 0)
	if err != nil {
		t.Fatal(err)
	}
	newUID := addMessage(t, f.user, "INBOX", message("Acme Privacy <privacy@acme.example>", "Done",
		[]string{"Authentication-Results: mx.test; dmarc=pass header.from=acme.example"}, "Request completed."))

	emails, _, err := f.monitor.fetchSince(ctx, "INBOX", next)
	if err != nil {
		t.Fatal(err)
	}
	if len(emails) != 1 || emails[0].UID != newUID {
		t.Fatalf("fetchSince returned %d emails %+v, want only UID %d", len(emails), emails, newUID)
	}
}

func TestMatchBroker(t *testing.T) {
	m := NewMonitor(config.InboxConfig{}, []broker.Broker{
		{ID: "spokeo", Email: "privacy@spokeo.com", Website: "https://www.spokeo.com"},
		{ID: "freemail", Email: "x@gmail.com"},
		{ID: "zd", Email: "privacy@mtalley.zendesk.com"},
	})
	tests := map[string]string{
		"spokeo.com":           "spokeo",
		"mail.spokeo.com":      "spokeo",
		"SPOKEO.COM":           "spokeo",
		"notspokeo.com":        "",
		"spokeo.com.evil.test": "",
		"gmail.com":            "",
		"mtalley.zendesk.com":  "zd",
		"other.zendesk.com":    "",
		"com":                  "",
		"":                     "",
	}
	for domain, want := range tests {
		b, ok := m.matchBroker(domain)
		if got := map[bool]string{true: b.ID, false: ""}[ok]; got != want {
			t.Errorf("matchBroker(%q) = %q, want %q", domain, got, want)
		}
	}
}

// With no known authserv-id, the topmost Authentication-Results header could
// be the sender's own, so nothing counts as verified.
func TestFetchFailsClosedWithoutAuthServ(t *testing.T) {
	f := newIMAPFixture(t)
	cfg := f.cfg
	cfg.AuthServID = ""
	m := f.connect(t, cfg)
	if m.VerifiesSenders() {
		t.Fatal("VerifiesSenders() = true with no authserv-id")
	}
	emails, err := m.FetchBrokerEmails(context.Background(), 7)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range emails {
		if e.Authenticated {
			t.Errorf("UID %d authenticated without a known authserv-id", e.UID)
		}
	}
	if !f.monitor.VerifiesSenders() {
		t.Error("VerifiesSenders() = false with authserv_id set")
	}
}

const deliveryReport = "From: Mail Delivery Subsystem <mailer-daemon@googlemail.com>\r\n" +
	"Authentication-Results: mx.test; dkim=pass header.d=googlemail.com\r\n" +
	"To: me@example.com\r\n" +
	"Subject: Delivery Status Notification (Failure)\r\n" +
	"Message-ID: <dsn1@mx.google.com>\r\n" +
	"In-Reply-To: <sent-acme@me.example>\r\n" +
	"References: <sent-acme@me.example>\r\n" +
	"MIME-Version: 1.0\r\n" +
	"Content-Type: multipart/report; report-type=delivery-status; boundary=\"b1\"\r\n" +
	"\r\n" +
	"--b1\r\n" +
	"Content-Type: text/plain; charset=UTF-8\r\n" +
	"\r\n" +
	"Address not found. Your message wasn't delivered to privacy@acme.example.\r\n" +
	"--b1\r\n" +
	"Content-Type: message/delivery-status\r\n" +
	"\r\n" +
	"Reporting-MTA: dns; googlemail.com\r\n" +
	"\r\n" +
	"Final-Recipient: rfc822; Privacy@Acme.example\r\n" +
	"Action: failed\r\n" +
	"Status: 5.1.1\r\n" +
	"--b1\r\n" +
	"Content-Type: message/rfc822\r\n" +
	"\r\n" +
	"Message-ID: <sent-acme@me.example>\r\n" +
	"From: Me <me@example.com>\r\n" +
	"To: privacy@acme.example\r\n" +
	"Subject: Personal Data Removal Request\r\n" +
	"\r\n" +
	"Please delete my data.\r\n" +
	"--b1--\r\n"

func TestFetchBounceReadsDeliveryReport(t *testing.T) {
	f := newIMAPFixture(t)
	uid := addMessage(t, f.user, "INBOX", deliveryReport)

	emails, err := f.monitor.FetchBounceEmails(context.Background(), 7)
	if err != nil {
		t.Fatal(err)
	}
	e, ok := byUID(emails)[uid]
	if !ok {
		t.Fatal("delivery report not fetched as a bounce")
	}
	if !e.Authenticated {
		t.Error("delivery report not authenticated")
	}
	if len(e.ReturnedMessageIDs) != 1 || e.ReturnedMessageIDs[0] != "<sent-acme@me.example>" {
		t.Errorf("ReturnedMessageIDs = %q", e.ReturnedMessageIDs)
	}
	if len(e.FailedRecipients) != 1 || e.FailedRecipients[0] != "privacy@acme.example" {
		t.Errorf("FailedRecipients = %q", e.FailedRecipients)
	}
	if len(e.References) != 1 || e.References[0] != "<sent-acme@me.example>" {
		t.Errorf("References = %q", e.References)
	}
	if !strings.Contains(e.Body, "Address not found") {
		t.Errorf("Body = %q", e.Body)
	}
}

// notifyNewMail tells clients with INBOX selected about new mail. The server
// writes "* N EXISTS" and "* N RECENT": two updates for one message, as real
// servers commonly do.
func (f *imapFixture) notifyNewMail(t *testing.T) {
	t.Helper()
	mb, err := f.user.GetMailbox("INBOX")
	if err != nil {
		t.Fatal(err)
	}
	status, err := mb.Status([]imap.StatusItem{imap.StatusMessages, imap.StatusRecent})
	if err != nil {
		t.Fatal(err)
	}
	f.backend.updates <- &backend.MailboxUpdate{Update: backend.NewUpdate("username", "INBOX"), MailboxStatus: status}
}

func TestWatchDeliversEachNewMessage(t *testing.T) {
	f := newIMAPFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan Email, 10)
	// Open INBOX before the watch starts, so no SELECT overlaps a pushed
	// update: go-imap's test server reads a connection's selected mailbox
	// without a lock when pushing (a server-side race, not ours).
	if err := f.monitor.examine("INBOX"); err != nil {
		t.Fatal(err)
	}
	var watchErr error
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		watchErr = f.monitor.WatchForNewEmails(ctx, func(e Email) { got <- e })
	}()
	// Registered after the fixture's, so it runs first: stop the watch before
	// the connection is closed, on every exit path.
	t.Cleanup(func() {
		cancel()
		select {
		case <-watchDone:
		case <-time.After(5 * time.Second):
		}
	})

	for i := range 3 {
		time.Sleep(100 * time.Millisecond)
		subject := fmt.Sprintf("Done %d", i)
		addMessage(t, f.user, "INBOX", message("Acme Privacy <privacy@acme.example>", subject,
			[]string{"Authentication-Results: mx.test; dmarc=pass header.from=acme.example"}, "Request completed."))
		f.notifyNewMail(t)
		select {
		case e := <-got:
			if e.Subject != subject || e.BrokerID != "acme" {
				t.Fatalf("message %d: got %q from %q", i, e.Subject, e.BrokerID)
			}
		case <-time.After(5 * time.Second):
			cancel()
			t.Fatalf("message %d never delivered: the watch is stuck", i)
		}
	}

	// The watch must stay idle between messages. Re-selecting the folder on
	// each fetch made the server's SELECT replies look like new mail: a loop.
	selects := func() int {
		f.log.mu.Lock()
		defer f.log.mu.Unlock()
		return f.log.selects
	}
	before := selects()
	time.Sleep(300 * time.Millisecond)
	if after := selects(); after != before {
		t.Errorf("watch keeps selecting the mailbox while idle (%d -> %d): busy loop", before, after)
	}

	cancel()
	select {
	case <-watchDone:
		if !errors.Is(watchErr, context.Canceled) {
			t.Errorf("watch ended with %v, want context.Canceled", watchErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watch did not stop after cancel")
	}
}

// A server that accepts the connection but never answers must not hang a
// scan past its deadline.
func TestConnectHonorsContext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	m := NewMonitor(config.InboxConfig{Server: "127.0.0.1", Port: port, Email: "u", Password: "p"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- m.Connect(ctx) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Connect succeeded against a silent server")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Connect ignored its context deadline")
	}
}

// A message that arrives between SELECT and SEARCH is returned by this fetch;
// the next fetch must start after it, or it is delivered twice.
func TestFetchSinceNeverReturnsAMessageTwice(t *testing.T) {
	f := newIMAPFixture(t)
	ctx := context.Background()
	_, next, err := f.monitor.fetchSince(ctx, "INBOX", 0)
	if err != nil {
		t.Fatal(err)
	}

	var lateUID uint32
	f.log.mu.Lock()
	f.log.onSearch = func() {
		lateUID = addMessage(t, f.user, "INBOX", message("Acme Privacy <privacy@acme.example>", "Late",
			[]string{"Authentication-Results: mx.test; dmarc=pass header.from=acme.example"}, "Request completed."))
	}
	f.log.mu.Unlock()

	first, next, err := f.monitor.fetchSince(ctx, "INBOX", next)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || first[0].UID != lateUID {
		t.Fatalf("first fetch = %v, want the late message (UID %d)", first, lateUID)
	}
	again, _, err := f.monitor.fetchSince(ctx, "INBOX", next)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Fatalf("late message delivered again: %v (next=%d)", again, next)
	}
}
