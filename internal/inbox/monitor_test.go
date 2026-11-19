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
	log *fetchLog
}

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
	return m.Mailbox.ListMessages(uid, seq, items, ch)
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
	monitor *Monitor
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
	mem := mb.(recMailbox).Mailbox.(*memory.Mailbox)
	return mem.Messages[len(mem.Messages)-1].Uid
}

func newIMAPFixture(t *testing.T) *imapFixture {
	t.Helper()
	log := &fetchLog{}
	be := recBackend{memory.New(), log}
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
	f := &imapFixture{user: u, log: log, uids: map[string]uint32{}}

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
	m := NewMonitor(config.InboxConfig{Server: "127.0.0.1", Port: port, Email: "username", Password: "password", Folder: "INBOX"},
		[]broker.Broker{
			{ID: "acme", Name: "Acme", Email: "privacy@acme.example", Website: "https://www.acme.example"},
			{ID: "beta", Name: "Beta", Email: "privacy@beta.example"},
			{ID: "freemail", Name: "Freemail Broker", Email: "somebroker@gmail.com"}, // must never match gmail senders
		})
	m.tlsConfig = &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}
	m.SetSentMessageIDs(map[string]string{"<sent1@me.example>": "beta"})
	if err := m.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Disconnect() })
	f.monitor = m
	return f
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
