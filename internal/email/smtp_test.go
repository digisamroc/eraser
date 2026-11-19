package email

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eraser-privacy/eraser/internal/config"
)

// testCert returns a self-signed certificate for 127.0.0.1 and a pool trusting it.
func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,

		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// fakeSMTP is a minimal SMTP server that records what a client did.
type fakeSMTP struct {
	addr string
	port int

	mu           sync.Mutex
	authUnderTLS bool
	authSeen     bool
	data         []byte
	from, to     string
}

type fakeOpts struct {
	implicitTLS   bool // TLS from the first byte (port-465 style)
	offerSTARTTLS bool
	silent        bool   // accept the connection but never speak
	dropOnQuit    bool   // close the connection on QUIT without replying
	rejectRcpt    string // reply to RCPT with this line instead of 250
}

func startFakeSMTP(t *testing.T, cert tls.Certificate, opts fakeOpts) *fakeSMTP {
	t.Helper()
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	var ln net.Listener
	var err error
	if opts.implicitTLS {
		ln, err = tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	f := &fakeSMTP{addr: host, port: port}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn, tlsCfg, opts)
		}
	}()
	return f
}

func (f *fakeSMTP) serve(conn net.Conn, tlsCfg *tls.Config, opts fakeOpts) {
	defer func() { _ = conn.Close() }()
	if opts.silent {
		_, _ = io.Copy(io.Discard, conn)
		return
	}
	_, isTLS := conn.(*tls.Conn)
	tp := textproto.NewConn(conn)
	_ = tp.PrintfLine("220 fake ESMTP")
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.Fields(line + " ")[0])
		switch cmd {
		case "EHLO", "HELO":
			exts := []string{"250-fake"}
			if !isTLS && opts.offerSTARTTLS {
				exts = append(exts, "250-STARTTLS")
			}
			exts = append(exts, "250 AUTH PLAIN")
			for _, e := range exts {
				_ = tp.PrintfLine("%s", e)
			}
		case "STARTTLS":
			_ = tp.PrintfLine("220 go ahead")
			tc := tls.Server(conn, tlsCfg)
			if err := tc.Handshake(); err != nil {
				return
			}
			conn, isTLS = tc, true
			tp = textproto.NewConn(conn)
		case "AUTH":
			f.mu.Lock()
			f.authSeen, f.authUnderTLS = true, isTLS
			f.mu.Unlock()
			_ = tp.PrintfLine("235 ok")
		case "MAIL":
			f.mu.Lock()
			f.from = line
			f.mu.Unlock()
			_ = tp.PrintfLine("250 ok")
		case "RCPT":
			if opts.rejectRcpt != "" {
				_ = tp.PrintfLine("%s", opts.rejectRcpt)
				continue
			}
			f.mu.Lock()
			f.to = line
			f.mu.Unlock()
			_ = tp.PrintfLine("250 ok")
		case "DATA":
			_ = tp.PrintfLine("354 go")
			data, err := tp.ReadDotBytes()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.data = data
			f.mu.Unlock()
			_ = tp.PrintfLine("250 queued")
		case "QUIT":
			if !opts.dropOnQuit {
				_ = tp.PrintfLine("221 bye")
			}
			return
		default:
			_ = tp.PrintfLine("250 ok")
		}
	}
}

func (f *fakeSMTP) snapshot() (authSeen, authUnderTLS bool, data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.authSeen, f.authUnderTLS, append([]byte(nil), f.data...)
}

func newTestSender(f *fakeSMTP, pool *x509.CertPool, mode string) *SMTPSender {
	s := NewSMTPSender(config.SMTPConfig{
		Host: f.addr, Port: f.port, Username: "jose@example.com", Password: "app-password",
		UseTLS: true, TLSMode: mode,
	}, "jose@example.com")
	s.rootCAs = pool
	return s
}

var testMsg = Message{
	To:       "privacy@broker.example",
	From:     "jose@example.com",
	FromName: "José Núñez",
	Subject:  "Personal Data Removal Request",
	Body:     "To Whom It May Concern,\n\nPlease delete data about José Núñez.\n\nSincerely,\nJosé",
}

func TestSendSTARTTLS(t *testing.T) {
	cert, pool := testCert(t)
	f := startFakeSMTP(t, cert, fakeOpts{offerSTARTTLS: true})

	res := newTestSender(f, pool, "").Send(context.Background(), testMsg) // non-465 port defaults to STARTTLS
	if !res.Success {
		t.Fatalf("send failed: %v", res.Error)
	}
	authSeen, underTLS, data := f.snapshot()
	if !authSeen || !underTLS {
		t.Fatalf("auth seen=%v underTLS=%v; credentials must only go over TLS", authSeen, underTLS)
	}
	checkMessage(t, data, res.MessageID)
}

func TestSendImplicitTLS(t *testing.T) {
	cert, pool := testCert(t)
	f := startFakeSMTP(t, cert, fakeOpts{implicitTLS: true})

	res := newTestSender(f, pool, config.TLSImplicit).Send(context.Background(), testMsg)
	if !res.Success {
		t.Fatalf("send failed: %v", res.Error)
	}
	if authSeen, underTLS, _ := f.snapshot(); !authSeen || !underTLS {
		t.Fatalf("auth seen=%v underTLS=%v", authSeen, underTLS)
	}
}

func TestSendRefusesWhenSTARTTLSMissing(t *testing.T) {
	cert, pool := testCert(t)
	f := startFakeSMTP(t, cert, fakeOpts{offerSTARTTLS: false})

	res := newTestSender(f, pool, config.TLSStartTLS).Send(context.Background(), testMsg)
	if res.Success {
		t.Fatal("send should fail when the server does not offer STARTTLS")
	}
	if !strings.Contains(res.Error.Error(), "STARTTLS") {
		t.Errorf("error should explain STARTTLS is missing: %v", res.Error)
	}
	if authSeen, _, data := f.snapshot(); authSeen || len(data) > 0 {
		t.Fatalf("no credentials or message may be sent without TLS (auth=%v data=%d bytes)", authSeen, len(data))
	}
}

func TestSendRejectsUntrustedCertificate(t *testing.T) {
	cert, _ := testCert(t)
	f := startFakeSMTP(t, cert, fakeOpts{offerSTARTTLS: true})

	res := newTestSender(f, nil, config.TLSStartTLS).Send(context.Background(), testMsg) // system roots only
	if res.Success {
		t.Fatal("send should fail with an untrusted certificate")
	}
	if authSeen, _, _ := f.snapshot(); authSeen {
		t.Fatal("credentials sent despite certificate failure")
	}
}

func TestSendAuthRequiresTLS(t *testing.T) {
	s := NewSMTPSender(config.SMTPConfig{Host: "127.0.0.1", Port: 1, Username: "u", Password: "p"}, "jose@example.com")
	res := s.Send(context.Background(), testMsg)
	if res.Success || !strings.Contains(res.Error.Error(), "TLS") {
		t.Fatalf("got %+v, want TLS-required error", res)
	}
}

func TestSendHonorsContextDeadline(t *testing.T) {
	cert, pool := testCert(t)
	f := startFakeSMTP(t, cert, fakeOpts{silent: true})

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	res := newTestSender(f, pool, config.TLSStartTLS).Send(ctx, testMsg)
	if res.Success {
		t.Fatal("send to a silent server should fail")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("send ignored the context deadline (took %v)", elapsed)
	}
}

func TestBuildMessageRejectsHeaderInjection(t *testing.T) {
	for name, m := range map[string]Message{
		"subject":   {To: "a@b.example", From: "c@d.example", Subject: "hi\r\nBcc: x@evil.example"},
		"from name": {To: "a@b.example", From: "c@d.example", FromName: "Jose\nBcc: x@evil.example", Subject: "hi"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := buildMessage(m, time.Now(), "<id@d.example>"); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

// checkMessage parses what the server received and checks headers and body.
func checkMessage(t *testing.T, data []byte, messageID string) {
	t.Helper()
	msg, err := mail.ReadMessage(bufio.NewReader(bytes.NewReader(data)))
	if err != nil {
		t.Fatalf("received message does not parse: %v\n%s", err, data)
	}
	h := msg.Header

	from, err := mail.ParseAddress(h.Get("From"))
	if err != nil || from.Name != "José Núñez" || from.Address != "jose@example.com" {
		t.Errorf("From = %q -> %+v, %v", h.Get("From"), from, err)
	}
	if strings.ContainsAny(h.Get("From"), "éúñ") {
		t.Errorf("From header must be RFC 2047 encoded, got %q", h.Get("From"))
	}
	if to, err := mail.ParseAddress(h.Get("To")); err != nil || to.Address != "privacy@broker.example" {
		t.Errorf("To = %q", h.Get("To"))
	}
	if subj, err := new(mime.WordDecoder).DecodeHeader(h.Get("Subject")); err != nil || subj != testMsg.Subject {
		t.Errorf("Subject = %q", h.Get("Subject"))
	}
	if d, err := h.Date(); err != nil || time.Since(d) > time.Minute {
		t.Errorf("Date = %q (%v)", h.Get("Date"), err)
	}
	id := h.Get("Message-Id")
	if !strings.HasPrefix(id, "<") || !strings.HasSuffix(id, "@example.com>") || id != messageID {
		t.Errorf("Message-ID = %q, result MessageID = %q", id, messageID)
	}
	if h.Get("Content-Transfer-Encoding") != "quoted-printable" {
		t.Errorf("Content-Transfer-Encoding = %q", h.Get("Content-Transfer-Encoding"))
	}

	body, err := io.ReadAll(quotedprintable.NewReader(msg.Body))
	if err != nil {
		t.Fatal(err)
	}
	// SMTP DATA always ends with a line break, so compare without trailing newlines.
	got := strings.TrimRight(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n")
	if got != strings.TrimRight(testMsg.Body, "\n") {
		t.Errorf("body round-trip:\n got %q\nwant %q", got, testMsg.Body)
	}
}

// Once the server accepts the message (250 after DATA), it will be delivered.
// A failed QUIT must not turn that into a failure, or the next run resends.
func TestSendSucceedsWhenQuitFails(t *testing.T) {
	cert, pool := testCert(t)
	f := startFakeSMTP(t, cert, fakeOpts{offerSTARTTLS: true, dropOnQuit: true})

	res := newTestSender(f, pool, "").Send(context.Background(), testMsg)
	if !res.Success || res.MessageID == "" {
		t.Fatalf("accepted message reported as failed: %+v", res)
	}
	if _, _, data := f.snapshot(); len(data) == 0 {
		t.Fatal("no message delivered")
	}
}

// A rejected recipient is the broker's problem, not the user's settings.
func TestSendReportsRecipientRejection(t *testing.T) {
	cert, pool := testCert(t)
	f := startFakeSMTP(t, cert, fakeOpts{offerSTARTTLS: true, rejectRcpt: "550 5.1.1 No such user"})

	res := newTestSender(f, pool, "").Send(context.Background(), testMsg)
	if res.Success {
		t.Fatal("send should fail")
	}
	msg := res.Error.Error()
	if !strings.Contains(msg, "recipient rejected") || !strings.Contains(msg, "550") || strings.Contains(msg, "configuration") {
		t.Errorf("error = %q, want the recipient rejection and its reply code", msg)
	}
}

// Personal data must never go over plaintext SMTP to another machine.
func TestSendRefusesPlaintextToRemoteHost(t *testing.T) {
	s := NewSMTPSender(config.SMTPConfig{Host: "smtp.example.com", Port: 25}, "jose@example.com")
	res := s.Send(context.Background(), testMsg)
	if res.Success || !strings.Contains(res.Error.Error(), "TLS") {
		t.Fatalf("got %+v, want a TLS-required error", res)
	}
}

// A local relay (e.g. on 127.0.0.1) may be plaintext.
func TestSendAllowsPlaintextToLoopback(t *testing.T) {
	cert, _ := testCert(t)
	f := startFakeSMTP(t, cert, fakeOpts{})
	s := NewSMTPSender(config.SMTPConfig{Host: f.addr, Port: f.port}, "jose@example.com")
	if res := s.Send(context.Background(), testMsg); !res.Success {
		t.Fatalf("send to loopback relay failed: %v", res.Error)
	}
}
