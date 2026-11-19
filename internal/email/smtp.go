package email

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/eraser-privacy/eraser/internal/config"
)

var errNoSTARTTLS = errors.New("SMTP server does not offer STARTTLS; refusing to send without TLS")

type SMTPSender struct {
	config config.SMTPConfig
	from   string

	rootCAs *x509.CertPool // nil uses the system roots; set by tests
}

func NewSMTPSender(cfg config.SMTPConfig, from string) *SMTPSender {
	return &SMTPSender{config: cfg, from: from}
}

func (s *SMTPSender) Name() string { return "smtp" }

func (s *SMTPSender) Send(ctx context.Context, msg Message) Result {
	if err := validateMessage(msg); err != nil {
		return Result{Success: false, Error: err}
	}
	mode := s.config.EffectiveTLSMode()
	if mode == config.TLSNone && s.config.Username != "" {
		return Result{Success: false, Error: fmt.Errorf("SMTP auth requires TLS")}
	}

	messageID, err := newMessageID(msg.From)
	if err != nil {
		return Result{Success: false, Error: err}
	}
	data, err := buildMessage(msg, time.Now(), messageID)
	if err != nil {
		return Result{Success: false, Error: err}
	}

	if err := s.deliver(ctx, mode, msg.From, msg.To, data); err != nil {
		return Result{Success: false, Error: sanitizeSMTPError(err)}
	}
	return Result{Success: true, MessageID: messageID}
}

func sanitizeSMTPError(err error) error {
	if errors.Is(err, errNoSTARTTLS) {
		return errNoSTARTTLS
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return fmt.Errorf("SMTP timed out or was cancelled")
	}
	s := strings.ToLower(err.Error())
	if strings.Contains(s, "auth") {
		return fmt.Errorf("SMTP authentication failed")
	}
	if strings.Contains(s, "certificate") || strings.Contains(s, "x509") {
		return fmt.Errorf("TLS certificate error")
	}
	return fmt.Errorf("SMTP error: check your configuration")
}

// deliver runs the SMTP conversation. With implicit TLS the connection is
// encrypted from the start; with STARTTLS it is upgraded before AUTH and
// fails closed if the server doesn't offer it.
func (s *SMTPSender) deliver(ctx context.Context, mode, from, to string, data []byte) error {
	addr := net.JoinHostPort(s.config.Host, strconv.Itoa(s.config.Port))
	tlsCfg := &tls.Config{
		ServerName: s.config.Host,
		MinVersion: tls.VersionTLS12,
		RootCAs:    s.rootCAs,
	}

	var conn net.Conn
	var err error
	if mode == config.TLSImplicit {
		conn, err = (&tls.Dialer{Config: tlsCfg}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("connect failed: %w", err)
	}
	// net/smtp has no context support: bound the whole conversation by the
	// deadline, and close the connection if ctx is cancelled first.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	client, err := smtp.NewClient(conn, s.config.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("SMTP greeting failed: %w", errors.Join(err, ctx.Err()))
	}
	defer func() { _ = client.Close() }()

	if mode == config.TLSStartTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errNoSTARTTLS
		}
		if err := client.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("STARTTLS failed: %w", err)
		}
	}

	if s.config.Username != "" {
		auth := smtp.PlainAuth("", s.config.Username, s.config.Password, s.config.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}
	}
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("sender rejected: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("recipient rejected: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("data command failed: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("message write failed: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("message finalization failed: %w", err)
	}
	return client.Quit()
}

// buildMessage renders RFC 5322 headers and a quoted-printable UTF-8 body.
func buildMessage(msg Message, now time.Time, messageID string) ([]byte, error) {
	for name, v := range map[string]string{"subject": msg.Subject, "sender name": msg.FromName} {
		if strings.ContainsAny(v, "\r\n") {
			return nil, fmt.Errorf("%s contains a line break", name)
		}
	}

	from := (&mail.Address{Name: msg.FromName, Address: msg.From}).String()
	to := (&mail.Address{Address: msg.To}).String()

	var b bytes.Buffer
	header := func(k, v string) { fmt.Fprintf(&b, "%s: %s\r\n", k, v) }
	header("From", from)
	header("To", to)
	header("Subject", mime.QEncoding.Encode("utf-8", msg.Subject))
	header("Date", now.Format(time.RFC1123Z))
	header("Message-ID", messageID)
	header("MIME-Version", "1.0")
	header("Content-Type", "text/plain; charset=utf-8")
	header("Content-Transfer-Encoding", "quoted-printable")
	b.WriteString("\r\n")

	qp := quotedprintable.NewWriter(&b)
	if _, err := qp.Write([]byte(msg.Body)); err != nil {
		return nil, fmt.Errorf("failed to encode body: %w", err)
	}
	if err := qp.Close(); err != nil {
		return nil, fmt.Errorf("failed to encode body: %w", err)
	}
	return b.Bytes(), nil
}

// newMessageID returns a unique "<random@sender-domain>" Message-ID.
func newMessageID(from string) (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate Message-ID: %w", err)
	}
	domain := from[strings.LastIndex(from, "@")+1:]
	return "<" + hex.EncodeToString(buf) + "@" + domain + ">", nil
}
