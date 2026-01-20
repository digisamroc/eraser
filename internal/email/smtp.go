package email

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"

	"github.com/eraser-privacy/eraser/internal/config"
)

type SMTPSender struct {
	config config.SMTPConfig
	from   string
}

func NewSMTPSender(cfg config.SMTPConfig, from string) *SMTPSender {
	return &SMTPSender{config: cfg, from: from}
}

func (s *SMTPSender) Name() string { return "smtp" }

func (s *SMTPSender) Send(ctx context.Context, msg Message) Result {
	if err := validateMessage(msg); err != nil {
		return Result{Success: false, Error: err}
	}
	// Reject headers with CRLF to prevent injection
	if strings.ContainsAny(msg.Subject, "\r\n") {
		return Result{Success: false, Error: fmt.Errorf("subject contains invalid characters")}
	}

	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

	var message strings.Builder
	message.WriteString(fmt.Sprintf("From: %s\r\n", msg.From))
	message.WriteString(fmt.Sprintf("To: %s\r\n", msg.To))
	message.WriteString(fmt.Sprintf("Subject: %s\r\n", msg.Subject))
	message.WriteString("MIME-Version: 1.0\r\n")
	message.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	message.WriteString("\r\n")
	message.WriteString(msg.Body)

	auth := smtp.PlainAuth("", s.config.Username, s.config.Password, s.config.Host)

	var err error
	if s.config.UseTLS {
		err = s.sendWithTLS(addr, auth, msg.From, msg.To, []byte(message.String()))
	} else {
		if s.config.Username != "" {
			return Result{Success: false, Error: fmt.Errorf("SMTP auth requires TLS")}
		}
		err = smtp.SendMail(addr, nil, msg.From, []string{msg.To}, []byte(message.String()))
	}
	if err != nil {
		return Result{Success: false, Error: sanitizeSMTPError(err)}
	}

	return Result{
		Success:   true,
		MessageID: fmt.Sprintf("smtp-%s-%d", msg.To, ctx.Value("sequence")),
	}
}

func sanitizeSMTPError(err error) error {
	s := strings.ToLower(err.Error())
	if strings.Contains(s, "auth") {
		return fmt.Errorf("SMTP authentication failed")
	}
	if strings.Contains(s, "certificate") {
		return fmt.Errorf("TLS certificate error")
	}
	return fmt.Errorf("SMTP error: check your configuration")
}

func (s *SMTPSender) sendWithTLS(addr string, auth smtp.Auth, from, to string, msg []byte) error {
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName: s.config.Host,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return fmt.Errorf("TLS connection failed: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, s.config.Host)
	if err != nil {
		return fmt.Errorf("SMTP client creation failed: %w", err)
	}
	defer client.Close()

	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
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
	if _, err = w.Write(msg); err != nil {
		return fmt.Errorf("message write failed: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("message finalization failed: %w", err)
	}
	return client.Quit()
}
