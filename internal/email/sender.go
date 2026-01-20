package email

import (
	"context"
	"fmt"
	"net/mail"
	"strings"

	"github.com/eraser-privacy/eraser/internal/config"
)

type Message struct {
	To      string
	From    string
	Subject string
	Body    string
}

type Result struct {
	Success   bool
	MessageID string
	Error     error
}

type Sender interface {
	Send(ctx context.Context, msg Message) Result
	Name() string
}

func NewSender(cfg config.EmailConfig) (Sender, error) {
	if cfg.Provider == "" || cfg.Provider == "smtp" {
		return NewSMTPSender(cfg.SMTP, cfg.From), nil
	}
	return nil, fmt.Errorf("unknown email provider: %s (only smtp is supported)", cfg.Provider)
}

// ValidateEmail checks for injection characters and RFC 5322 compliance
func ValidateEmail(email string) error {
	if strings.ContainsAny(email, "\r\n,;") {
		return fmt.Errorf("email contains invalid characters")
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return fmt.Errorf("invalid email format: %w", err)
	}
	return nil
}

func validateMessage(msg Message) error {
	if err := ValidateEmail(msg.From); err != nil {
		return fmt.Errorf("invalid sender: %w", err)
	}
	if err := ValidateEmail(msg.To); err != nil {
		return fmt.Errorf("invalid recipient: %w", err)
	}
	return nil
}
