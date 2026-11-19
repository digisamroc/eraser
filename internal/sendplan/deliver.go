package sendplan

import (
	"context"
	"fmt"
	"time"

	"github.com/eraser-privacy/eraser/internal/broker"
	"github.com/eraser-privacy/eraser/internal/config"
	"github.com/eraser-privacy/eraser/internal/email"
	"github.com/eraser-privacy/eraser/internal/history"
	"github.com/eraser-privacy/eraser/internal/template"
)

const defaultTemplate = "generic"

// Deliverer renders, sends, and records removal requests. The CLI and the
// web UI both send through it so they can't drift apart.
type Deliverer struct {
	Config *config.Config
	Engine *template.Engine
	Sender email.Sender
	Store  *history.Store
}

// Deliver sends one removal request and records the outcome in history.
//
// A failed send is not an error: it is returned in the record with
// StatusFailed. The error is non-nil only when nothing should be sent (a
// form-only broker) or when the history record couldn't be written. Callers
// must stop on an error, because an unrecorded send would be repeated next
// run and wouldn't count toward the daily cap.
func (d Deliverer) Deliver(ctx context.Context, disclose config.Disclosure, b broker.Broker) (*history.Record, error) {
	if !b.EmailAccepted() {
		return nil, fmt.Errorf("broker %s does not process emailed requests; use its opt-out form", b.ID)
	}
	if d.Store == nil {
		return nil, fmt.Errorf("no history store; refusing to send without recording it")
	}

	tmpl := d.Config.Options.Template
	if tmpl == "" {
		tmpl = defaultTemplate
	}
	record := &history.Record{
		BrokerID:   b.ID,
		BrokerName: b.Name,
		Email:      b.Email,
		Template:   tmpl,
	}

	rendered, err := d.Engine.Render(tmpl, d.Config.Profile, disclose, b)
	if err != nil {
		record.Status, record.Error = history.StatusFailed, fmt.Sprintf("failed to render template: %v", err)
	} else {
		result := d.Sender.Send(ctx, email.Message{
			To:       b.Email,
			From:     d.Config.Email.From,
			FromName: d.Config.Profile.FullName(),
			Subject:  rendered.Subject,
			Body:     rendered.Body,
		})
		if result.Success {
			record.Status, record.MessageID = history.StatusSent, result.MessageID
		} else {
			record.Status = history.StatusFailed
			if result.Error != nil {
				record.Error = result.Error.Error()
			}
		}
	}

	record.SentAt = time.Now()
	if err := d.Store.Add(record); err != nil {
		return record, fmt.Errorf("failed to record history for %s: %w", b.ID, err)
	}
	return record, nil
}
