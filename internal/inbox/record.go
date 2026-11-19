package inbox

import (
	"fmt"

	"github.com/eraser-privacy/eraser/internal/history"
)

// PipelineStatusFor maps a response type to the broker's pipeline stage.
func PipelineStatusFor(t ResponseType) (history.PipelineStatus, bool) {
	switch t {
	case ResponseSuccess:
		return history.PipelineConfirmed, true
	case ResponseFormRequired:
		return history.PipelineFormRequired, true
	case ResponseConfirmationRequired:
		return history.PipelineAwaitingConfirmation, true
	case ResponseRejected:
		return history.PipelineRejected, true
	case ResponseInfoRequired:
		return history.PipelineInfoRequired, true
	case ResponsePending:
		return history.PipelineAwaitingResponse, true
	default:
		return "", false
	}
}

// Record stores a classified broker email, updating the stored response if
// the same email (broker and subject) was recorded before. It returns true
// when a new response was inserted.
//
// The broker's pipeline status is only changed for authenticated mail, so a
// spoofed "your data was removed" email can't mark a broker as done.
func Record(store *history.Store, e *Email, c ClassifiedResponse) (bool, error) {
	body := e.Body
	if body == "" {
		body = e.HTMLBody
	}

	inserted := false
	existing, err := store.FindBrokerResponseBySubject(e.BrokerID, e.Subject)
	if err != nil {
		return false, err
	}
	if existing != nil {
		if err := store.UpdateBrokerResponseClassification(existing.ID, string(c.Type), c.FormURL, c.ConfirmURL,
			c.Confidence, c.NeedsReview, e.Authenticated); err != nil {
			return false, err
		}
		if existing.EmailBody == "" && body != "" {
			if err := store.UpdateBrokerResponseBody(existing.ID, body); err != nil {
				return false, err
			}
		}
	} else {
		if err := store.AddBrokerResponse(&history.BrokerResponse{
			BrokerID:      e.BrokerID,
			BrokerName:    e.BrokerName,
			ResponseType:  string(c.Type),
			EmailFrom:     e.From,
			EmailSubject:  e.Subject,
			EmailBody:     body,
			FormURL:       c.FormURL,
			ConfirmURL:    c.ConfirmURL,
			Confidence:    c.Confidence,
			NeedsReview:   c.NeedsReview,
			ReceivedAt:    e.ReceivedAt,
			Authenticated: e.Authenticated,
		}); err != nil {
			return false, fmt.Errorf("failed to store response from %s: %w", e.BrokerID, err)
		}
		inserted = true
	}

	if e.Authenticated {
		if status, ok := PipelineStatusFor(c.Type); ok {
			// Errors here mean no sent request exists for the broker yet.
			_ = store.UpdatePipelineStatus(e.BrokerID, status)
		}
	}
	return inserted, nil
}
