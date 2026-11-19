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

// Record stores a classified broker email. An email seen before (same
// Message-ID; same subject when there is none) replaces its stored response
// in full, so a stored body, its links and its authenticated flag always come
// from one email. It returns true when a new response was inserted.
//
// The broker's pipeline status is only changed for authenticated mail, so a
// spoofed "your data was removed" email can't mark a broker as done, and an
// unauthenticated email never replaces an authenticated one.
func Record(store *history.Store, e *Email, c ClassifiedResponse) (bool, error) {
	body := e.Body
	if body == "" {
		body = e.HTMLBody
	}
	resp := &history.BrokerResponse{
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
		MessageID:     e.MessageID,
	}

	existing, err := store.FindBrokerResponse(e.BrokerID, e.MessageID, e.Subject)
	if err != nil {
		return false, err
	}
	inserted := false
	switch {
	case existing != nil && existing.Authenticated && !e.Authenticated:
		return false, nil
	case existing != nil:
		if err := store.ReplaceBrokerResponse(existing.ID, resp); err != nil {
			return false, err
		}
	default:
		if err := store.AddBrokerResponse(resp); err != nil {
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
