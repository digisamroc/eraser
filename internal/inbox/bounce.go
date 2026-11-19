package inbox

import (
	"errors"
	"slices"
	"strings"

	"github.com/eraser-privacy/eraser/internal/broker"
)

// Reasons VerifyBounce rejects a bounce.
var (
	ErrBounceUnverified     = errors.New("bounce notice not verified by your mail provider")
	ErrBounceNotOurs        = errors.New("bounce doesn't refer to exactly one request Eraser sent")
	ErrBounceWrongRecipient = errors.New("bounce names a different recipient than the request it refers to")
)

// VerifyBounce returns the broker a bounce is about, or an error saying why
// the bounce can't be trusted.
//
// Anyone can send an authenticated "delivery failed" email from their own
// domain naming a broker's address. A real bounce also carries the Message-ID
// of the request that failed (in the returned message, or In-Reply-To /
// References), which only the broker's and our mail servers have seen. So a
// bounce counts only if it is authenticated, refers to exactly one broker we
// sent a request to (sent maps Message-ID to broker ID), and, when the report
// lists failed recipients, names that broker's address.
func VerifyBounce(e *Email, sent map[string]string, db *broker.BrokerDatabase) (*broker.Broker, error) {
	if !e.Authenticated {
		return nil, ErrBounceUnverified
	}

	ids := append(append([]string{e.InReplyTo}, e.References...), e.ReturnedMessageIDs...)
	var brokerID string
	for _, id := range ids {
		b, ok := sent[strings.TrimSpace(id)]
		if !ok {
			continue
		}
		if brokerID != "" && b != brokerID {
			return nil, ErrBounceNotOurs
		}
		brokerID = b
	}
	b := db.FindByID(brokerID)
	if brokerID == "" || b == nil {
		return nil, ErrBounceNotOurs
	}

	if len(e.FailedRecipients) > 0 && !slices.Contains(e.FailedRecipients, strings.ToLower(b.Email)) {
		return nil, ErrBounceWrongRecipient
	}
	return b, nil
}
