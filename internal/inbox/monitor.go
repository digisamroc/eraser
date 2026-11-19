package inbox

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/textproto"
	"strings"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/emersion/go-message/mail"
	"github.com/eraser-privacy/eraser/internal/broker"
	"github.com/eraser-privacy/eraser/internal/config"
	"golang.org/x/net/publicsuffix"
)

// fetchBatch bounds the number of UIDs in one FETCH command.
const fetchBatch = 100

// Monitor handles IMAP connection and email monitoring.
//
// Privacy rules: mailboxes are opened read-only (EXAMINE) when fetching, so
// no flags change and nothing is marked as read; only envelopes are fetched
// for recent mail, and full bodies are downloaded (with BODY.PEEK) only for
// messages that match a broker.
type Monitor struct {
	config     config.InboxConfig
	client     *client.Client
	brokers    map[string]broker.Broker // registered email/website domain -> broker
	brokerByID map[string]broker.Broker
	sentIDs    map[string]string // Message-ID of a sent request -> broker ID
	authServ   AuthServ          // identifies the provider's Authentication-Results header
	tlsConfig  *tls.Config       // nil uses the system roots; set by tests
}

// Email represents a parsed email from a broker
type Email struct {
	UID        uint32 // IMAP UID for operations like move/delete
	MessageID  string
	From       string
	FromName   string // Sender display name (e.g., "Mail Delivery System")
	FromDomain string
	Subject    string
	Body       string
	HTMLBody   string
	ReceivedAt time.Time
	BrokerID   string // Matched broker ID (if found)
	BrokerName string // Matched broker name (if found)
	Folder     string // Mailbox the message was fetched from; UIDs are per-folder
	InReplyTo  string
	References []string // Message-IDs from the References header
	// Authenticated is true when the user's mail provider verified the sender
	// (see Authenticated). Links are only extracted from authenticated email.
	Authenticated bool

	// Delivery report parts (bounces): the Message-ID of the returned
	// original, and the recipients the report says failed (lowercase).
	ReturnedMessageIDs []string
	FailedRecipients   []string
}

// NewMonitor creates a new inbox monitor. Personal mailbox domains (Gmail,
// Outlook, ...) are never mapped to a broker, so personal mail can't match.
func NewMonitor(cfg config.InboxConfig, brokerList []broker.Broker) *Monitor {
	m := &Monitor{
		config:     cfg,
		brokers:    make(map[string]broker.Broker),
		brokerByID: make(map[string]broker.Broker),
		authServ:   AuthServFor(cfg),
	}
	for _, b := range brokerList {
		m.brokerByID[b.ID] = b
		for _, d := range []string{emailDomain(b.Email), extractDomain(b.Website)} {
			if d == "" || broker.IsFreemailDomain(d) {
				continue
			}
			m.brokers[d] = b
		}
	}
	return m
}

// VerifiesSenders reports whether the monitor knows which
// Authentication-Results header is the provider's. Without it no email is
// authenticated: links are ignored and bounces can't remove brokers.
func (m *Monitor) VerifiesSenders() bool { return m.authServ.Known() }

// SetSentMessageIDs supplies Message-IDs of sent requests (from history), so
// a reply can be matched to its broker by In-Reply-To even when it comes from
// a help-desk domain. Message-IDs are random and only the broker saw them.
func (m *Monitor) SetSentMessageIDs(ids map[string]string) {
	m.sentIDs = ids
}

func emailDomain(addr string) string {
	if i := strings.LastIndex(addr, "@"); i >= 0 {
		return strings.ToLower(addr[i+1:])
	}
	return ""
}

// extractDomain extracts the domain from a URL
func extractDomain(url string) string {
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "www.")
	parts := strings.Split(url, "/")
	if len(parts) > 0 {
		return strings.ToLower(parts[0])
	}
	return ""
}

// matchBroker finds the broker for a sender domain: an exact match, or a
// subdomain of a registered domain, walking up no further than the
// organizational domain (so "evil.co.uk" can never match "co.uk").
func (m *Monitor) matchBroker(domain string) (broker.Broker, bool) {
	d := strings.ToLower(strings.TrimSpace(domain))
	if d == "" || broker.IsFreemailDomain(d) {
		return broker.Broker{}, false
	}
	org, err := publicsuffix.EffectiveTLDPlusOne(d)
	if err != nil {
		return broker.Broker{}, false
	}
	for {
		if b, ok := m.brokers[d]; ok {
			return b, true
		}
		if d == org {
			return broker.Broker{}, false
		}
		i := strings.IndexByte(d, '.')
		if i < 0 {
			return broker.Broker{}, false
		}
		d = d[i+1:]
	}
}

func (m *Monitor) assignBroker(e *Email) {
	if id, ok := m.sentIDs[e.InReplyTo]; ok {
		if b, ok := m.brokerByID[id]; ok {
			e.BrokerID, e.BrokerName = b.ID, b.Name
			return
		}
	}
	if b, ok := m.matchBroker(e.FromDomain); ok {
		e.BrokerID, e.BrokerName = b.ID, b.Name
	}
}

// Connect establishes IMAP connection
func (m *Monitor) Connect(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", m.config.Server, m.config.Port)

	c, err := client.DialTLS(addr, m.tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to IMAP server: %w", err)
	}
	if err := c.Login(m.config.Email, m.config.Password); err != nil {
		_ = c.Logout()
		return fmt.Errorf("failed to login: %w", err)
	}
	m.client = c
	return nil
}

// Disconnect closes the IMAP connection
func (m *Monitor) Disconnect() error {
	if m.client != nil {
		return m.client.Logout()
	}
	return nil
}

// FetchBrokerEmails fetches broker emails from the configured folder.
func (m *Monitor) FetchBrokerEmails(ctx context.Context, days int) ([]Email, error) {
	return m.FetchBrokerEmailsFromFolder(ctx, m.config.Folder, days)
}

// FetchBrokerEmailsFromFolder fetches broker emails from the last N days.
func (m *Monitor) FetchBrokerEmailsFromFolder(ctx context.Context, folder string, days int) ([]Email, error) {
	criteria := imap.NewSearchCriteria()
	criteria.Since = time.Now().AddDate(0, 0, -days)
	emails, _, err := m.fetch(ctx, folder, criteria, isBrokerEmail)
	return emails, err
}

// FetchBounceEmails fetches recent bounce/undeliverable notifications.
func (m *Monitor) FetchBounceEmails(ctx context.Context, days int) ([]Email, error) {
	criteria := imap.NewSearchCriteria()
	criteria.Since = time.Now().AddDate(0, 0, -days)
	emails, _, err := m.fetch(ctx, m.config.Folder, criteria, isBounceEnvelope)
	return emails, err
}

// fetchSince returns broker emails with UID >= from (0 means all) and the
// folder's next UID, for incremental polling.
func (m *Monitor) fetchSince(ctx context.Context, folder string, from uint32) ([]Email, uint32, error) {
	criteria := imap.NewSearchCriteria()
	set := new(imap.SeqSet)
	set.AddRange(max(from, 1), 0) // "from:*"
	criteria.Uid = set
	emails, next, err := m.fetch(ctx, folder, criteria, func(e *Email) bool {
		// "N:*" also matches the highest UID when it is below N.
		return e.UID >= from && isBrokerEmail(e)
	})
	return emails, next, err
}

func isBrokerEmail(e *Email) bool { return e.BrokerID != "" }

// fetch runs a search in folder, keeps messages whose envelope passes keep,
// and downloads full bodies only for those. It returns the folder's UIDNEXT.
func (m *Monitor) fetch(ctx context.Context, folder string, criteria *imap.SearchCriteria, keep func(*Email) bool) ([]Email, uint32, error) {
	if m.client == nil {
		return nil, 0, fmt.Errorf("not connected to IMAP server")
	}
	// Read-only (EXAMINE): the server cannot change any flags.
	mbox, err := m.client.Select(folder, true)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to select mailbox %s: %w", folder, err)
	}
	uids, err := m.client.UidSearch(criteria)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search %s: %w", folder, err)
	}

	// Pass 1: envelopes only.
	var kept []*Email
	err = m.uidFetch(uids, []imap.FetchItem{imap.FetchEnvelope, imap.FetchUid}, func(msg *imap.Message) {
		if msg.Envelope == nil {
			return
		}
		e := emailFromEnvelope(msg)
		e.Folder = folder
		m.assignBroker(e)
		if keep(e) {
			kept = append(kept, e)
		}
	})
	if err != nil {
		return nil, 0, fmt.Errorf("failed to fetch envelopes from %s: %w", folder, err)
	}

	// Pass 2: full bodies for kept messages only, without setting \Seen.
	byUID := make(map[uint32]*Email, len(kept))
	keptUIDs := make([]uint32, 0, len(kept))
	for _, e := range kept {
		byUID[e.UID] = e
		keptUIDs = append(keptUIDs, e.UID)
	}
	section := &imap.BodySectionName{Peek: true}
	err = m.uidFetch(keptUIDs, []imap.FetchItem{section.FetchItem(), imap.FetchUid}, func(msg *imap.Message) {
		if e := byUID[msg.Uid]; e != nil {
			if r := msg.GetBody(section); r != nil {
				parseBody(e, r, m.authServ)
			}
		}
	})
	if err != nil {
		return nil, 0, fmt.Errorf("failed to fetch bodies from %s: %w", folder, err)
	}

	out := make([]Email, 0, len(kept))
	for _, e := range kept {
		out = append(out, *e)
	}
	return out, mbox.UidNext, nil
}

// uidFetch fetches items for uids in batches and calls fn for each message.
func (m *Monitor) uidFetch(uids []uint32, items []imap.FetchItem, fn func(*imap.Message)) error {
	for start := 0; start < len(uids); start += fetchBatch {
		set := new(imap.SeqSet)
		set.AddNum(uids[start:min(start+fetchBatch, len(uids))]...)

		messages := make(chan *imap.Message, fetchBatch)
		done := make(chan error, 1)
		go func() { done <- m.client.UidFetch(set, items, messages) }()
		for msg := range messages {
			fn(msg)
		}
		if err := <-done; err != nil {
			return err
		}
	}
	return nil
}

func emailFromEnvelope(msg *imap.Message) *Email {
	env := msg.Envelope
	e := &Email{
		UID:        msg.Uid,
		Subject:    env.Subject,
		ReceivedAt: env.Date,
		MessageID:  env.MessageId,
		InReplyTo:  strings.TrimSpace(env.InReplyTo),
	}
	if len(env.From) > 0 {
		from := env.From[0]
		e.From = from.Address()
		e.FromName = from.PersonalName
		e.FromDomain = strings.ToLower(from.HostName)
	}
	return e
}

// maxPartBytes bounds how much of one MIME part is read.
const maxPartBytes = 1 << 20

// parseBody fills in the authentication result, text parts, and, for
// delivery reports, the returned message's ID and the failed recipients.
func parseBody(e *Email, r io.Reader, as AuthServ) {
	mr, err := mail.CreateReader(r)
	if err != nil {
		return // unparseable: stays unauthenticated with no body
	}
	// Header.Get returns the first (topmost) occurrence: the one added by the
	// user's own provider. Lower ones can be forged by the sender.
	e.Authenticated = Authenticated(mr.Header.Get("Authentication-Results"), e.FromDomain, as)
	if refs, err := mr.Header.MsgIDList("References"); err == nil {
		for _, id := range refs {
			e.References = append(e.References, "<"+id+">")
		}
	}

	for {
		p, err := mr.NextPart()
		if err != nil {
			break // io.EOF or a malformed part
		}
		h, ok := p.Header.(interface {
			ContentType() (string, map[string]string, error)
		})
		if !ok {
			continue
		}
		ct, _, _ := h.ContentType()
		body, _ := io.ReadAll(io.LimitReader(p.Body, maxPartBytes))
		_, inline := p.Header.(*mail.InlineHeader)
		switch {
		case inline && strings.HasPrefix(ct, "text/plain") && e.Body == "":
			e.Body = string(body)
		case inline && strings.HasPrefix(ct, "text/html") && e.HTMLBody == "":
			e.HTMLBody = string(body)
		case ct == "message/delivery-status":
			e.FailedRecipients = append(e.FailedRecipients, failedRecipients(body)...)
		case ct == "message/rfc822" || ct == "text/rfc822-headers" || ct == "message/rfc822-headers":
			if id := returnedMessageID(body); id != "" {
				e.ReturnedMessageIDs = append(e.ReturnedMessageIDs, id)
			}
		}
	}
}

// failedRecipients reads the Final-Recipient fields of a delivery-status
// report (RFC 3464), e.g. "Final-Recipient: rfc822; privacy@acme.example".
func failedRecipients(report []byte) []string {
	var out []string
	for _, line := range strings.Split(string(report), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "Final-Recipient") {
			continue
		}
		if _, addr, ok := strings.Cut(value, ";"); ok {
			if addr = strings.ToLower(strings.TrimSpace(addr)); addr != "" {
				out = append(out, addr)
			}
		}
	}
	return out
}

// returnedMessageID reads the Message-ID from a returned message or its headers.
func returnedMessageID(raw []byte) string {
	h, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(raw))).ReadMIMEHeader()
	if err != nil && len(h) == 0 {
		return ""
	}
	return strings.TrimSpace(h.Get("Message-Id"))
}

// Envelope-level bounce hints. Narrower than the classifier's list (no
// "noreply"), because these decide which bodies get downloaded at all.
var (
	bounceEnvelopeSenders = []string{
		"mailer-daemon", "postmaster", "mail delivery",
		"mail delivery system", "mail delivery subsystem",
		"mailerdaemon", "mailsystem",
	}
	bounceEnvelopeSubjects = []string{
		"undeliverable", "delivery failed", "delivery status notification",
		"returned mail", "mail delivery failed", "delivery failure",
		"message not delivered", "could not be delivered",
	}
)

// isBounceEnvelope decides from the envelope alone whether a message looks
// like a bounce, so other mail bodies are never downloaded.
func isBounceEnvelope(e *Email) bool {
	from, name, subject := strings.ToLower(e.From), strings.ToLower(e.FromName), strings.ToLower(e.Subject)
	for _, s := range bounceEnvelopeSenders {
		if strings.Contains(from, s) || strings.Contains(name, s) {
			return true
		}
	}
	for _, p := range bounceEnvelopeSubjects {
		if strings.Contains(subject, p) {
			return true
		}
	}
	return false
}

// WatchForNewEmails monitors for new broker emails (blocking). Each message
// is delivered once: only UIDs above the last one seen are fetched.
func (m *Monitor) WatchForNewEmails(ctx context.Context, callback func(Email)) error {
	if m.client == nil {
		return fmt.Errorf("not connected to IMAP server")
	}
	mbox, err := m.client.Select(m.config.Folder, true)
	if err != nil {
		return fmt.Errorf("failed to select mailbox: %w", err)
	}
	next := mbox.UidNext

	updates := make(chan client.Update)
	m.client.Updates = updates

	stop := make(chan struct{})
	idleDone := make(chan error, 1)
	go func() { idleDone <- m.client.Idle(stop, nil) }()

	for {
		select {
		case <-ctx.Done():
			close(stop)
			if err := <-idleDone; err != nil {
				log.Printf("IDLE ended during shutdown: %v", err)
			}
			return ctx.Err()
		case update := <-updates:
			if _, ok := update.(*client.MailboxUpdate); !ok {
				continue
			}
			close(stop)
			if err := <-idleDone; err != nil {
				return fmt.Errorf("IDLE error: %w", err)
			}

			emails, newNext, err := m.fetchSince(ctx, m.config.Folder, next)
			if err != nil {
				log.Printf("Error fetching new email: %v", err)
			} else {
				next = max(next, newNext)
				for _, e := range emails {
					callback(e)
				}
			}

			stop = make(chan struct{})
			go func() { idleDone <- m.client.Idle(stop, nil) }()
		case err := <-idleDone:
			if err != nil {
				return fmt.Errorf("IDLE error: %w", err)
			}
		}
	}
}

// EnsureFolderExists creates a folder/label if it doesn't already exist
func (m *Monitor) EnsureFolderExists(name string) error {
	if m.client == nil {
		return fmt.Errorf("not connected to IMAP server")
	}

	mailboxes := make(chan *imap.MailboxInfo, 10)
	done := make(chan error, 1)
	go func() { done <- m.client.List("", "*", mailboxes) }()

	exists := false
	for mbox := range mailboxes {
		if strings.EqualFold(mbox.Name, name) {
			exists = true
		}
	}
	if err := <-done; err != nil {
		return fmt.Errorf("failed to list folders: %w", err)
	}
	if exists {
		return nil
	}
	if err := m.client.Create(name); err != nil {
		return fmt.Errorf("failed to create folder '%s': %w", name, err)
	}
	return nil
}

// ArchiveEmails moves the given emails that were fetched from the configured
// folder into dest, and returns how many it moved. UIDs only identify a
// message within its own folder, so emails from any other folder are skipped.
func (m *Monitor) ArchiveEmails(emails []Email, dest string) (int, error) {
	if m.client == nil {
		return 0, fmt.Errorf("not connected to IMAP server")
	}
	src := m.config.Folder

	set := new(imap.SeqSet)
	n := 0
	for _, e := range emails {
		if e.Folder == src && e.UID > 0 {
			set.AddNum(e.UID)
			n++
		}
	}
	if n == 0 {
		return 0, nil
	}

	if _, err := m.client.Select(src, false); err != nil {
		return 0, fmt.Errorf("failed to select mailbox: %w", err)
	}

	// MOVE (RFC 6851) is atomic and supported by Gmail and Outlook.
	if err := m.client.UidMove(set, dest); err != nil {
		// Fallback: COPY, flag \Deleted, EXPUNGE. Note: a plain EXPUNGE also
		// removes any other messages already flagged \Deleted in src.
		if err := m.client.UidCopy(set, dest); err != nil {
			return 0, fmt.Errorf("failed to copy emails to '%s': %w", dest, err)
		}
		item := imap.FormatFlagsOp(imap.AddFlags, true)
		if err := m.client.UidStore(set, item, []interface{}{imap.DeletedFlag}, nil); err != nil {
			return 0, fmt.Errorf("failed to mark emails as deleted: %w", err)
		}
		if err := m.client.Expunge(nil); err != nil {
			return 0, fmt.Errorf("failed to expunge deleted emails: %w", err)
		}
	}
	return n, nil
}
