package inbox

import (
	"context"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/emersion/go-message/mail"
	"github.com/eraser-privacy/eraser/internal/broker"
	"github.com/eraser-privacy/eraser/internal/config"
)

// Monitor handles IMAP connection and email monitoring
type Monitor struct {
	config  config.InboxConfig
	client  *client.Client
	brokers map[string]broker.Broker // Map of email domain to broker
}

// Email represents a parsed email from a broker
type Email struct {
	UID         uint32 // IMAP UID for operations like move/delete
	MessageID   string
	From        string
	FromName    string // Sender display name (e.g., "Mail Delivery System")
	FromDomain  string
	Subject     string
	Body        string
	HTMLBody    string
	ReceivedAt  time.Time
	BrokerID    string // Matched broker ID (if found)
	BrokerName  string // Matched broker name (if found)
}

// NewMonitor creates a new inbox monitor
func NewMonitor(cfg config.InboxConfig, brokerList []broker.Broker) *Monitor {
	// Build a map of email domains to brokers for quick lookup
	brokerMap := make(map[string]broker.Broker)
	for _, b := range brokerList {
		// Extract domain from broker email
		if b.Email != "" {
			parts := strings.Split(b.Email, "@")
			if len(parts) == 2 {
				domain := strings.ToLower(parts[1])
				brokerMap[domain] = b
			}
		}
		// Also map by website domain
		if b.Website != "" {
			domain := extractDomain(b.Website)
			if domain != "" {
				brokerMap[domain] = b
			}
		}
	}

	return &Monitor{
		config:  cfg,
		brokers: brokerMap,
	}
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

// Connect establishes IMAP connection
func (m *Monitor) Connect(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", m.config.Server, m.config.Port)

	log.Printf("Connecting to IMAP server %s...", addr)

	c, err := client.DialTLS(addr, nil)
	if err != nil {
		return fmt.Errorf("failed to connect to IMAP server: %w", err)
	}

	log.Printf("Connected, logging in as %s...", m.config.Email)

	if err := c.Login(m.config.Email, m.config.Password); err != nil {
		c.Logout()
		return fmt.Errorf("failed to login: %w", err)
	}

	m.client = c
	log.Printf("Login successful")
	return nil
}

// Disconnect closes the IMAP connection
func (m *Monitor) Disconnect() error {
	if m.client != nil {
		return m.client.Logout()
	}
	return nil
}

// FetchRecentEmails fetches emails from the last N days
func (m *Monitor) FetchRecentEmails(ctx context.Context, days int) ([]Email, error) {
	if m.client == nil {
		return nil, fmt.Errorf("not connected to IMAP server")
	}

	// Select the mailbox (usually INBOX)
	mbox, err := m.client.Select(m.config.Folder, false)
	if err != nil {
		return nil, fmt.Errorf("failed to select mailbox %s: %w", m.config.Folder, err)
	}

	log.Printf("Mailbox %s has %d messages", m.config.Folder, mbox.Messages)

	if mbox.Messages == 0 {
		return nil, nil
	}

	// Search for emails from the last N days (use UID search)
	since := time.Now().AddDate(0, 0, -days)
	criteria := imap.NewSearchCriteria()
	criteria.Since = since

	uids, err := m.client.UidSearch(criteria)
	if err != nil {
		return nil, fmt.Errorf("failed to search emails: %w", err)
	}

	log.Printf("Found %d emails since %s", len(uids), since.Format("2006-01-02"))

	if len(uids) == 0 {
		return nil, nil
	}

	// Fetch the messages using UIDs
	seqSet := new(imap.SeqSet)
	seqSet.AddNum(uids...)

	// Fetch envelope, body, and UID
	section := &imap.BodySectionName{}
	items := []imap.FetchItem{imap.FetchEnvelope, imap.FetchFlags, imap.FetchUid, section.FetchItem()}

	messages := make(chan *imap.Message, len(uids))
	done := make(chan error, 1)
	go func() {
		done <- m.client.UidFetch(seqSet, items, messages)
	}()

	var emails []Email
	for msg := range messages {
		email, err := m.parseMessage(msg, section)
		if err != nil {
			log.Printf("Warning: failed to parse message: %v", err)
			continue
		}
		if email != nil {
			emails = append(emails, *email)
		}
	}

	if err := <-done; err != nil {
		return nil, fmt.Errorf("failed to fetch messages: %w", err)
	}

	return emails, nil
}

// parseMessage converts an IMAP message to our Email struct
func (m *Monitor) parseMessage(msg *imap.Message, section *imap.BodySectionName) (*Email, error) {
	if msg == nil || msg.Envelope == nil {
		return nil, nil
	}

	email := &Email{
		UID:        msg.Uid,
		Subject:    msg.Envelope.Subject,
		ReceivedAt: msg.Envelope.Date,
	}

	// Get message ID
	if msg.Envelope.MessageId != "" {
		email.MessageID = msg.Envelope.MessageId
	}

	// Get sender
	if len(msg.Envelope.From) > 0 {
		from := msg.Envelope.From[0]
		email.From = from.Address()
		email.FromName = from.PersonalName
		if from.HostName != "" {
			email.FromDomain = strings.ToLower(from.HostName)
		}
	}

	// Try to match to a known broker
	if email.FromDomain != "" {
		if b, ok := m.brokers[email.FromDomain]; ok {
			email.BrokerID = b.ID
			email.BrokerName = b.Name
		}
	}

	// Parse body
	r := msg.GetBody(section)
	if r == nil {
		return email, nil
	}

	mr, err := mail.CreateReader(r)
	if err != nil {
		return email, nil // Return without body on parse error
	}

	// Process each part
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}

		switch h := p.Header.(type) {
		case *mail.InlineHeader:
			ct, _, _ := h.ContentType()
			body, _ := io.ReadAll(p.Body)

			if strings.HasPrefix(ct, "text/plain") && email.Body == "" {
				email.Body = string(body)
			} else if strings.HasPrefix(ct, "text/html") && email.HTMLBody == "" {
				email.HTMLBody = string(body)
			}
		}
	}

	return email, nil
}

// FetchBrokerEmails fetches only emails from known broker domains
func (m *Monitor) FetchBrokerEmails(ctx context.Context, days int) ([]Email, error) {
	allEmails, err := m.FetchRecentEmails(ctx, days)
	if err != nil {
		return nil, err
	}

	var brokerEmails []Email
	for _, email := range allEmails {
		if email.BrokerID != "" {
			brokerEmails = append(brokerEmails, email)
		}
	}

	log.Printf("Found %d emails from known brokers (out of %d total)", len(brokerEmails), len(allEmails))
	return brokerEmails, nil
}

// FetchBrokerEmailsFromFolder fetches broker emails from a specific folder
func (m *Monitor) FetchBrokerEmailsFromFolder(ctx context.Context, folder string, days int) ([]Email, error) {
	// Select the specified folder
	mbox, err := m.client.Select(folder, false)
	if err != nil {
		return nil, fmt.Errorf("failed to select folder %s: %w", folder, err)
	}
	log.Printf("Folder %s has %d messages", folder, mbox.Messages)

	if mbox.Messages == 0 {
		return nil, nil
	}

	// Search for emails from the last N days
	since := time.Now().AddDate(0, 0, -days)
	criteria := imap.NewSearchCriteria()
	criteria.Since = since

	uids, err := m.client.UidSearch(criteria)
	if err != nil {
		return nil, fmt.Errorf("failed to search emails in %s: %w", folder, err)
	}

	log.Printf("Found %d emails since %s in %s", len(uids), since.Format("2006-01-02"), folder)

	if len(uids) == 0 {
		return nil, nil
	}

	// Fetch emails in batches
	var allEmails []Email
	batchSize := 50
	for i := 0; i < len(uids); i += batchSize {
		end := i + batchSize
		if end > len(uids) {
			end = len(uids)
		}

		seqSet := new(imap.SeqSet)
		for _, uid := range uids[i:end] {
			seqSet.AddNum(uid)
		}

		// Fetch message details
		messages := make(chan *imap.Message, batchSize)
		done := make(chan error, 1)
		section := &imap.BodySectionName{Peek: true}

		go func() {
			done <- m.client.UidFetch(seqSet, []imap.FetchItem{
				imap.FetchEnvelope,
				imap.FetchUid,
				section.FetchItem(),
			}, messages)
		}()

		for msg := range messages {
			email, err := m.parseMessage(msg, section)
			if err == nil && email != nil {
				allEmails = append(allEmails, *email)
			}
		}

		if err := <-done; err != nil {
			log.Printf("Warning: error fetching batch: %v", err)
		}
	}

	// Filter to broker emails only
	var brokerEmails []Email
	for _, email := range allEmails {
		if email.BrokerID != "" {
			brokerEmails = append(brokerEmails, email)
		}
	}

	log.Printf("Found %d emails from known brokers in %s (out of %d total)", len(brokerEmails), folder, len(allEmails))
	return brokerEmails, nil
}

// FetchBounceEmails fetches emails that look like bounce/undeliverable notifications
func (m *Monitor) FetchBounceEmails(ctx context.Context, days int) ([]Email, error) {
	allEmails, err := m.FetchRecentEmails(ctx, days)
	if err != nil {
		return nil, err
	}

	// Bounce sender patterns
	bounceSenders := []string{
		"mailer-daemon", "postmaster", "mail delivery",
		"mail delivery system", "mail delivery subsystem",
		"mailerdaemon", "mailsystem",
	}

	// Bounce subject patterns
	bounceSubjects := []string{
		"undeliverable", "delivery failed", "delivery status notification",
		"returned mail", "mail delivery failed", "delivery failure",
		"message not delivered", "could not be delivered",
	}

	var bounceEmails []Email
	for _, email := range allEmails {
		fromLower := strings.ToLower(email.From)
		fromNameLower := strings.ToLower(email.FromName)
		subjectLower := strings.ToLower(email.Subject)

		isBounce := false

		// Check sender
		for _, sender := range bounceSenders {
			if strings.Contains(fromLower, sender) || strings.Contains(fromNameLower, sender) {
				isBounce = true
				break
			}
		}

		// Check subject if not already identified as bounce
		if !isBounce {
			for _, pattern := range bounceSubjects {
				if strings.Contains(subjectLower, pattern) {
					isBounce = true
					break
				}
			}
		}

		if isBounce {
			bounceEmails = append(bounceEmails, email)
		}
	}

	log.Printf("Found %d bounce emails (out of %d total)", len(bounceEmails), len(allEmails))
	return bounceEmails, nil
}

// WatchForNewEmails monitors for new emails (blocking)
func (m *Monitor) WatchForNewEmails(ctx context.Context, callback func(Email)) error {
	if m.client == nil {
		return fmt.Errorf("not connected to IMAP server")
	}

	// Select mailbox
	_, err := m.client.Select(m.config.Folder, false)
	if err != nil {
		return fmt.Errorf("failed to select mailbox: %w", err)
	}

	// Start IDLE
	updates := make(chan client.Update)
	m.client.Updates = updates

	stop := make(chan struct{})
	idleDone := make(chan error, 1)

	go func() {
		idleDone <- m.client.Idle(stop, nil)
	}()

	log.Printf("Watching for new emails (press Ctrl+C to stop)...")

	for {
		select {
		case <-ctx.Done():
			close(stop)
			return ctx.Err()
		case update := <-updates:
			switch u := update.(type) {
			case *client.MailboxUpdate:
				log.Printf("New mail detected: %d messages", u.Mailbox.Messages)
				// Fetch the latest message
				close(stop)
				<-idleDone

				emails, err := m.FetchRecentEmails(ctx, 1)
				if err != nil {
					log.Printf("Error fetching new email: %v", err)
				} else if len(emails) > 0 {
					// Process the newest email
					for _, email := range emails {
						if email.BrokerID != "" {
							callback(email)
						}
					}
				}

				// Restart IDLE
				stop = make(chan struct{})
				go func() {
					idleDone <- m.client.Idle(stop, nil)
				}()
			}
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

	// List existing folders to check if it exists
	mailboxes := make(chan *imap.MailboxInfo, 10)
	done := make(chan error, 1)
	go func() {
		done <- m.client.List("", "*", mailboxes)
	}()

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
		log.Printf("Folder '%s' already exists", name)
		return nil
	}

	// Create the folder
	if err := m.client.Create(name); err != nil {
		return fmt.Errorf("failed to create folder '%s': %w", name, err)
	}

	log.Printf("Created folder '%s'", name)
	return nil
}

// MoveToFolder moves a single email to the specified folder by UID
func (m *Monitor) MoveToFolder(uid uint32, folder string) error {
	if m.client == nil {
		return fmt.Errorf("not connected to IMAP server")
	}

	seqSet := new(imap.SeqSet)
	seqSet.AddNum(uid)

	// Try MOVE first (RFC 6851) - this is most efficient
	if err := m.client.UidMove(seqSet, folder); err != nil {
		// Fallback to COPY + DELETE if MOVE not supported
		if err := m.client.UidCopy(seqSet, folder); err != nil {
			return fmt.Errorf("failed to copy email to '%s': %w", folder, err)
		}

		// Mark as deleted
		item := imap.FormatFlagsOp(imap.AddFlags, true)
		flags := []interface{}{imap.DeletedFlag}
		if err := m.client.UidStore(seqSet, item, flags, nil); err != nil {
			return fmt.Errorf("failed to mark email as deleted: %w", err)
		}

		// Expunge to remove the deleted message
		if err := m.client.Expunge(nil); err != nil {
			return fmt.Errorf("failed to expunge deleted email: %w", err)
		}
	}

	return nil
}

// ArchiveEmails moves multiple emails to the archive folder
func (m *Monitor) ArchiveEmails(uids []uint32, folder string) error {
	if m.client == nil {
		return fmt.Errorf("not connected to IMAP server")
	}

	if len(uids) == 0 {
		return nil
	}

	// Re-select INBOX to ensure we're in the right mailbox
	if _, err := m.client.Select(m.config.Folder, false); err != nil {
		return fmt.Errorf("failed to select mailbox: %w", err)
	}

	seqSet := new(imap.SeqSet)
	seqSet.AddNum(uids...)

	// Try MOVE first (RFC 6851) - this is most efficient
	if err := m.client.UidMove(seqSet, folder); err != nil {
		log.Printf("MOVE not supported, falling back to COPY+DELETE: %v", err)

		// Fallback to COPY + DELETE if MOVE not supported
		if err := m.client.UidCopy(seqSet, folder); err != nil {
			return fmt.Errorf("failed to copy emails to '%s': %w", folder, err)
		}

		// Mark as deleted
		item := imap.FormatFlagsOp(imap.AddFlags, true)
		flags := []interface{}{imap.DeletedFlag}
		if err := m.client.UidStore(seqSet, item, flags, nil); err != nil {
			return fmt.Errorf("failed to mark emails as deleted: %w", err)
		}

		// Expunge to remove deleted messages
		if err := m.client.Expunge(nil); err != nil {
			return fmt.Errorf("failed to expunge deleted emails: %w", err)
		}
	}

	log.Printf("Archived %d emails to '%s'", len(uids), folder)
	return nil
}
