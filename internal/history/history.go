package history

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/eraser-privacy/eraser/internal/config"
	_ "modernc.org/sqlite"
)

type Status string

const (
	StatusSent    Status = "sent"
	StatusFailed  Status = "failed"
	StatusPending Status = "pending"
)

// PipelineStatus represents the current stage in the removal pipeline
type PipelineStatus string

const (
	PipelineEmailSent            PipelineStatus = "email_sent"
	PipelineAwaitingResponse     PipelineStatus = "awaiting_response"
	PipelineFormRequired         PipelineStatus = "form_required"
	PipelineFormFilled           PipelineStatus = "form_filled"
	PipelineAwaitingCaptcha      PipelineStatus = "awaiting_captcha"
	PipelineCaptchaSolved        PipelineStatus = "captcha_solved"
	PipelineAwaitingConfirmation PipelineStatus = "awaiting_confirmation"
	PipelineInfoRequired         PipelineStatus = "info_required" // broker asked for more details
	PipelineConfirmed            PipelineStatus = "confirmed"
	PipelineFailed               PipelineStatus = "failed"
	PipelineRejected             PipelineStatus = "rejected"
)

// TaskType represents the type of pending task
type TaskType string

const (
	TaskCaptcha    TaskType = "captcha"
	TaskManualForm TaskType = "manual_form"
	TaskReview     TaskType = "review"
	TaskConfirm    TaskType = "confirm"
)

type Record struct {
	ID             int64
	BrokerID       string
	BrokerName     string
	Email          string
	Template       string
	Status         Status
	MessageID      string
	Error          string
	SentAt         time.Time
	CreatedAt      time.Time
	PipelineStatus PipelineStatus // Current stage in pipeline
}

// BrokerResponse stores a classified response from a broker
type BrokerResponse struct {
	ID           int64
	BrokerID     string
	BrokerName   string
	ResponseType string // form_required, confirmation_required, success, rejected, pending, unknown
	EmailFrom    string
	EmailSubject string
	EmailBody    string // Stored for reclassification, capped at MaxStoredBodyBytes
	FormURL      string // Extracted form URL (if any)
	ConfirmURL   string // Extracted confirmation URL (if any)
	Confidence   float64
	NeedsReview  bool
	ReceivedAt   time.Time
	ProcessedAt  time.Time
	CreatedAt    time.Time
	// Authenticated is true when the receiving server verified the sender
	// (DMARC or aligned DKIM). Links from unauthenticated emails are never
	// stored or acted on, including when a stored email is reclassified.
	Authenticated bool
	MessageID     string // the email's Message-ID; identifies the email a row came from
}

// PendingTask represents a task that needs human intervention
type PendingTask struct {
	ID             int64
	BrokerID       string
	BrokerName     string
	TaskType       TaskType
	FormURL        string
	ScreenshotPath string
	BrowserState   string // JSON serialized browser state (profile data for helper page)
	Notes          string
	Status         string // pending, completed, skipped
	CreatedAt      time.Time
	OpenedAt       sql.NullTime // When user first opened the helper page
	CompletedAt    sql.NullTime
}

type Store struct {
	db *sql.DB
}

// scanRecord handles nullable columns when scanning a row
func scanRecord(scanner interface{ Scan(...any) error }) (*Record, error) {
	var r Record
	var sentAt, createdAt sql.NullTime
	var messageID, errStr sql.NullString

	err := scanner.Scan(&r.ID, &r.BrokerID, &r.BrokerName, &r.Email, &r.Template,
		&r.Status, &messageID, &errStr, &sentAt, &createdAt)
	if err != nil {
		return nil, err
	}

	r.MessageID = messageID.String
	r.Error = errStr.String
	r.SentAt = sentAt.Time
	r.CreatedAt = createdAt.Time
	return &r, nil
}

// NewStore opens (or creates) the history database. It holds names, broker
// replies and send history, so the file is made owner-only before SQLite
// opens it; SQLite gives its journal files the database file's mode.
func NewStore(dbPath string) (*Store, error) {
	if strings.Contains(dbPath, "?") {
		// The driver reads connection options after the first "?".
		return nil, fmt.Errorf("history database path must not contain '?': %s", dbPath)
	}
	if err := config.PrepareDir(filepath.Dir(dbPath)); err != nil {
		return nil, fmt.Errorf("failed to create history directory: %w", err)
	}
	if err := makePrivate(dbPath); err != nil {
		return nil, fmt.Errorf("failed to secure history database: %w", err)
	}

	// Each pooled connection waits up to busyTimeout for a lock instead of
	// failing at once with SQLITE_BUSY: the web UI reads while a send job
	// writes, and the CLI can run alongside it. A failed history write stops
	// a send, so it must not fail just because a read was in progress.
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout("+strconv.Itoa(int(busyTimeout/time.Millisecond))+")")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	store := &Store{db: db}
	if err := store.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

// busyTimeout is how long a statement waits for another connection's lock.
const busyTimeout = 5 * time.Second

// makePrivate creates path if needed and sets it, and any SQLite journal
// files left beside it, to 0600.
func makePrivate(path string) error {
	f, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE, 0o600) //nolint:gosec // G304: the user's own database path
	if err != nil {
		return err
	}
	_ = f.Close()
	for _, p := range []string{path, path + "-journal", path + "-wal", path + "-shm"} {
		if err := os.Chmod(p, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (s *Store) migrate() error {
	// First, try to add new columns to existing databases
	// These must run before the index creation below
	// Each fails harmlessly when the column already exists (or, on a new
	// database, the table doesn't yet; CREATE TABLE below covers that).
	_, _ = s.db.Exec(`ALTER TABLE removal_requests ADD COLUMN pipeline_status TEXT DEFAULT 'email_sent'`)
	_, _ = s.db.Exec(`ALTER TABLE pending_tasks ADD COLUMN opened_at DATETIME`)
	// email_body was read and written but never created, so every insert
	// into broker_responses failed on databases made by older versions.
	// These fail harmlessly when the column (or, on a new database, the
	// table) doesn't need it; the CREATE TABLE below covers new databases.
	_, _ = s.db.Exec(`ALTER TABLE broker_responses ADD COLUMN email_body TEXT`)
	_, _ = s.db.Exec(`ALTER TABLE broker_responses ADD COLUMN authenticated INTEGER DEFAULT 0`)
	_, _ = s.db.Exec(`ALTER TABLE broker_responses ADD COLUMN message_id TEXT`)

	query := `
	CREATE TABLE IF NOT EXISTS removal_requests (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		broker_id TEXT NOT NULL,
		broker_name TEXT NOT NULL,
		email TEXT NOT NULL,
		template TEXT NOT NULL,
		status TEXT NOT NULL,
		message_id TEXT,
		error TEXT,
		sent_at DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		pipeline_status TEXT DEFAULT 'email_sent'
	);

	CREATE INDEX IF NOT EXISTS idx_broker_id ON removal_requests(broker_id);
	CREATE INDEX IF NOT EXISTS idx_sent_at ON removal_requests(sent_at);
	CREATE INDEX IF NOT EXISTS idx_status ON removal_requests(status);
	CREATE INDEX IF NOT EXISTS idx_pipeline_status ON removal_requests(pipeline_status);

	-- Broker responses table (stores classified email responses)
	CREATE TABLE IF NOT EXISTS broker_responses (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		broker_id TEXT NOT NULL,
		broker_name TEXT NOT NULL,
		response_type TEXT NOT NULL,
		email_from TEXT,
		email_subject TEXT,
		email_body TEXT,
		form_url TEXT,
		confirm_url TEXT,
		confidence REAL,
		needs_review INTEGER DEFAULT 0,
		received_at DATETIME,
		processed_at DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		authenticated INTEGER DEFAULT 0,
		message_id TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_br_broker_id ON broker_responses(broker_id);
	CREATE INDEX IF NOT EXISTS idx_br_response_type ON broker_responses(response_type);
	CREATE INDEX IF NOT EXISTS idx_br_needs_review ON broker_responses(needs_review);
	CREATE INDEX IF NOT EXISTS idx_br_message_id ON broker_responses(broker_id, message_id);

	-- Pending tasks table (for CAPTCHAs, manual forms, etc.)
	CREATE TABLE IF NOT EXISTS pending_tasks (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		broker_id TEXT NOT NULL,
		broker_name TEXT NOT NULL,
		task_type TEXT NOT NULL,
		form_url TEXT,
		screenshot_path TEXT,
		browser_state TEXT,
		notes TEXT,
		status TEXT DEFAULT 'pending',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		opened_at DATETIME,
		completed_at DATETIME
	);

	CREATE INDEX IF NOT EXISTS idx_pt_broker_id ON pending_tasks(broker_id);
	CREATE INDEX IF NOT EXISTS idx_pt_task_type ON pending_tasks(task_type);
	CREATE INDEX IF NOT EXISTS idx_pt_status ON pending_tasks(status);
	`

	_, err := s.db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	return nil
}

func (s *Store) Add(record *Record) error {
	query := `
	INSERT INTO removal_requests (broker_id, broker_name, email, template, status, message_id, error, sent_at, created_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	result, err := s.db.Exec(query,
		record.BrokerID,
		record.BrokerName,
		record.Email,
		record.Template,
		record.Status,
		record.MessageID,
		record.Error,
		record.SentAt,
		time.Now(),
	)
	if err != nil {
		return fmt.Errorf("failed to insert record: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}

	record.ID = id
	return nil
}

func (s *Store) GetRecentRequests(limit int) ([]Record, error) {
	query := `
	SELECT id, broker_id, broker_name, email, template, status, message_id, error, sent_at, created_at
	FROM removal_requests ORDER BY sent_at DESC LIMIT ?`

	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query records: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var records []Record
	for rows.Next() {
		record, err := scanRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan record: %w", err)
		}
		records = append(records, *record)
	}
	return records, rows.Err()
}

func (s *Store) GetStats() (total, sent, failed int, err error) {
	query := `SELECT COUNT(*), SUM(CASE WHEN status='sent' THEN 1 ELSE 0 END),
		SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) FROM removal_requests`

	err = s.db.QueryRow(query).Scan(&total, &sent, &failed)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("failed to get stats: %w", err)
	}
	return
}

func (s *Store) GetMonthlyStats() (sent, failed int, err error) {
	now := time.Now()
	startOfMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())

	query := `SELECT SUM(CASE WHEN status='sent' THEN 1 ELSE 0 END),
		SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) FROM removal_requests WHERE sent_at >= ?`

	var sentNull, failedNull sql.NullInt64
	err = s.db.QueryRow(query, startOfMonth).Scan(&sentNull, &failedNull)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get monthly stats: %w", err)
	}
	return int(sentNull.Int64), int(failedNull.Int64), nil
}

func (s *Store) Close() error { return s.db.Close() }

type BrokerStatus struct {
	BrokerID  string
	LastSent  time.Time
	Status    Status
	TotalSent int
}

// GetAllBrokerStatuses returns each broker's most recent attempt and count.
// Times are compared in Go: SQLite returns aggregates like MAX(sent_at) as
// text, and text comparison is wrong across time zones.
func (s *Store) GetAllBrokerStatuses() (map[string]BrokerStatus, error) {
	statuses := make(map[string]BrokerStatus)
	err := s.eachSend(`SELECT broker_id, status, sent_at FROM removal_requests`, func(brokerID string, status Status, at time.Time) {
		bs := statuses[brokerID]
		bs.BrokerID = brokerID
		bs.TotalSent++
		if bs.LastSent.IsZero() || !at.Before(bs.LastSent) {
			bs.LastSent, bs.Status = at, status
		}
		statuses[brokerID] = bs
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query broker statuses: %w", err)
	}
	return statuses, nil
}

// LastSuccessfulSends maps broker ID to the time of its latest successful send.
func (s *Store) LastSuccessfulSends() (map[string]time.Time, error) {
	last := make(map[string]time.Time)
	err := s.eachSend(`SELECT broker_id, status, sent_at FROM removal_requests WHERE status = 'sent'`, func(brokerID string, _ Status, at time.Time) {
		if at.After(last[brokerID]) {
			last[brokerID] = at
		}
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query sends: %w", err)
	}
	return last, nil
}

// CountSentSince counts successful sends at or after t (used for daily caps).
func (s *Store) CountSentSince(t time.Time) (int, error) {
	n := 0
	err := s.eachSend(`SELECT broker_id, status, sent_at FROM removal_requests WHERE status = 'sent'`, func(_ string, _ Status, at time.Time) {
		if !at.Before(t) {
			n++
		}
	})
	if err != nil {
		return 0, fmt.Errorf("failed to count sends: %w", err)
	}
	return n, nil
}

// eachSend runs a (broker_id, status, sent_at) query and parses sent_at in Go.
func (s *Store) eachSend(query string, fn func(brokerID string, status Status, at time.Time)) error {
	rows, err := s.db.Query(query)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var brokerID, status string
		var raw any
		if err := rows.Scan(&brokerID, &status, &raw); err != nil {
			return err
		}
		at, err := parseDBTime(raw)
		if err != nil {
			return fmt.Errorf("broker %s: %w", brokerID, err)
		}
		fn(brokerID, Status(status), at)
	}
	return rows.Err()
}

// Layouts the SQLite driver and CURRENT_TIMESTAMP may have stored.
var dbTimeLayouts = []string{
	"2006-01-02 15:04:05.999999999 -0700 MST",
	"2006-01-02 15:04:05.999999999-07:00",
	time.RFC3339Nano,
	"2006-01-02 15:04:05", // CURRENT_TIMESTAMP (UTC)
}

func parseDBTime(v any) (time.Time, error) {
	var s string
	switch t := v.(type) {
	case nil:
		return time.Time{}, nil
	case time.Time:
		return t, nil
	case string:
		s = t
	case []byte:
		s = string(t)
	default:
		return time.Time{}, fmt.Errorf("unexpected time value %T", v)
	}
	if i := strings.Index(s, " m="); i >= 0 { // monotonic clock suffix from Time.String
		s = s[:i]
	}
	for _, layout := range dbTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized time %q", s)
}

// DeleteByStatus deletes all records with the given status
func (s *Store) DeleteByStatus(status Status) (int64, error) {
	result, err := s.db.Exec(`DELETE FROM removal_requests WHERE status = ?`, string(status))
	if err != nil {
		return 0, fmt.Errorf("failed to delete records: %w", err)
	}
	return result.RowsAffected()
}

func DefaultDBPath() string {
	dir := config.DataDir()
	if dir == "" {
		return "eraser_history.db"
	}
	return filepath.Join(dir, "history.db")
}

// ==================== Broker Response Methods ====================

// MaxStoredBodyBytes caps stored email bodies; they're kept only so a
// response can be reclassified later.
const MaxStoredBodyBytes = 64 << 10

func capBody(body string) string {
	if len(body) <= MaxStoredBodyBytes {
		return body
	}
	body = body[:MaxStoredBodyBytes]
	for !utf8.ValidString(body) { // don't cut a multi-byte character in half
		body = body[:len(body)-1]
	}
	return body
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *Store) AddBrokerResponse(resp *BrokerResponse) error {
	query := `
	INSERT INTO broker_responses (broker_id, broker_name, response_type, email_from, email_subject, email_body,
		form_url, confirm_url, confidence, needs_review, received_at, processed_at, created_at, authenticated, message_id)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	result, err := s.db.Exec(query,
		resp.BrokerID, resp.BrokerName, resp.ResponseType, resp.EmailFrom, resp.EmailSubject, capBody(resp.EmailBody),
		resp.FormURL, resp.ConfirmURL, resp.Confidence, boolInt(resp.NeedsReview),
		resp.ReceivedAt, time.Now(), time.Now(), boolInt(resp.Authenticated), resp.MessageID,
	)
	if err != nil {
		return fmt.Errorf("failed to insert broker response: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}
	resp.ID = id
	return nil
}

const brokerResponseColumns = `id, broker_id, broker_name, response_type, email_from, email_subject, email_body,
		form_url, confirm_url, confidence, needs_review, received_at, processed_at, created_at, authenticated, message_id`

// scanBrokerResponse reads one row selected with brokerResponseColumns.
func scanBrokerResponse(scanner interface{ Scan(...any) error }) (BrokerResponse, error) {
	var r BrokerResponse
	var needsReview, authenticated sql.NullInt64
	var emailFrom, emailSubject, emailBody, formURL, confirmURL, messageID sql.NullString
	var confidence sql.NullFloat64
	var receivedAt, processedAt, createdAt any

	if err := scanner.Scan(&r.ID, &r.BrokerID, &r.BrokerName, &r.ResponseType, &emailFrom, &emailSubject, &emailBody,
		&formURL, &confirmURL, &confidence, &needsReview, &receivedAt, &processedAt, &createdAt, &authenticated, &messageID); err != nil {
		return r, err
	}
	r.EmailFrom, r.EmailSubject, r.EmailBody = emailFrom.String, emailSubject.String, emailBody.String
	r.FormURL, r.ConfirmURL = formURL.String, confirmURL.String
	r.Confidence = confidence.Float64
	r.NeedsReview = needsReview.Int64 == 1
	r.Authenticated = authenticated.Int64 == 1
	r.MessageID = messageID.String

	var err error
	if r.ReceivedAt, err = parseDBTime(receivedAt); err != nil {
		return r, err
	}
	if r.ProcessedAt, err = parseDBTime(processedAt); err != nil {
		return r, err
	}
	if r.CreatedAt, err = parseDBTime(createdAt); err != nil {
		return r, err
	}
	return r, nil
}

func (s *Store) queryBrokerResponses(query string, args ...any) ([]BrokerResponse, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query broker responses: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var responses []BrokerResponse
	for rows.Next() {
		r, err := scanBrokerResponse(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan broker response: %w", err)
		}
		responses = append(responses, r)
	}
	return responses, rows.Err()
}

// FindBrokerResponse finds the stored response for an email: the row with
// its Message-ID, or else a row with the same subject and no Message-ID
// (stored by older versions, or from an email without one).
func (s *Store) FindBrokerResponse(brokerID, messageID, subject string) (*BrokerResponse, error) {
	queries := []struct {
		where string
		args  []any
	}{
		{`broker_id = ? AND message_id = ?`, []any{brokerID, messageID}},
		{`broker_id = ? AND email_subject = ? AND (message_id IS NULL OR message_id = '')`, []any{brokerID, subject}},
	}
	if messageID == "" {
		queries = queries[1:]
	}
	for _, q := range queries {
		r, err := scanBrokerResponse(s.db.QueryRow(`SELECT `+brokerResponseColumns+`
			FROM broker_responses WHERE `+q.where+` ORDER BY id LIMIT 1`, q.args...))
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("failed to find broker response: %w", err)
		}
		return &r, nil
	}
	return nil, nil
}

// ReplaceBrokerResponse overwrites every email-derived field of a stored
// response, so its body, links and authenticated flag always come from the
// same email.
func (s *Store) ReplaceBrokerResponse(id int64, resp *BrokerResponse) error {
	_, err := s.db.Exec(`UPDATE broker_responses SET broker_name = ?, response_type = ?, email_from = ?,
		email_subject = ?, email_body = ?, form_url = ?, confirm_url = ?, confidence = ?, needs_review = ?,
		received_at = ?, processed_at = ?, authenticated = ?, message_id = ? WHERE id = ?`,
		resp.BrokerName, resp.ResponseType, resp.EmailFrom, resp.EmailSubject, capBody(resp.EmailBody),
		resp.FormURL, resp.ConfirmURL, resp.Confidence, boolInt(resp.NeedsReview),
		resp.ReceivedAt, time.Now(), boolInt(resp.Authenticated), resp.MessageID, id)
	if err != nil {
		return fmt.Errorf("failed to replace broker response: %w", err)
	}
	resp.ID = id
	return nil
}

// UpdateBrokerResponseClassification updates the classification fields of a response
func (s *Store) UpdateBrokerResponseClassification(id int64, responseType string, formURL, confirmURL string, confidence float64, needsReview, authenticated bool) error {
	query := `UPDATE broker_responses SET response_type = ?, form_url = ?, confirm_url = ?,
		confidence = ?, needs_review = ?, authenticated = ?, processed_at = ? WHERE id = ?`

	_, err := s.db.Exec(query, responseType, formURL, confirmURL, confidence, boolInt(needsReview), boolInt(authenticated), time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to update broker response: %w", err)
	}
	return nil
}

// SentMessageIDs maps the Message-ID of each successful send to its broker,
// so replies can be matched by In-Reply-To.
func (s *Store) SentMessageIDs() (map[string]string, error) {
	rows, err := s.db.Query(`SELECT message_id, broker_id FROM removal_requests
		WHERE status = 'sent' AND message_id IS NOT NULL AND message_id != ''`)
	if err != nil {
		return nil, fmt.Errorf("failed to query message ids: %w", err)
	}
	defer func() { _ = rows.Close() }()

	ids := make(map[string]string)
	for rows.Next() {
		var id, brokerID string
		if err := rows.Scan(&id, &brokerID); err != nil {
			return nil, fmt.Errorf("failed to scan message id: %w", err)
		}
		ids[id] = brokerID
	}
	return ids, rows.Err()
}

// ClearBrokerResponses removes all broker responses (for full re-scan)
func (s *Store) ClearBrokerResponses() error {
	_, err := s.db.Exec("DELETE FROM broker_responses")
	if err != nil {
		return fmt.Errorf("failed to clear broker responses: %w", err)
	}
	return nil
}

func (s *Store) GetAllBrokerResponses() ([]BrokerResponse, error) {
	return s.queryBrokerResponses(`SELECT ` + brokerResponseColumns + `
		FROM broker_responses ORDER BY created_at DESC`)
}

func (s *Store) GetBrokerResponses(responseType string, needsReview bool, limit int) ([]BrokerResponse, error) {
	query := `SELECT ` + brokerResponseColumns + ` FROM broker_responses WHERE 1=1`
	var args []any
	if responseType != "" {
		query += ` AND response_type = ?`
		args = append(args, responseType)
	}
	if needsReview {
		query += ` AND needs_review = 1`
	}
	query += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, limit)
	return s.queryBrokerResponses(query, args...)
}

// GetResponseStats returns counts of response types
func (s *Store) GetResponseStats() (map[string]int, error) {
	query := `SELECT response_type, COUNT(*) FROM broker_responses GROUP BY response_type`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query response stats: %w", err)
	}
	defer func() { _ = rows.Close() }()

	stats := make(map[string]int)
	for rows.Next() {
		var responseType string
		var count int
		if err := rows.Scan(&responseType, &count); err != nil {
			return nil, fmt.Errorf("failed to scan response stat: %w", err)
		}
		stats[responseType] = count
	}
	return stats, rows.Err()
}

// FormWithStatus represents a form detected from email with its current fill status
type FormWithStatus struct {
	BrokerID       string
	BrokerName     string
	FormURL        string
	EmailSubject   string
	DetectedAt     time.Time
	Status         string // pending, filled, captcha, failed, skipped
	TaskID         int64  // If there's a pending task
	PipelineStatus PipelineStatus
}

// GetFormsWithStatus returns all detected forms with their current status
func (s *Store) GetFormsWithStatus() ([]FormWithStatus, error) {
	// Get all broker_responses with form_url, joined with pending_tasks and removal_requests
	query := `
	SELECT
		br.broker_id,
		br.broker_name,
		br.form_url,
		br.email_subject,
		br.created_at as detected_at,
		COALESCE(pt.id, 0) as task_id,
		COALESCE(pt.status, '') as task_status,
		COALESCE(rr.pipeline_status, '') as pipeline_status
	FROM broker_responses br
	LEFT JOIN pending_tasks pt ON br.broker_id = pt.broker_id AND pt.task_type IN ('captcha', 'manual_form')
	LEFT JOIN (
		SELECT broker_id, pipeline_status
		FROM removal_requests
		WHERE id IN (SELECT MAX(id) FROM removal_requests GROUP BY broker_id)
	) rr ON br.broker_id = rr.broker_id
	WHERE br.form_url IS NOT NULL AND br.form_url != ''
	ORDER BY br.created_at DESC
	`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query forms: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var forms []FormWithStatus
	seen := make(map[string]bool) // Dedupe by broker_id

	for rows.Next() {
		var f FormWithStatus
		var taskStatus, pipelineStatus string

		if err := rows.Scan(&f.BrokerID, &f.BrokerName, &f.FormURL, &f.EmailSubject,
			&f.DetectedAt, &f.TaskID, &taskStatus, &pipelineStatus); err != nil {
			return nil, fmt.Errorf("failed to scan form: %w", err)
		}

		// Skip duplicates (keep first/most recent)
		if seen[f.BrokerID] {
			continue
		}
		seen[f.BrokerID] = true

		f.PipelineStatus = PipelineStatus(pipelineStatus)

		// Determine status based on task and pipeline status
		if taskStatus == "completed" {
			f.Status = "filled"
		} else if taskStatus == "skipped" {
			f.Status = "skipped"
		} else if taskStatus == "pending" && f.TaskID > 0 {
			f.Status = "captcha"
		} else if pipelineStatus == string(PipelineFormFilled) || pipelineStatus == string(PipelineConfirmed) {
			f.Status = "filled"
		} else if pipelineStatus == string(PipelineFailed) {
			f.Status = "failed"
		} else if pipelineStatus == string(PipelineRejected) {
			f.Status = "skipped"
		} else {
			f.Status = "pending"
		}

		forms = append(forms, f)
	}

	return forms, rows.Err()
}

// GetFormStats returns counts of forms by status
func (s *Store) GetFormStats() (pending, filled, captcha, failed, skipped int, err error) {
	forms, err := s.GetFormsWithStatus()
	if err != nil {
		return 0, 0, 0, 0, 0, err
	}

	for _, f := range forms {
		switch f.Status {
		case "pending":
			pending++
		case "filled":
			filled++
		case "captcha":
			captcha++
		case "failed":
			failed++
		case "skipped":
			skipped++
		}
	}
	return
}

// ==================== Pending Task Methods ====================

// AddPendingTask creates a new pending task for human intervention
func (s *Store) AddPendingTask(task *PendingTask) error {
	query := `
	INSERT INTO pending_tasks (broker_id, broker_name, task_type, form_url, screenshot_path,
		browser_state, notes, status, created_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	result, err := s.db.Exec(query,
		task.BrokerID, task.BrokerName, task.TaskType, task.FormURL, task.ScreenshotPath,
		task.BrowserState, task.Notes, "pending", time.Now(),
	)
	if err != nil {
		return fmt.Errorf("failed to insert pending task: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}
	task.ID = id
	return nil
}

// GetPendingTasks retrieves pending tasks with optional filtering
func (s *Store) GetPendingTasks(taskType TaskType, status string) ([]PendingTask, error) {
	var query string
	var args []interface{}

	if taskType != "" && status != "" {
		query = `SELECT id, broker_id, broker_name, task_type, form_url, screenshot_path,
			browser_state, notes, status, created_at, opened_at, completed_at
			FROM pending_tasks WHERE task_type = ? AND status = ? ORDER BY created_at DESC`
		args = []interface{}{taskType, status}
	} else if taskType != "" {
		query = `SELECT id, broker_id, broker_name, task_type, form_url, screenshot_path,
			browser_state, notes, status, created_at, opened_at, completed_at
			FROM pending_tasks WHERE task_type = ? ORDER BY created_at DESC`
		args = []interface{}{taskType}
	} else if status != "" {
		query = `SELECT id, broker_id, broker_name, task_type, form_url, screenshot_path,
			browser_state, notes, status, created_at, opened_at, completed_at
			FROM pending_tasks WHERE status = ? ORDER BY created_at DESC`
		args = []interface{}{status}
	} else {
		query = `SELECT id, broker_id, broker_name, task_type, form_url, screenshot_path,
			browser_state, notes, status, created_at, opened_at, completed_at
			FROM pending_tasks ORDER BY created_at DESC`
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query pending tasks: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var tasks []PendingTask
	for rows.Next() {
		var t PendingTask
		var createdAt sql.NullTime
		var formURL, screenshotPath, browserState, notes sql.NullString

		err := rows.Scan(&t.ID, &t.BrokerID, &t.BrokerName, &t.TaskType, &formURL, &screenshotPath,
			&browserState, &notes, &t.Status, &createdAt, &t.OpenedAt, &t.CompletedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan pending task: %w", err)
		}

		t.FormURL = formURL.String
		t.ScreenshotPath = screenshotPath.String
		t.BrowserState = browserState.String
		t.Notes = notes.String
		t.CreatedAt = createdAt.Time
		tasks = append(tasks, t)
	}

	return tasks, rows.Err()
}

// GetPendingTaskByID retrieves a specific pending task
func (s *Store) GetPendingTaskByID(id int64) (*PendingTask, error) {
	query := `SELECT id, broker_id, broker_name, task_type, form_url, screenshot_path,
		browser_state, notes, status, created_at, opened_at, completed_at
		FROM pending_tasks WHERE id = ?`

	var t PendingTask
	var createdAt sql.NullTime
	var formURL, screenshotPath, browserState, notes sql.NullString

	err := s.db.QueryRow(query, id).Scan(&t.ID, &t.BrokerID, &t.BrokerName, &t.TaskType, &formURL, &screenshotPath,
		&browserState, &notes, &t.Status, &createdAt, &t.OpenedAt, &t.CompletedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query pending task: %w", err)
	}

	t.FormURL = formURL.String
	t.ScreenshotPath = screenshotPath.String
	t.BrowserState = browserState.String
	t.Notes = notes.String
	t.CreatedAt = createdAt.Time
	return &t, nil
}

// CompletePendingTask marks a task as completed
func (s *Store) CompletePendingTask(id int64, status string) error {
	query := `UPDATE pending_tasks SET status = ?, completed_at = ? WHERE id = ?`
	_, err := s.db.Exec(query, status, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to complete pending task: %w", err)
	}
	return nil
}

// MarkTaskOpened sets the opened_at timestamp (only if not already set)
func (s *Store) MarkTaskOpened(id int64) error {
	query := `UPDATE pending_tasks SET opened_at = ? WHERE id = ? AND opened_at IS NULL`
	_, err := s.db.Exec(query, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to mark task opened: %w", err)
	}
	return nil
}

// GetPendingTaskStats returns counts of pending tasks by type and status
func (s *Store) GetPendingTaskStats() (pending, completed, skipped int, err error) {
	query := `SELECT
		SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END),
		SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END),
		SUM(CASE WHEN status='skipped' THEN 1 ELSE 0 END)
		FROM pending_tasks`

	var pendingNull, completedNull, skippedNull sql.NullInt64
	err = s.db.QueryRow(query).Scan(&pendingNull, &completedNull, &skippedNull)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("failed to get task stats: %w", err)
	}
	return int(pendingNull.Int64), int(completedNull.Int64), int(skippedNull.Int64), nil
}

// ==================== Pipeline Status Methods ====================

// UpdatePipelineStatus updates the pipeline status for a broker
func (s *Store) UpdatePipelineStatus(brokerID string, status PipelineStatus) error {
	query := `UPDATE removal_requests SET pipeline_status = ? WHERE broker_id = ? AND id = (
		SELECT id FROM removal_requests WHERE broker_id = ? ORDER BY sent_at DESC LIMIT 1
	)`
	_, err := s.db.Exec(query, status, brokerID, brokerID)
	if err != nil {
		return fmt.Errorf("failed to update pipeline status: %w", err)
	}
	return nil
}

// GetPipelineStats returns counts by pipeline status
func (s *Store) GetPipelineStats() (map[PipelineStatus]int, error) {
	query := `SELECT pipeline_status, COUNT(*) FROM removal_requests
		WHERE id IN (SELECT MAX(id) FROM removal_requests GROUP BY broker_id)
		GROUP BY pipeline_status`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query pipeline stats: %w", err)
	}
	defer func() { _ = rows.Close() }()

	stats := make(map[PipelineStatus]int)
	for rows.Next() {
		var status sql.NullString
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, fmt.Errorf("failed to scan pipeline stat: %w", err)
		}
		if status.Valid {
			stats[PipelineStatus(status.String)] = count
		} else {
			stats[PipelineEmailSent] = count
		}
	}
	return stats, rows.Err()
}
