package history

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

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
	EmailBody    string // Stored for reclassification
	FormURL      string // Extracted form URL (if any)
	ConfirmURL   string // Extracted confirmation URL (if any)
	Confidence   float64
	NeedsReview  bool
	ReceivedAt   time.Time
	ProcessedAt  time.Time
	CreatedAt    time.Time
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

func NewStore(dbPath string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0700); err != nil {
		return nil, fmt.Errorf("failed to create history directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	store := &Store{db: db}
	if err := store.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) migrate() error {
	// First, try to add new columns to existing databases
	// These must run before the index creation below
	s.db.Exec(`ALTER TABLE removal_requests ADD COLUMN pipeline_status TEXT DEFAULT 'email_sent'`)
	s.db.Exec(`ALTER TABLE pending_tasks ADD COLUMN opened_at DATETIME`)

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
		form_url TEXT,
		confirm_url TEXT,
		confidence REAL,
		needs_review INTEGER DEFAULT 0,
		received_at DATETIME,
		processed_at DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_br_broker_id ON broker_responses(broker_id);
	CREATE INDEX IF NOT EXISTS idx_br_response_type ON broker_responses(response_type);
	CREATE INDEX IF NOT EXISTS idx_br_needs_review ON broker_responses(needs_review);

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

func (s *Store) GetLastRequestForBroker(brokerID string) (*Record, error) {
	query := `
	SELECT id, broker_id, broker_name, email, template, status, message_id, error, sent_at, created_at
	FROM removal_requests WHERE broker_id = ? ORDER BY sent_at DESC LIMIT 1`

	record, err := scanRecord(s.db.QueryRow(query, brokerID))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query record: %w", err)
	}
	return record, nil
}

func (s *Store) GetRecentRequests(limit int) ([]Record, error) {
	query := `
	SELECT id, broker_id, broker_name, email, template, status, message_id, error, sent_at, created_at
	FROM removal_requests ORDER BY sent_at DESC LIMIT ?`

	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query records: %w", err)
	}
	defer rows.Close()

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

func (s *Store) GetAllBrokerStatuses() (map[string]BrokerStatus, error) {
	query := `SELECT broker_id, MAX(sent_at) as last_sent,
		(SELECT status FROM removal_requests r2 WHERE r2.broker_id = r.broker_id ORDER BY sent_at DESC LIMIT 1),
		COUNT(*) FROM removal_requests r GROUP BY broker_id`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query broker statuses: %w", err)
	}
	defer rows.Close()

	statuses := make(map[string]BrokerStatus)
	for rows.Next() {
		var bs BrokerStatus
		var lastSent sql.NullTime
		var status string

		if err := rows.Scan(&bs.BrokerID, &lastSent, &status, &bs.TotalSent); err != nil {
			return nil, fmt.Errorf("failed to scan broker status: %w", err)
		}
		bs.LastSent = lastSent.Time
		bs.Status = Status(status)
		statuses[bs.BrokerID] = bs
	}
	return statuses, rows.Err()
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
	home, err := os.UserHomeDir()
	if err != nil {
		return "eraser_history.db"
	}
	return filepath.Join(home, ".eraser", "history.db")
}

// ==================== Broker Response Methods ====================

// AddBrokerResponse stores a classified response from a broker
func (s *Store) AddBrokerResponse(resp *BrokerResponse) error {
	query := `
	INSERT INTO broker_responses (broker_id, broker_name, response_type, email_from, email_subject, email_body,
		form_url, confirm_url, confidence, needs_review, received_at, processed_at, created_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	needsReview := 0
	if resp.NeedsReview {
		needsReview = 1
	}

	result, err := s.db.Exec(query,
		resp.BrokerID, resp.BrokerName, resp.ResponseType, resp.EmailFrom, resp.EmailSubject, resp.EmailBody,
		resp.FormURL, resp.ConfirmURL, resp.Confidence, needsReview,
		resp.ReceivedAt, time.Now(), time.Now(),
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

// FindBrokerResponseBySubject finds an existing response by broker_id and email_subject
func (s *Store) FindBrokerResponseBySubject(brokerID, subject string) (*BrokerResponse, error) {
	query := `SELECT id, broker_id, broker_name, response_type, email_from, email_subject,
		form_url, confirm_url, confidence, needs_review, received_at, processed_at, created_at
		FROM broker_responses WHERE broker_id = ? AND email_subject = ? LIMIT 1`

	var r BrokerResponse
	var needsReviewInt int
	var receivedAtStr, processedAtStr, createdAtStr sql.NullString
	var formURL, confirmURL sql.NullString

	err := s.db.QueryRow(query, brokerID, subject).Scan(
		&r.ID, &r.BrokerID, &r.BrokerName, &r.ResponseType, &r.EmailFrom, &r.EmailSubject,
		&formURL, &confirmURL, &r.Confidence, &needsReviewInt, &receivedAtStr, &processedAtStr, &createdAtStr)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to find broker response: %w", err)
	}

	r.FormURL = formURL.String
	r.ConfirmURL = confirmURL.String
	r.NeedsReview = needsReviewInt == 1

	return &r, nil
}

// UpdateBrokerResponseClassification updates the classification fields of a response
func (s *Store) UpdateBrokerResponseClassification(id int64, responseType string, formURL, confirmURL string, confidence float64, needsReview bool) error {
	query := `UPDATE broker_responses SET response_type = ?, form_url = ?, confirm_url = ?,
		confidence = ?, needs_review = ?, processed_at = ? WHERE id = ?`

	needsReviewInt := 0
	if needsReview {
		needsReviewInt = 1
	}

	_, err := s.db.Exec(query, responseType, formURL, confirmURL, confidence, needsReviewInt, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to update broker response: %w", err)
	}
	return nil
}

// UpdateBrokerResponseBody updates the email body for an existing response
func (s *Store) UpdateBrokerResponseBody(id int64, body string) error {
	query := `UPDATE broker_responses SET email_body = ? WHERE id = ?`
	_, err := s.db.Exec(query, body, id)
	if err != nil {
		return fmt.Errorf("failed to update broker response body: %w", err)
	}
	return nil
}

// ClearBrokerResponses removes all broker responses (for full re-scan)
func (s *Store) ClearBrokerResponses() error {
	_, err := s.db.Exec("DELETE FROM broker_responses")
	if err != nil {
		return fmt.Errorf("failed to clear broker responses: %w", err)
	}
	return nil
}

// GetAllBrokerResponses retrieves all broker responses (for reclassification)
func (s *Store) GetAllBrokerResponses() ([]BrokerResponse, error) {
	query := `SELECT id, broker_id, broker_name, response_type, email_from, email_subject, email_body,
		form_url, confirm_url, confidence, needs_review, received_at, processed_at, created_at
		FROM broker_responses ORDER BY created_at DESC`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query all broker responses: %w", err)
	}
	defer rows.Close()

	var responses []BrokerResponse
	for rows.Next() {
		var r BrokerResponse
		var needsReviewInt int
		var receivedAtStr, processedAtStr, createdAtStr sql.NullString
		var formURL, confirmURL, emailBody sql.NullString

		err := rows.Scan(&r.ID, &r.BrokerID, &r.BrokerName, &r.ResponseType, &r.EmailFrom, &r.EmailSubject, &emailBody,
			&formURL, &confirmURL, &r.Confidence, &needsReviewInt, &receivedAtStr, &processedAtStr, &createdAtStr)
		if err != nil {
			return nil, fmt.Errorf("failed to scan broker response: %w", err)
		}

		r.EmailBody = emailBody.String
		r.FormURL = formURL.String
		r.ConfirmURL = confirmURL.String
		r.NeedsReview = needsReviewInt == 1

		// Parse time strings
		if receivedAtStr.Valid {
			r.ReceivedAt, _ = time.Parse(time.RFC3339, receivedAtStr.String)
			if r.ReceivedAt.IsZero() {
				r.ReceivedAt, _ = time.Parse("2006-01-02 15:04:05", receivedAtStr.String)
			}
		}
		if processedAtStr.Valid {
			r.ProcessedAt, _ = time.Parse(time.RFC3339, processedAtStr.String)
			if r.ProcessedAt.IsZero() {
				r.ProcessedAt, _ = time.Parse("2006-01-02 15:04:05", processedAtStr.String)
			}
		}
		if createdAtStr.Valid {
			r.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr.String)
			if r.CreatedAt.IsZero() {
				r.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAtStr.String)
			}
		}

		responses = append(responses, r)
	}

	return responses, rows.Err()
}

// GetBrokerResponses retrieves broker responses with optional filtering
func (s *Store) GetBrokerResponses(responseType string, needsReview bool, limit int) ([]BrokerResponse, error) {
	var query string
	var args []interface{}

	if responseType != "" && needsReview {
		query = `SELECT id, broker_id, broker_name, response_type, email_from, email_subject,
			form_url, confirm_url, confidence, needs_review, received_at, processed_at, created_at
			FROM broker_responses WHERE response_type = ? AND needs_review = 1 ORDER BY created_at DESC LIMIT ?`
		args = []interface{}{responseType, limit}
	} else if responseType != "" {
		query = `SELECT id, broker_id, broker_name, response_type, email_from, email_subject,
			form_url, confirm_url, confidence, needs_review, received_at, processed_at, created_at
			FROM broker_responses WHERE response_type = ? ORDER BY created_at DESC LIMIT ?`
		args = []interface{}{responseType, limit}
	} else if needsReview {
		query = `SELECT id, broker_id, broker_name, response_type, email_from, email_subject,
			form_url, confirm_url, confidence, needs_review, received_at, processed_at, created_at
			FROM broker_responses WHERE needs_review = 1 ORDER BY created_at DESC LIMIT ?`
		args = []interface{}{limit}
	} else {
		query = `SELECT id, broker_id, broker_name, response_type, email_from, email_subject,
			form_url, confirm_url, confidence, needs_review, received_at, processed_at, created_at
			FROM broker_responses ORDER BY created_at DESC LIMIT ?`
		args = []interface{}{limit}
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query broker responses: %w", err)
	}
	defer rows.Close()

	var responses []BrokerResponse
	for rows.Next() {
		var r BrokerResponse
		var needsReviewInt int
		var receivedAtStr, processedAtStr, createdAtStr sql.NullString
		var formURL, confirmURL sql.NullString

		err := rows.Scan(&r.ID, &r.BrokerID, &r.BrokerName, &r.ResponseType, &r.EmailFrom, &r.EmailSubject,
			&formURL, &confirmURL, &r.Confidence, &needsReviewInt, &receivedAtStr, &processedAtStr, &createdAtStr)
		if err != nil {
			return nil, fmt.Errorf("failed to scan broker response: %w", err)
		}

		r.FormURL = formURL.String
		r.ConfirmURL = confirmURL.String
		r.NeedsReview = needsReviewInt == 1

		// Parse time strings (SQLite stores as TEXT)
		if receivedAtStr.Valid {
			r.ReceivedAt, _ = time.Parse(time.RFC3339, receivedAtStr.String)
			if r.ReceivedAt.IsZero() {
				r.ReceivedAt, _ = time.Parse("2006-01-02 15:04:05", receivedAtStr.String)
			}
		}
		if processedAtStr.Valid {
			r.ProcessedAt, _ = time.Parse(time.RFC3339, processedAtStr.String)
			if r.ProcessedAt.IsZero() {
				r.ProcessedAt, _ = time.Parse("2006-01-02 15:04:05", processedAtStr.String)
			}
		}
		if createdAtStr.Valid {
			r.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr.String)
			if r.CreatedAt.IsZero() {
				r.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAtStr.String)
			}
		}

		responses = append(responses, r)
	}

	return responses, rows.Err()
}

// GetResponseStats returns counts of response types
func (s *Store) GetResponseStats() (map[string]int, error) {
	query := `SELECT response_type, COUNT(*) FROM broker_responses GROUP BY response_type`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query response stats: %w", err)
	}
	defer rows.Close()

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
	defer rows.Close()

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
	defer rows.Close()

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
	defer rows.Close()

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
