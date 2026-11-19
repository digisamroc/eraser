package web

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
)

// JobStatus represents the status of a background job
type JobStatus string

const (
	JobStatusRunning   JobStatus = "running"
	JobStatusCompleted JobStatus = "completed"
	JobStatusCancelled JobStatus = "cancelled"
	JobStatusPaused    JobStatus = "paused" // Paused due to daily limit
	JobStatusError     JobStatus = "error"  // Stopped due to auth/config error
)

// Job represents a background email sending job
type Job struct {
	ID            string    `json:"id"`
	Status        JobStatus `json:"status"`
	Progress      int       `json:"progress"`
	Sent          int       `json:"sent"`
	Failed        int       `json:"failed"`
	Total         int       `json:"total"`
	CurrentBroker string    `json:"current_broker"`
	StartedAt     time.Time `json:"started_at"`
	CompletedAt   time.Time `json:"completed_at,omitempty"`
	Error         string    `json:"error,omitempty"`
	ErrorType     string    `json:"error_type,omitempty"`  // "auth", "rate_limit", etc.
	DailyLimit    int       `json:"daily_limit,omitempty"` // Max emails per day
	DaySent       int       `json:"day_sent,omitempty"`    // Emails sent today

	ctx                  context.Context
	cancelFunc           context.CancelFunc
	mu                   sync.Mutex
	consecutiveAuthFails int // Track consecutive auth failures
}

// Update updates the job progress
func (j *Job) Update(sent, failed int, currentBroker string) {
	j.mu.Lock()
	defer j.mu.Unlock()

	j.Sent = sent
	j.Failed = failed
	j.CurrentBroker = currentBroker
	if j.Total > 0 {
		j.Progress = ((sent + failed) * 100) / j.Total
	}
}

// Complete marks a running job as completed. A cancelled job stays cancelled.
func (j *Job) Complete() {
	j.mu.Lock()
	defer j.mu.Unlock()

	if j.Status != JobStatusRunning {
		return
	}
	j.Status = JobStatusCompleted
	j.CompletedAt = time.Now()
	j.Progress = 100
	j.CurrentBroker = ""
}

// StopWithError stops the job due to an error
func (j *Job) StopWithError(errorType, errorMsg string) {
	j.mu.Lock()
	defer j.mu.Unlock()

	j.Status = JobStatusCompleted
	j.CompletedAt = time.Now()
	j.Error = errorMsg
	j.ErrorType = errorType
	j.CurrentBroker = ""
}

// RecordAuthFailure records an auth failure and returns true if job should stop
func (j *Job) RecordAuthFailure() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.consecutiveAuthFails++
	return j.consecutiveAuthFails >= 3
}

// ResetAuthFailures resets the consecutive auth failure counter
func (j *Job) ResetAuthFailures() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.consecutiveAuthFails = 0
}

// Cancel cancels the job
func (j *Job) Cancel() {
	j.mu.Lock()
	defer j.mu.Unlock()

	if j.Status == JobStatusRunning {
		j.Status = JobStatusCancelled
		j.CompletedAt = time.Now()
		if j.cancelFunc != nil {
			j.cancelFunc()
		}
	}
}

// SetDailyLimit records the cap and how many sends it already counts.
func (j *Job) SetDailyLimit(limit, daySent int) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.DailyLimit, j.DaySent = limit, daySent
}

// IsRunning reports whether the job is still running.
func (j *Job) IsRunning() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.Status == JobStatusRunning
}

// IsCancelled returns true if the job was cancelled
func (j *Job) IsCancelled() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.Status == JobStatusCancelled
}

// Context returns the job's context
func (j *Job) Context() context.Context {
	return j.ctx
}

// ToJSON returns the job data for JSON serialization
func (j *Job) ToJSON() map[string]interface{} {
	j.mu.Lock()
	defer j.mu.Unlock()

	return map[string]interface{}{
		"id":             j.ID,
		"status":         j.Status,
		"progress":       j.Progress,
		"sent":           j.Sent,
		"failed":         j.Failed,
		"total":          j.Total,
		"current_broker": j.CurrentBroker,
		"started_at":     j.StartedAt,
		"completed_at":   j.CompletedAt,
		"error":          j.Error,
		"error_type":     j.ErrorType,
		"daily_limit":    j.DailyLimit,
		"day_sent":       j.DaySent,
	}
}

// JobManager manages background jobs
type JobManager struct {
	jobs map[string]*Job
	mu   sync.RWMutex
}

// NewJobManager creates a new job manager
func NewJobManager() *JobManager {
	return &JobManager{
		jobs: make(map[string]*Job),
	}
}

// Create creates a new job with the given total count
func (jm *JobManager) Create(total int) *Job {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())

	job := &Job{
		ID:         uuid.New().String(),
		Status:     JobStatusRunning,
		Progress:   0,
		Sent:       0,
		Failed:     0,
		Total:      total,
		StartedAt:  time.Now(),
		ctx:        ctx,
		cancelFunc: cancel,
	}

	jm.jobs[job.ID] = job
	return job
}

// Get returns a job by ID, or nil if not found
func (jm *JobManager) Get(id string) *Job {
	jm.mu.RLock()
	defer jm.mu.RUnlock()

	return jm.jobs[id]
}

// GetActive returns the currently running job, or nil if none
func (jm *JobManager) GetActive() *Job {
	jm.mu.RLock()
	defer jm.mu.RUnlock()

	for _, job := range jm.jobs {
		if job.IsRunning() {
			return job
		}
	}
	return nil
}

// Cleanup removes completed jobs older than the specified duration
func (jm *JobManager) Cleanup(maxAge time.Duration) {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	for id, job := range jm.jobs {
		if job.finishedBefore(cutoff) {
			delete(jm.jobs, id)
		}
	}
}

func (j *Job) finishedBefore(t time.Time) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.Status != JobStatusRunning && j.CompletedAt.Before(t)
}
