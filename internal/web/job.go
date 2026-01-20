package web

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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
	JobStatusPaused    JobStatus = "paused"    // Paused due to daily limit
	JobStatusError     JobStatus = "error"     // Stopped due to auth/config error
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
	ErrorType     string    `json:"error_type,omitempty"`   // "auth", "rate_limit", etc.
	DailyLimit    int       `json:"daily_limit,omitempty"`  // Max emails per day
	DaySent       int       `json:"day_sent,omitempty"`     // Emails sent today

	ctx              context.Context
	cancelFunc       context.CancelFunc
	mu               sync.Mutex
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

// Complete marks the job as completed
func (j *Job) Complete() {
	j.mu.Lock()
	defer j.mu.Unlock()

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
		if job.Status == JobStatusRunning {
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
		if job.Status != JobStatusRunning && job.CompletedAt.Before(cutoff) {
			delete(jm.jobs, id)
		}
	}
}

// PersistentJobState represents a job that can be saved/loaded from disk
type PersistentJobState struct {
	ID               string    `json:"id"`
	Status           JobStatus `json:"status"`
	Sent             int       `json:"sent"`
	Failed           int       `json:"failed"`
	Total            int       `json:"total"`
	StartedAt        time.Time `json:"started_at"`
	RemainingBrokers []string  `json:"remaining_brokers"` // Broker IDs still to process
	Search           string    `json:"search"`            // Original filter params
	Category         string    `json:"category"`
	Region           string    `json:"region"`
	StatusFilter     string    `json:"status_filter"`
}

// JobPersistence handles saving/loading job state
type JobPersistence struct {
	dataDir string
}

// NewJobPersistence creates a new job persistence handler
func NewJobPersistence(dataDir string) *JobPersistence {
	return &JobPersistence{dataDir: dataDir}
}

func (jp *JobPersistence) filePath() string {
	return filepath.Join(jp.dataDir, "pending_job.json")
}

// Save saves the job state to disk
func (jp *JobPersistence) Save(state *PersistentJobState) error {
	if err := os.MkdirAll(jp.dataDir, 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(jp.filePath(), data, 0600)
}

// Load loads a pending job state from disk, returns nil if none exists
func (jp *JobPersistence) Load() (*PersistentJobState, error) {
	data, err := os.ReadFile(jp.filePath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var state PersistentJobState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}

	return &state, nil
}

// Clear removes the saved job state
func (jp *JobPersistence) Clear() error {
	err := os.Remove(jp.filePath())
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
