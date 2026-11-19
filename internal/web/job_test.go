package web

import (
	"sync"
	"testing"
	"time"
)

// Run with -race. Each reader goroutine uses only the JobManager method under
// test, never the job's own lock, so nothing orders its reads after the
// writer's locked writes. Any unlocked read of job state is then reported
// regardless of timing. (Calling job.ToJSON from the same reader would take
// the job lock and mask the race.)
func TestJobConcurrentAccess(t *testing.T) {
	for name, read := range map[string]func(*JobManager){
		"GetActive": func(jm *JobManager) { _ = jm.GetActive() },
		"Cleanup":   func(jm *JobManager) { jm.Cleanup(time.Hour) },
	} {
		t.Run(name, func(t *testing.T) {
			jm := NewJobManager()
			job := jm.Create(10)

			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				job.SetDailyLimit(250, 3)
				job.Complete()
			}()
			go func() {
				defer wg.Done()
				for range 100 {
					read(jm)
				}
			}()
			wg.Wait()
		})
	}
}

func TestCompleteKeepsCancelledStatus(t *testing.T) {
	job := NewJobManager().Create(1)
	job.Cancel()
	job.Complete()
	if got := job.ToJSON()["status"]; got != JobStatusCancelled {
		t.Fatalf("status = %v, want cancelled", got)
	}
}
