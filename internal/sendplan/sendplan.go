// Package sendplan decides which brokers a send run should email, shared by
// the CLI and the web UI so both apply the same resend and daily-cap rules.
package sendplan

import (
	"time"

	"github.com/eraser-privacy/eraser/internal/broker"
)

// Window is the period the daily cap covers. Gmail's sending limit is a
// rolling 24 hours, so the cap uses the same window.
const Window = 24 * time.Hour

// Options controls a plan.
type Options struct {
	Now             time.Time
	ResendAfterDays int  // skip brokers successfully sent to within this many days
	ForceResend     bool // ignore ResendAfterDays
	DailyLimit      int  // maximum successful sends per Window, including earlier runs
	Limit           int  // optional cap for this run; 0 means none
}

// Plan is the outcome of Build.
type Plan struct {
	Send           []broker.Broker // to email now, in order
	SkippedRecent  []broker.Broker // sent successfully within ResendAfterDays
	Deferred       int             // eligible but held back by the daily cap or Limit
	RemainingToday int             // daily cap headroom before this run
}

// WindowStart returns the start of the daily-cap window ending at now.
func WindowStart(now time.Time) time.Time {
	return now.Add(-Window)
}

// Build applies resend and cap rules. lastSent maps broker ID to the time of
// its latest successful send; sentInWindow counts sends since WindowStart(now).
func Build(candidates []broker.Broker, lastSent map[string]time.Time, sentInWindow int, opts Options) Plan {
	var p Plan
	p.RemainingToday = max(opts.DailyLimit-sentInWindow, 0)

	cutoff := opts.Now.AddDate(0, 0, -opts.ResendAfterDays)
	budget := p.RemainingToday
	if opts.Limit > 0 && opts.Limit < budget {
		budget = opts.Limit
	}

	for _, b := range candidates {
		if at, ok := lastSent[b.ID]; ok && !opts.ForceResend && at.After(cutoff) {
			p.SkippedRecent = append(p.SkippedRecent, b)
			continue
		}
		if len(p.Send) >= budget {
			p.Deferred++
			continue
		}
		p.Send = append(p.Send, b)
	}
	return p
}
