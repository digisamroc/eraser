package main

import (
	"sync"
	"testing"
)

// The system resolver sometimes says "no such host" for a domain that
// exists; a name only counts as missing if every attempt fails.
func TestResolveAllRetriesFailures(t *testing.T) {
	retryDelay = 0
	var mu sync.Mutex
	calls := map[string]int{}
	check := func(name string) bool {
		mu.Lock()
		defer mu.Unlock()
		calls[name]++
		switch name {
		case "flaky.example":
			return calls[name] == resolveAttempts // fails until the last attempt
		case "live.example":
			return true
		}
		return false
	}

	ok := resolveAll([]string{"flaky.example", "live.example", "gone.example"}, check)
	for name, want := range map[string]bool{"flaky.example": true, "live.example": true, "gone.example": false} {
		if got := ok(name); got != want {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	if calls["live.example"] != 1 || calls["gone.example"] != resolveAttempts {
		t.Errorf("calls = %v", calls)
	}
}
