package web

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/eraser-privacy/eraser/internal/config"
)

// SessionStore manages secure server-side sessions
// Credentials are never sent to the client - only an opaque session ID
type SessionStore struct {
	sessions map[string]*Session
	mu       sync.RWMutex
	ttl      time.Duration
}

// Session holds wizard state securely on the server
type Session struct {
	ID        string
	Step      string
	Profile   config.Profile
	Email     config.Email
	CreatedAt time.Time
	ExpiresAt time.Time
}

// NewSessionStore creates a new session store with automatic cleanup
func NewSessionStore(ttl time.Duration) *SessionStore {
	store := &SessionStore{
		sessions: make(map[string]*Session),
		ttl:      ttl,
	}

	// Start background cleanup goroutine
	go store.cleanupLoop()

	return store
}

// generateSessionID creates a cryptographically secure session ID
func generateSessionID() (string, error) {
	bytes := make([]byte, 32) // 256 bits
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// Create creates a new session and returns its ID
func (s *SessionStore) Create() (string, error) {
	id, err := generateSessionID()
	if err != nil {
		return "", err
	}

	now := time.Now()
	session := &Session{
		ID:        id,
		CreatedAt: now,
		ExpiresAt: now.Add(s.ttl),
	}

	s.mu.Lock()
	s.sessions[id] = session
	s.mu.Unlock()

	return id, nil
}

// Get retrieves a session by ID, returns nil if not found or expired
func (s *SessionStore) Get(id string) *Session {
	if id == "" {
		return nil
	}

	s.mu.RLock()
	session, exists := s.sessions[id]
	s.mu.RUnlock()

	if !exists {
		return nil
	}

	// Check if expired
	if time.Now().After(session.ExpiresAt) {
		s.Delete(id)
		return nil
	}

	return session
}

// Update updates a session's data and extends its expiry
func (s *SessionStore) Update(id string, updateFn func(*Session)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, exists := s.sessions[id]
	if !exists {
		return false
	}

	// Check if expired
	if time.Now().After(session.ExpiresAt) {
		delete(s.sessions, id)
		return false
	}

	// Apply updates
	updateFn(session)

	// Extend expiry
	session.ExpiresAt = time.Now().Add(s.ttl)

	return true
}

// Delete removes a session
func (s *SessionStore) Delete(id string) {
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
}

// cleanupLoop periodically removes expired sessions
func (s *SessionStore) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.cleanup()
	}
}

// cleanup removes all expired sessions
func (s *SessionStore) cleanup() {
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	for id, session := range s.sessions {
		if now.After(session.ExpiresAt) {
			delete(s.sessions, id)
		}
	}
}

// Count returns the number of active sessions (for monitoring)
func (s *SessionStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}
