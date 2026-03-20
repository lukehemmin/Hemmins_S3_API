// Package ui implements the management UI session API.
// Per system-architecture.md section 8 and security-model.md section 6.
package ui

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

const sessionIDBytes = 32 // 256-bit session ID

// Session represents an authenticated admin UI session.
// Per security-model.md section 6: absolute and idle expiry are both tracked.
type Session struct {
	ID         string
	Username   string
	Role       string
	CreatedAt  time.Time
	LastSeenAt time.Time
}

// SessionStore is a thread-safe in-memory session store.
//
// Design rationale — in-memory store:
//   - Single-node deployment: no high-availability requirement.
//   - Server restart invalidates all sessions — acceptable for an admin tool.
//   - Memory is bounded: TTL enforcement prevents unbounded growth.
//   - Avoids additional DB schema/migration complexity for Phase 5 slice 1.
//   - Per system-architecture.md section 7.2: "서버 측 세션 저장" is explicitly an option.
type SessionStore struct {
	mu      sync.Mutex
	sessions map[string]*Session
	ttl     time.Duration // absolute session lifetime
	idleTTL time.Duration // maximum idle time between requests
	now     func() time.Time
}

// NewSessionStore creates a SessionStore with the given absolute and idle TTLs.
// Per configuration-model.md section 5.6: defaults are 12h absolute, 30m idle.
// Per security-model.md section 6: both expiry policies must be applied.
func NewSessionStore(ttl, idleTTL time.Duration) *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*Session),
		ttl:      ttl,
		idleTTL:  idleTTL,
		now:      time.Now,
	}
}

// Create generates a new session for username/role and returns the session ID.
// The session ID is a 256-bit cryptographically random value encoded as base64-URL.
// Per security-model.md section 6.
func (s *SessionStore) Create(username, role string) (string, error) {
	b := make([]byte, sessionIDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating session ID: %w", err)
	}
	id := base64.URLEncoding.EncodeToString(b)

	now := s.now()
	sess := &Session{
		ID:         id,
		Username:   username,
		Role:       role,
		CreatedAt:  now,
		LastSeenAt: now,
	}

	s.mu.Lock()
	s.sessions[id] = sess
	s.mu.Unlock()

	return id, nil
}

// Get returns the session for id, enforcing both absolute and idle expiry.
// Updates LastSeenAt on success.
// Returns (nil, false) if the session is absent or expired.
// Per security-model.md section 6: both expiry policies must be enforced.
func (s *SessionStore) Get(id string) (*Session, bool) {
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[id]
	if !ok {
		return nil, false
	}

	// Enforce absolute expiry.
	if now.Sub(sess.CreatedAt) > s.ttl {
		delete(s.sessions, id)
		return nil, false
	}

	// Enforce idle expiry.
	if now.Sub(sess.LastSeenAt) > s.idleTTL {
		delete(s.sessions, id)
		return nil, false
	}

	// Refresh last-seen timestamp.
	sess.LastSeenAt = now
	return sess, true
}

// Delete removes the session for id. No-op if the session does not exist.
// Per security-model.md section 6: logout causes immediate session invalidation.
func (s *SessionStore) Delete(id string) {
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
}
