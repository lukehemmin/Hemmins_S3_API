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
//
// TTL and IdleTTL are captured from the SessionStore at session creation time.
// This ensures that hot-reloading session TTL settings only affects new sessions;
// existing sessions retain the TTL policy active when they were created.
// Per configuration-model.md section 8.3: session TTL hot-reload is applied to new sessions only.
type Session struct {
	ID         string
	Username   string
	Role       string
	CreatedAt  time.Time
	LastSeenAt time.Time
	TTL        time.Duration // absolute TTL captured at session creation time
	IdleTTL    time.Duration // idle TTL captured at session creation time
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

	s.mu.Lock()
	sess := &Session{
		ID:         id,
		Username:   username,
		Role:       role,
		CreatedAt:  now,
		LastSeenAt: now,
		TTL:        s.ttl,     // capture current store TTL at creation time
		IdleTTL:    s.idleTTL, // capture current store idle TTL at creation time
	}
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

	// Enforce absolute expiry using this session's own TTL (captured at creation time).
	if now.Sub(sess.CreatedAt) > sess.TTL {
		delete(s.sessions, id)
		return nil, false
	}

	// Enforce idle expiry using this session's own idle TTL (captured at creation time).
	if now.Sub(sess.LastSeenAt) > sess.IdleTTL {
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

// UpdateTTLs updates the absolute and idle TTLs used for newly created sessions.
// Existing sessions are not affected; they retain the TTL values captured at creation time.
//
// Policy rationale (conservative):
//   - Shorter TTL (security tightening): takes effect for new sessions immediately.
//     Existing sessions expire at their original deadline — disruptive mid-operation
//     retroactive shortening is avoided.
//   - Longer TTL (convenience): applies to new sessions. Existing sessions are unaffected.
//   - Single-admin use case: retroactive session extension is unnecessary.
//
// Per configuration-model.md section 8.3: safe subset hot-reload applies to new sessions only.
func (s *SessionStore) UpdateTTLs(ttl, idleTTL time.Duration) {
	s.mu.Lock()
	s.ttl = ttl
	s.idleTTL = idleTTL
	s.mu.Unlock()
}

// DeleteByUsername removes all sessions for the given username.
// Returns the number of sessions deleted.
// Per security-model.md section 5.2: password change invalidates all existing sessions.
//
// Policy rationale:
// - Conservative approach: invalidate ALL sessions for the user whose password changed.
// - In-memory store makes per-user scan O(n) but acceptable for admin-only tool.
// - More secure than only invalidating the "current" session — password theft
//   scenarios often involve attacker sessions that should also be terminated.
func (s *SessionStore) DeleteByUsername(username string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	var deleted int
	for id, sess := range s.sessions {
		if sess.Username == username {
			delete(s.sessions, id)
			deleted++
		}
	}
	return deleted
}
