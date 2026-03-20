package ui

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/lukehemmin/hemmins-s3-api/internal/auth"
	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

const sessionCookieName = "hemmins_session"

// Server handles UI session API requests.
// Per system-architecture.md section 8: UI is served from the same binary as the S3 API.
// Per security-model.md section 6: sessions use HttpOnly, SameSite=Lax cookies.
type Server struct {
	db           *metadata.DB
	store        *SessionStore
	secureCookie bool // true when server.public_endpoint starts with "https://"
}

// NewServer creates a UI Server backed by db using store for session management.
// secureCookie must be true when cfg.Server.PublicEndpoint has an https:// prefix.
// Per security-model.md sections 6 and 7: Secure cookie is required for HTTPS public endpoints.
func NewServer(db *metadata.DB, store *SessionStore, secureCookie bool) *Server {
	return &Server{
		db:           db,
		store:        store,
		secureCookie: secureCookie,
	}
}

// Handler returns the http.Handler serving all UI session API routes.
//
// Route map:
//
//	POST /ui/api/session/login   → login
//	GET  /ui/api/session/me      → session info
//	POST /ui/api/session/logout  → logout
//	anything else under /ui/     → 404 Not Found
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/ui/api/session/login", s.handleLogin)
	mux.HandleFunc("/ui/api/session/me", s.handleMe)
	mux.HandleFunc("/ui/api/session/logout", s.handleLogout)
	mux.HandleFunc("/ui/api/dashboard", s.handleDashboard)
	mux.HandleFunc("/ui/api/buckets", s.handleBuckets)
	// Catch-all for unrecognized /ui/* paths.
	mux.HandleFunc("/ui/", func(w http.ResponseWriter, r *http.Request) {
		writeJSONError(w, http.StatusNotFound, "not found")
	})
	return mux
}

// handleLogin implements POST /ui/api/session/login.
//
// Request body: {"username": "...", "password": "..."}
// Success: 200 JSON {"username": "...", "role": "..."} + Set-Cookie header.
// Failure: 401 JSON {"error": "invalid credentials"}.
//
// The response does NOT distinguish "user not found" from "wrong password"
// to prevent username enumeration. Per security-model.md section 8.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.Username == "" || body.Password == "" {
		writeJSONError(w, http.StatusBadRequest, "username and password are required")
		return
	}

	// Retrieve user.
	// ErrUserNotFound → 401 (unknown username, audit log).
	// Any other DB error → 500 (server-side fault, error log, no details to client).
	// The two cases are kept generic at the response level to prevent username enumeration.
	user, err := s.db.LookupUIUser(body.Username)
	if err != nil {
		if errors.Is(err, metadata.ErrUserNotFound) {
			log.Printf("AUDIT login_failure username=%q reason=unknown_user", body.Username)
			writeJSONError(w, http.StatusUnauthorized, "invalid credentials")
		} else {
			log.Printf("ERROR handleLogin LookupUIUser(%q): %v", body.Username, err)
			writeJSONError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}

	// Verify password.
	// (false, nil) → wrong password → 401 (audit log).
	// (false, err) → stored hash is malformed / unreadable → 500 (error log, not an auth failure).
	ok, err := auth.VerifyPassword(body.Password, user.PasswordHash)
	if err != nil {
		log.Printf("ERROR handleLogin VerifyPassword username=%q: %v", body.Username, err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !ok {
		log.Printf("AUDIT login_failure username=%q reason=bad_password", body.Username)
		writeJSONError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	sessionID, err := s.store.Create(user.Username, user.Role)
	if err != nil {
		log.Printf("ERROR handleLogin create session: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Best-effort audit timestamp — failure does not reject the login.
	if err := s.db.TouchUIUserLastLogin(user.Username); err != nil {
		log.Printf("ERROR handleLogin TouchUIUserLastLogin(%q): %v", user.Username, err)
	}

	log.Printf("AUDIT login_success username=%q role=%q", user.Username, user.Role)

	http.SetCookie(w, s.newSessionCookie(sessionID))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"username": user.Username,
		"role":     user.Role,
	})
}

// handleMe implements GET /ui/api/session/me.
// Returns 200 JSON with the current session's username and role, or 401 if not authenticated.
// Per security-model.md section 6.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	sess, ok := s.sessionFromRequest(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"username": sess.Username,
		"role":     sess.Role,
	})
}

// handleLogout implements POST /ui/api/session/logout.
// Invalidates the session and clears the session cookie.
// Returns 204 No Content — idempotent: absent or invalid session also returns 204.
//
// Policy decision: idempotent 204.
// Rationale: prevents leaking session-existence info to callers that retry on errors,
// and is consistent with safe-delete semantics. Pinned by TestLogout_Idempotent.
// Per security-model.md sections 6 and 8.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		// Retrieve session for audit log, then delete unconditionally.
		if sess, ok := s.store.Get(cookie.Value); ok {
			log.Printf("AUDIT logout username=%q", sess.Username)
		}
		s.store.Delete(cookie.Value)
	}

	// Clear the cookie regardless of whether a session existed.
	http.SetCookie(w, s.clearSessionCookie())
	w.WriteHeader(http.StatusNoContent)
}

// sessionFromRequest reads the session cookie and returns the validated session.
func (s *Server) sessionFromRequest(r *http.Request) (*Session, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, false
	}
	return s.store.Get(cookie.Value)
}

// newSessionCookie builds the Set-Cookie for an active session.
// Per security-model.md section 6: HttpOnly, SameSite=Lax, optional Secure.
func (s *Server) newSessionCookie(sessionID string) *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.secureCookie,
	}
}

// clearSessionCookie builds a Set-Cookie that expires the session cookie immediately.
// Per security-model.md section 6: logout must clear the session cookie.
func (s *Server) clearSessionCookie() *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.secureCookie,
		MaxAge:   -1, // instructs browser to delete the cookie (serialized as Max-Age=0)
	}
}

// requireSession extracts and validates the session from the request.
// Writes 401 JSON and returns (nil, false) if the session is absent or expired.
// Use this in handlers that require authentication.
func (s *Server) requireSession(w http.ResponseWriter, r *http.Request) (*Session, bool) {
	sess, ok := s.sessionFromRequest(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "not authenticated")
		return nil, false
	}
	return sess, true
}

// handleDashboard implements GET /ui/api/dashboard.
// Returns aggregate storage statistics for the admin dashboard.
// Session required; 401 if not authenticated.
// Per product-spec.md section 7.2.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if _, ok := s.requireSession(w, r); !ok {
		return
	}

	stats, err := s.db.GetDashboardStats()
	if err != nil {
		log.Printf("ERROR handleDashboard GetDashboardStats: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}

// bucketItem is the JSON shape of a single entry in the GET /ui/api/buckets response.
type bucketItem struct {
	Name         string `json:"name"`
	CreationDate string `json:"creationDate"` // RFC3339 UTC
}

// handleBuckets implements GET /ui/api/buckets.
// Returns all buckets as a JSON array with name and creationDate (RFC3339).
// Session required; 401 if not authenticated.
// Per product-spec.md section 7.1.
func (s *Server) handleBuckets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if _, ok := s.requireSession(w, r); !ok {
		return
	}

	buckets, err := s.db.ListBuckets()
	if err != nil {
		log.Printf("ERROR handleBuckets ListBuckets: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	items := make([]bucketItem, len(buckets))
	for i, b := range buckets {
		items[i] = bucketItem{
			Name:         b.Name,
			CreationDate: b.CreatedAt.UTC().Format(time.RFC3339),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(items)
}

// writeJSONError writes a JSON error response.
func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// WithReadinessGate wraps inner with a middleware that returns 503 when isReady() == false.
// Prevents all /ui/ endpoints from behaving like a normal auth API in setup-required or
// partial-init state, where no admin users exist yet.
//
// Without this gate, POST /ui/api/session/login would return 401 "invalid credentials"
// (DB has no users), which misleads callers into thinking bootstrap succeeded but
// credentials are wrong. A 503 with "setup required" is unambiguous.
//
// Per security-model.md §3.2: in setup-required state, the login screen must not be
// exposed as a normal login screen.
func WithReadinessGate(isReady func() bool, inner http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isReady() {
			writeJSONError(w, http.StatusServiceUnavailable, "setup required")
			return
		}
		inner.ServeHTTP(w, r)
	})
}
