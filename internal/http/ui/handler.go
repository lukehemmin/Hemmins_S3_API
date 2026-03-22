package ui

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lukehemmin/hemmins-s3-api/internal/auth"
	"github.com/lukehemmin/hemmins-s3-api/internal/config"
	"github.com/lukehemmin/hemmins-s3-api/internal/http/s3"
	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
	"github.com/lukehemmin/hemmins-s3-api/internal/storage"
)

const sessionCookieName = "hemmins_session"

// Server handles UI session API requests.
// Per system-architecture.md section 8: UI is served from the same binary as the S3 API.
// Per security-model.md section 6: sessions use HttpOnly, SameSite=Lax cookies.
type Server struct {
	db           *metadata.DB
	store        *SessionStore
	secureCookie bool // true when server.public_endpoint starts with "https://"
	settingsView *SettingsView

	// Storage paths for object upload API.
	// Set by SetConfig from the runtime configuration.
	objectRoot string
	tempRoot   string

	// Presign configuration for presigned URL generation.
	// Set by SetConfig from the runtime configuration.
	publicEndpoint string
	region         string
	masterKey      string
	maxPresignTTL  time.Duration
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

// SetConfig attaches a read-only configuration view for the settings API
// and extracts storage paths needed for object upload and presigned URL generation.
// Must be called before Handler() if settings API, object upload, or presigned URL is needed.
// Per product-spec.md section 7.4 and configuration-model.md section 10.1.
func (s *Server) SetConfig(cfg *config.Config) {
	s.settingsView = NewSettingsView(cfg)
	s.objectRoot = cfg.Paths.ObjectRoot
	s.tempRoot = cfg.Paths.TempRoot
	s.publicEndpoint = cfg.Server.PublicEndpoint
	s.region = cfg.S3.Region
	s.masterKey = cfg.Auth.MasterKey
	s.maxPresignTTL = cfg.S3.MaxPresignTTL.Duration
}

// Handler returns the http.Handler serving all UI session API routes.
//
// Route map:
//
//	GET  /ui/api/session/csrf    → CSRF token (no session required)
//	POST /ui/api/session/login   → login (CSRF required)
//	GET  /ui/api/session/me      → session info
//	POST /ui/api/session/logout  → logout (CSRF required)
//	GET  /ui/api/dashboard       → dashboard stats
//	GET  /ui/api/buckets         → bucket list
//	POST /ui/api/buckets         → create bucket (CSRF required)
//	DELETE /ui/api/buckets/{name} → delete bucket (CSRF required)
//	GET  /ui/api/buckets/{name}/objects → list objects in bucket
//	DELETE /ui/api/buckets/{name}/objects?key=... → delete object (CSRF required)
//	GET  /ui/api/buckets/{name}/objects/download?key=... → download object
//	POST /ui/api/buckets/{name}/objects/upload?key=... → upload object (CSRF required)
//	GET  /ui/api/buckets/{name}/objects/meta?key=... → get object metadata
//	POST /ui/api/buckets/{name}/objects/presign → generate presigned URL (CSRF required)
//	GET  /ui/api/settings        → settings and path status
//	GET  /ui/api/access-keys    → list access keys (session required)
//	POST /ui/api/access-keys    → create access key (session + CSRF required)
//	POST /ui/api/access-keys/revoke → revoke access key (session + CSRF required)
//	POST /ui/api/access-keys/delete → delete access key (session + CSRF required)
//	POST /ui/api/account/password → change admin password (session + CSRF required)
//	anything else under /ui/     → 404 Not Found
//
// Per security-model.md section 6: state-changing requests require CSRF protection.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/ui/api/session/csrf", s.handleCSRF)
	mux.HandleFunc("/ui/api/session/login", s.handleLogin)
	mux.HandleFunc("/ui/api/session/me", s.handleMe)
	mux.HandleFunc("/ui/api/session/logout", s.handleLogout)
	mux.HandleFunc("/ui/api/dashboard", s.handleDashboard)
	mux.HandleFunc("/ui/api/buckets", s.handleBuckets)
	mux.HandleFunc("/ui/api/buckets/", s.handleBucketByName)
	mux.HandleFunc("/ui/api/settings", s.handleSettings)
	mux.HandleFunc("/ui/api/access-keys", s.handleAccessKeys)
	mux.HandleFunc("/ui/api/access-keys/revoke", s.handleAccessKeysRevoke)
	mux.HandleFunc("/ui/api/access-keys/delete", s.handleAccessKeysDelete)
	mux.HandleFunc("/ui/api/account/password", s.handlePasswordChange)
	// API catch-all: any unrecognized /ui/api/* path returns JSON 404.
	mux.HandleFunc("/ui/api/", func(w http.ResponseWriter, r *http.Request) {
		writeJSONError(w, http.StatusNotFound, "not found")
	})
	// Static file server for /ui/* (non-API) paths.
	// Serves index.html for SPA shell and static assets (CSS, JS).
	// Per implementation-roadmap.md Phase 5: UI shell from same binary.
	mux.Handle("/ui/", staticFileServer())
	return mux
}

// handleLogin implements POST /ui/api/session/login.
//
// Request body: {"username": "...", "password": "..."}
// Success: 200 JSON {"username": "...", "role": "..."} + Set-Cookie header.
// Failure: 401 JSON {"error": "invalid credentials"}.
// CSRF failure: 403 JSON {"error": "CSRF validation failed"}.
//
// The response does NOT distinguish "user not found" from "wrong password"
// to prevent username enumeration. Per security-model.md section 8.
// Per security-model.md section 6: state-changing requests require CSRF protection.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// CSRF validation is required for login.
	// Per security-model.md section 6: state-changing requests require CSRF protection.
	if !s.requireCSRF(w, r) {
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
// CSRF failure: 403 JSON {"error": "CSRF validation failed"}.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// CSRF validation is required for logout.
	// Per security-model.md section 6: state-changing requests require CSRF protection.
	if !s.requireCSRF(w, r) {
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
	// Also clear the CSRF cookie on logout.
	clearCSRFCookie(w, s.secureCookie)
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

// handleCSRF implements GET /ui/api/session/csrf.
//
// Issues a CSRF token in both JSON body and Set-Cookie header.
// This endpoint does NOT require an existing session because CSRF tokens
// are needed before login. However, it respects the setup-required gating.
//
// Response: 200 JSON {"token": "..."}
// Also sets hemmins_csrf cookie with SameSite=Lax.
//
// Per security-model.md section 6: state-changing requests require CSRF protection.
// The client must:
//  1. Call GET /ui/api/session/csrf to obtain a token
//  2. Include the token in X-CSRF-Token header on POST requests
//  3. The browser automatically sends the cookie
func (s *Server) handleCSRF(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	token, err := generateCSRFToken()
	if err != nil {
		log.Printf("ERROR handleCSRF generateCSRFToken: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	setCSRFCookie(w, token, s.secureCookie)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"token": token,
	})
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

// handleBuckets implements GET /ui/api/buckets and POST /ui/api/buckets.
//
// GET: Returns all buckets as a JSON array with name and creationDate (RFC3339).
// POST: Creates a new bucket. Request body: {"name":"bucket-name"}
//
// Session required; 401 if not authenticated.
// POST requires CSRF; 403 if CSRF validation fails.
// Per product-spec.md section 7.1 and security-model.md section 6.
func (s *Server) handleBuckets(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleBucketsGet(w, r)
	case http.MethodPost:
		s.handleBucketsCreate(w, r)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleBucketsGet implements GET /ui/api/buckets.
// Returns all buckets as a JSON array with name and creationDate (RFC3339).
func (s *Server) handleBucketsGet(w http.ResponseWriter, r *http.Request) {
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

// handleBucketsCreate implements POST /ui/api/buckets.
//
// Request body: {"name":"bucket-name"}
// Success: 201 Created with JSON {"name":"...", "creationDate":"..."}
// Errors:
//   - 400: invalid JSON body, missing name, or invalid bucket name
//   - 401: not authenticated
//   - 403: CSRF validation failed
//   - 409: bucket already exists
//   - 500: internal error
//
// Per product-spec.md section 7.3 and security-model.md section 6.
func (s *Server) handleBucketsCreate(w http.ResponseWriter, r *http.Request) {
	// Session required.
	if _, ok := s.requireSession(w, r); !ok {
		return
	}

	// CSRF required for state-changing operations.
	if !s.requireCSRF(w, r) {
		return
	}

	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.Name == "" {
		writeJSONError(w, http.StatusBadRequest, "bucket name is required")
		return
	}

	// Reuse S3 bucket name validation to ensure consistency.
	// Per s3-compatibility-matrix.md section 2.3.
	if err := s3.ValidateBucketName(body.Name); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid bucket name")
		return
	}

	createdAt := time.Now().UTC()
	if err := s.db.CreateBucket(body.Name, createdAt); err != nil {
		if errors.Is(err, metadata.ErrBucketAlreadyExists) {
			writeJSONError(w, http.StatusConflict, "bucket already exists")
			return
		}
		log.Printf("ERROR handleBucketsCreate CreateBucket(%q): %v", body.Name, err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	log.Printf("AUDIT bucket_created name=%q", body.Name)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(bucketItem{
		Name:         body.Name,
		CreationDate: createdAt.Format(time.RFC3339),
	})
}

// handleBucketByName routes requests for /ui/api/buckets/{name}[/...].
//
// Supported operations:
//   - DELETE /ui/api/buckets/{name} → delete bucket
//   - GET /ui/api/buckets/{name}/objects → list objects in bucket
//   - DELETE /ui/api/buckets/{name}/objects?key=... → delete object (CSRF required)
//   - GET /ui/api/buckets/{name}/objects/download?key=... → download object
//   - POST /ui/api/buckets/{name}/objects/upload?key=... → upload object (CSRF required)
//   - GET /ui/api/buckets/{name}/objects/meta?key=... → get object metadata
//   - POST /ui/api/buckets/{name}/objects/presign → generate presigned URL (CSRF required)
//
// Per product-spec.md section 7.3 and security-model.md section 6.
func (s *Server) handleBucketByName(w http.ResponseWriter, r *http.Request) {
	// Extract bucket name and sub-path from: /ui/api/buckets/{name}[/objects[/download|upload|meta|presign]]
	const prefix = "/ui/api/buckets/"
	remainder := strings.TrimPrefix(r.URL.Path, prefix)
	if remainder == "" {
		writeJSONError(w, http.StatusBadRequest, "bucket name is required")
		return
	}

	// Check if this is a /objects sub-resource request.
	if idx := strings.Index(remainder, "/"); idx >= 0 {
		bucketName := remainder[:idx]
		subPath := remainder[idx+1:]
		if subPath == "objects" {
			s.handleBucketObjects(w, r, bucketName)
			return
		}
		if subPath == "objects/download" {
			s.handleObjectDownload(w, r, bucketName)
			return
		}
		if subPath == "objects/upload" {
			s.handleObjectUpload(w, r, bucketName)
			return
		}
		if subPath == "objects/meta" {
			s.handleObjectMeta(w, r, bucketName)
			return
		}
		if subPath == "objects/presign" {
			s.handleObjectPresign(w, r, bucketName)
			return
		}
		// Unknown sub-resource.
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}

	// No sub-path: this is a bucket-level operation (DELETE).
	bucketName := remainder
	s.handleBucketDelete(w, r, bucketName)
}

// handleBucketDelete implements DELETE /ui/api/buckets/{name}.
//
// Deletes a bucket by name extracted from the URL path.
// Success: 204 No Content
// Errors:
//   - 400: invalid bucket name
//   - 401: not authenticated
//   - 403: CSRF validation failed
//   - 404: bucket not found
//   - 409: bucket not empty
//   - 500: internal error
//
// Per product-spec.md section 7.1 and security-model.md section 6.
func (s *Server) handleBucketDelete(w http.ResponseWriter, r *http.Request, name string) {
	if r.Method != http.MethodDelete {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Session required.
	if _, ok := s.requireSession(w, r); !ok {
		return
	}

	// CSRF required for state-changing operations.
	if !s.requireCSRF(w, r) {
		return
	}

	// Validate bucket name using S3 rules.
	// Per s3-compatibility-matrix.md section 2.3.
	if err := s3.ValidateBucketName(name); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid bucket name")
		return
	}

	// Delete the bucket.
	if err := s.db.DeleteBucket(name); err != nil {
		if errors.Is(err, metadata.ErrBucketNotFound) {
			writeJSONError(w, http.StatusNotFound, "bucket not found")
			return
		}
		if errors.Is(err, metadata.ErrBucketNotEmpty) {
			writeJSONError(w, http.StatusConflict, "bucket not empty")
			return
		}
		log.Printf("ERROR handleBucketDelete DeleteBucket(%q): %v", name, err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	log.Printf("AUDIT bucket_deleted name=%q", name)
	w.WriteHeader(http.StatusNoContent)
}

// listObjectsMaxKeys is the default and maximum value for maxKeys in object listing.
// Matches the S3 API behavior per s3-compatibility-matrix.md section 7.
const listObjectsMaxKeys = 1000

// objectItem represents a single object in the JSON response for object listing.
type objectItem struct {
	Key          string `json:"key"`
	Size         int64  `json:"size"`
	ETag         string `json:"etag"` // quoted MD5, e.g. "d41d8cd98f00b204e9800998ecf8427e"
	LastModified string `json:"lastModified"` // RFC3339 UTC
	ContentType  string `json:"contentType"`
	StorageClass string `json:"storageClass"`
}

// listObjectsResponse is the JSON response for GET /ui/api/buckets/{name}/objects.
type listObjectsResponse struct {
	Bucket                string       `json:"bucket"`
	Prefix                string       `json:"prefix"`
	Delimiter             string       `json:"delimiter,omitempty"`
	MaxKeys               int          `json:"maxKeys"`
	KeyCount              int          `json:"keyCount"`
	IsTruncated           bool         `json:"isTruncated"`
	NextContinuationToken string       `json:"nextContinuationToken,omitempty"`
	Objects               []objectItem `json:"objects"`
	CommonPrefixes        []string     `json:"commonPrefixes,omitempty"`
}

// handleBucketObjects routes requests for /ui/api/buckets/{name}/objects.
//
// Supported operations:
//   - GET    /ui/api/buckets/{name}/objects → list objects in bucket
//   - DELETE /ui/api/buckets/{name}/objects?key=... → delete object (CSRF required)
//
// Per product-spec.md section 7.3 and security-model.md section 6.
func (s *Server) handleBucketObjects(w http.ResponseWriter, r *http.Request, bucketName string) {
	switch r.Method {
	case http.MethodGet:
		s.handleObjectList(w, r, bucketName)
	case http.MethodDelete:
		s.handleObjectDelete(w, r, bucketName)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleObjectList implements GET /ui/api/buckets/{name}/objects.
//
// Returns a paginated list of objects in the bucket as JSON.
// Query parameters:
//   - prefix: filter objects by key prefix
//   - delimiter: group keys by delimiter (for folder-like browsing)
//   - continuationToken: pagination cursor from previous response
//   - maxKeys: maximum number of items to return (default 1000, max 1000)
//
// Session required; CSRF is NOT required (GET request).
// Per product-spec.md section 7.3 and security-model.md section 6.
func (s *Server) handleObjectList(w http.ResponseWriter, r *http.Request, bucketName string) {
	// Session required.
	if _, ok := s.requireSession(w, r); !ok {
		return
	}

	// Validate bucket name using S3 rules.
	if err := s3.ValidateBucketName(bucketName); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid bucket name")
		return
	}

	// Check bucket exists.
	exists, err := s.db.BucketExists(bucketName)
	if err != nil {
		log.Printf("ERROR handleObjectList BucketExists(%q): %v", bucketName, err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !exists {
		writeJSONError(w, http.StatusNotFound, "bucket not found")
		return
	}

	// Parse query parameters.
	q := r.URL.Query()
	prefix := q.Get("prefix")
	delimiter := q.Get("delimiter")
	continuationToken := q.Get("continuationToken")

	// Parse maxKeys: default 1000, max 1000, reject zero and negative.
	maxKeys := listObjectsMaxKeys
	if mk := q.Get("maxKeys"); mk != "" {
		n, err := strconv.Atoi(mk)
		if err != nil || n <= 0 {
			writeJSONError(w, http.StatusBadRequest, "maxKeys must be a positive integer")
			return
		}
		if n > listObjectsMaxKeys {
			n = listObjectsMaxKeys
		}
		maxKeys = n
	}

	// Call metadata layer.
	opts := metadata.ListOptions{
		Prefix:            prefix,
		Delimiter:         delimiter,
		MaxKeys:           maxKeys,
		ContinuationToken: continuationToken,
	}

	result, err := s.db.ListObjectsV2(bucketName, opts)
	if err != nil {
		if errors.Is(err, metadata.ErrInvalidContinuationToken) {
			writeJSONError(w, http.StatusBadRequest, "invalid continuation token")
			return
		}
		log.Printf("ERROR handleObjectList ListObjectsV2(%q): %v", bucketName, err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Build JSON response.
	resp := listObjectsResponse{
		Bucket:                bucketName,
		Prefix:                prefix,
		Delimiter:             delimiter,
		MaxKeys:               maxKeys,
		KeyCount:              result.KeyCount,
		IsTruncated:           result.IsTruncated,
		NextContinuationToken: result.NextContinuationToken,
		Objects:               make([]objectItem, len(result.Objects)),
		CommonPrefixes:        result.CommonPrefixes,
	}

	for i, obj := range result.Objects {
		resp.Objects[i] = objectItem{
			Key:          obj.Key,
			Size:         obj.Size,
			ETag:         "\"" + obj.ETag + "\"", // quoted per S3 convention
			LastModified: obj.LastModified.UTC().Format(time.RFC3339),
			ContentType:  obj.ContentType,
			StorageClass: obj.StorageClass,
		}
	}

	// Ensure objects array is never null in JSON.
	if resp.Objects == nil {
		resp.Objects = []objectItem{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleObjectDownload implements GET /ui/api/buckets/{name}/objects/download?key=...
//
// Downloads a single object as a raw byte stream with appropriate headers.
// Query parameter:
//   - key: the object key to download (required)
//
// Success: raw object body with Content-Type, Content-Length, ETag, Last-Modified headers.
// Errors are JSON responses:
//   - 400: missing key parameter or invalid bucket name
//   - 401: not authenticated
//   - 404: bucket or object not found
//   - 405: method not allowed
//   - 500: internal error (blob missing/corrupt, DB error)
//
// Session required; CSRF is NOT required (GET request).
// Per product-spec.md section 7.3 and security-model.md section 6.
func (s *Server) handleObjectDownload(w http.ResponseWriter, r *http.Request, bucketName string) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Session required.
	if _, ok := s.requireSession(w, r); !ok {
		return
	}

	// Validate bucket name using S3 rules.
	if err := s3.ValidateBucketName(bucketName); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid bucket name")
		return
	}

	// Get the object key from query parameter.
	objectKey := r.URL.Query().Get("key")
	if objectKey == "" {
		writeJSONError(w, http.StatusBadRequest, "key parameter is required")
		return
	}

	// Check bucket exists.
	exists, err := s.db.BucketExists(bucketName)
	if err != nil {
		log.Printf("ERROR handleObjectDownload BucketExists(%q): %v", bucketName, err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !exists {
		writeJSONError(w, http.StatusNotFound, "bucket not found")
		return
	}

	// Look up object metadata.
	obj, err := s.db.GetObjectByKey(bucketName, objectKey)
	if err != nil {
		if errors.Is(err, metadata.ErrObjectNotFound) {
			writeJSONError(w, http.StatusNotFound, "object not found")
			return
		}
		if errors.Is(err, metadata.ErrCorruptObject) {
			// Blob is expected to be present but is marked corrupt.
			// Return a generic 500; do not reveal internal state.
			log.Printf("ERROR handleObjectDownload corrupt object bucket=%q key=%q", bucketName, objectKey)
			writeJSONError(w, http.StatusInternalServerError, "internal error")
			return
		}
		log.Printf("ERROR handleObjectDownload GetObjectByKey(%q, %q): %v", bucketName, objectKey, err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Open the blob file.
	// A missing blob with a valid metadata row is a corruption state.
	// Return a generic 500; never expose the raw storage_path.
	f, err := os.Open(obj.StoragePath)
	if err != nil {
		log.Printf("ERROR handleObjectDownload open blob bucket=%q key=%q: %v", bucketName, objectKey, err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer f.Close()

	// Set response headers before streaming.
	w.Header().Set("Content-Type", obj.ContentType)
	w.Header().Set("Content-Length", strconv.FormatInt(obj.Size, 10))
	w.Header().Set("ETag", `"`+obj.ETag+`"`)
	w.Header().Set("Last-Modified", obj.LastModified.UTC().Format(http.TimeFormat))

	// Restore x-amz-meta-* user metadata from stored metadata_json.
	if obj.MetadataJSON != "" && obj.MetadataJSON != "{}" {
		var userMeta map[string]string
		if jsonErr := json.Unmarshal([]byte(obj.MetadataJSON), &userMeta); jsonErr == nil {
			for k, v := range userMeta {
				w.Header().Set("X-Amz-Meta-"+k, v)
			}
		}
	}

	// Write status and stream body.
	w.WriteHeader(http.StatusOK)
	if _, copyErr := io.Copy(w, f); copyErr != nil {
		// Headers already sent; nothing useful we can do for the client here.
		log.Printf("ERROR handleObjectDownload stream bucket=%q key=%q: %v", bucketName, objectKey, copyErr)
	}
}

// handleObjectDelete implements DELETE /ui/api/buckets/{name}/objects?key=...
//
// Deletes a single object from the bucket.
// Query parameter:
//   - key: the object key to delete (required)
//
// Success: 204 No Content
// Errors are JSON responses:
//   - 400: missing key parameter or invalid bucket name
//   - 401: not authenticated
//   - 403: CSRF validation failed
//   - 404: bucket or object not found
//   - 500: internal error
//
// Deletion semantics follow the S3 API and operations-runbook.md section 4.1:
//   - Metadata row is deleted first (atomic transaction)
//   - Then blob file is removed
//   - If blob removal fails, the orphan blob becomes a quarantine candidate (recoverable)
//   - Corrupt objects (metadata row exists but blob missing) can still be deleted
//
// Session and CSRF required; per product-spec.md section 7.3 and security-model.md section 6.
func (s *Server) handleObjectDelete(w http.ResponseWriter, r *http.Request, bucketName string) {
	// Session required.
	if _, ok := s.requireSession(w, r); !ok {
		return
	}

	// CSRF required for state-changing operations.
	if !s.requireCSRF(w, r) {
		return
	}

	// Validate bucket name using S3 rules.
	if err := s3.ValidateBucketName(bucketName); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid bucket name")
		return
	}

	// Get the object key from query parameter.
	objectKey := r.URL.Query().Get("key")
	if objectKey == "" {
		writeJSONError(w, http.StatusBadRequest, "key parameter is required")
		return
	}

	// Check bucket exists.
	exists, err := s.db.BucketExists(bucketName)
	if err != nil {
		log.Printf("ERROR handleObjectDelete BucketExists(%q): %v", bucketName, err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !exists {
		writeJSONError(w, http.StatusNotFound, "bucket not found")
		return
	}

	// Delete the metadata row, obtaining the blob storage path.
	// Per operations-runbook.md section 4.1: metadata first, blob second.
	// is_corrupt is intentionally ignored by DeleteObject so that corrupt
	// objects can be cleaned up via the normal API.
	storagePath, err := s.db.DeleteObject(bucketName, objectKey)
	if err != nil {
		if errors.Is(err, metadata.ErrObjectNotFound) {
			writeJSONError(w, http.StatusNotFound, "object not found")
			return
		}
		log.Printf("ERROR handleObjectDelete DeleteObject(%q, %q): %v", bucketName, objectKey, err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Remove the blob file.
	// Per operations-runbook.md section 4.1: metadata row is already deleted,
	// so any blob removal outcome still results in success.
	// Never expose storagePath (raw filesystem path) in any response.
	// Per security-model.md section 4.3.
	if removeErr := os.Remove(storagePath); removeErr != nil {
		if os.IsNotExist(removeErr) {
			// Blob already gone (corrupt object, or prior cleanup).
			// Metadata row is cleaned up; system is consistent.
			log.Printf("WARN handleObjectDelete blob already absent bucket=%q key=%q", bucketName, objectKey)
		} else {
			// Unexpected error removing blob. The blob becomes an orphan
			// recoverable by startup recovery.
			log.Printf("ERROR handleObjectDelete remove blob bucket=%q key=%q: %v", bucketName, objectKey, removeErr)
		}
		// Continue: return success. Raw error is NOT forwarded to the client.
	}

	log.Printf("AUDIT object_deleted bucket=%q key=%q", bucketName, objectKey)
	w.WriteHeader(http.StatusNoContent)
}

// handleObjectUpload implements POST /ui/api/buckets/{name}/objects/upload?key=...
//
// Uploads a single object to the bucket from raw request body.
// Query parameter:
//   - key: the object key to create (required)
//
// Request headers:
//   - Content-Type: stored as object content type (default: application/octet-stream)
//   - X-Amz-Meta-*: stored as user metadata
//
// Success: 201 Created with JSON response:
//
//	{
//	  "bucket": "...",
//	  "key": "...",
//	  "size": 12345,
//	  "etag": "\"md5hex...\"",
//	  "contentType": "...",
//	  "lastModified": "2024-01-01T00:00:00Z"
//	}
//
// Errors are JSON responses:
//   - 400: missing key parameter or invalid bucket name
//   - 401: not authenticated
//   - 403: CSRF validation failed
//   - 404: bucket not found
//   - 500: internal error (storage/DB failure)
//
// Upload semantics follow the S3 API per s3-compatibility-matrix.md section 6.1:
//   - Overwrite is allowed; existing object is atomically replaced
//   - Metadata is fully replaced on overwrite, not merged
//
// Session and CSRF required; per product-spec.md section 7.3 and security-model.md section 6.
func (s *Server) handleObjectUpload(w http.ResponseWriter, r *http.Request, bucketName string) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Session required.
	if _, ok := s.requireSession(w, r); !ok {
		return
	}

	// CSRF required for state-changing operations.
	if !s.requireCSRF(w, r) {
		return
	}

	// Validate bucket name using S3 rules.
	if err := s3.ValidateBucketName(bucketName); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid bucket name")
		return
	}

	// Get the object key from query parameter.
	objectKey := r.URL.Query().Get("key")
	if objectKey == "" {
		writeJSONError(w, http.StatusBadRequest, "key parameter is required")
		return
	}

	// Check bucket exists.
	exists, err := s.db.BucketExists(bucketName)
	if err != nil {
		log.Printf("ERROR handleObjectUpload BucketExists(%q): %v", bucketName, err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !exists {
		writeJSONError(w, http.StatusNotFound, "bucket not found")
		return
	}

	// Storage paths must be configured.
	if s.objectRoot == "" || s.tempRoot == "" {
		log.Printf("ERROR handleObjectUpload storage paths not configured")
		writeJSONError(w, http.StatusInternalServerError, "upload not available")
		return
	}

	// Generate UUID for the blob file and compute storage path.
	// Per system-architecture.md section 3: sharded by first 4 hex chars.
	objectID := uuid.NewString()
	destPath := storage.StoragePath(s.objectRoot, objectID)

	// Stream body through MD5 hasher; AtomicWrite handles temp → rename → fsync.
	// Per system-architecture.md section 5.1: blob must be durably written before metadata commit.
	bodyReader := r.Body
	if bodyReader == nil {
		bodyReader = http.NoBody
	}
	h := md5.New()
	body := io.TeeReader(bodyReader, h)

	result, err := storage.AtomicWrite(r.Context(), s.tempRoot, destPath, body)
	if err != nil {
		log.Printf("ERROR handleObjectUpload AtomicWrite(%q): %v", destPath, err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// ETag is the raw MD5 hex of the full body bytes.
	// Per s3-compatibility-matrix.md section 6.2.
	etag := hex.EncodeToString(h.Sum(nil))

	// Resolve content-type; default per RFC 7233 / S3 docs.
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	// Collect x-amz-meta-* headers and serialize to JSON.
	// Per s3-compatibility-matrix.md section 5.1.
	userMeta := make(map[string]string)
	for k, vv := range r.Header {
		lower := strings.ToLower(k)
		if strings.HasPrefix(lower, "x-amz-meta-") {
			metaKey := lower[len("x-amz-meta-"):]
			if len(vv) > 0 {
				userMeta[metaKey] = vv[0]
			}
		}
	}
	metaJSON := "{}"
	if len(userMeta) > 0 {
		b, jerr := json.Marshal(userMeta)
		if jerr == nil {
			metaJSON = string(b)
		}
	}

	// Commit metadata. Blob is already durably written at this point.
	// Per system-architecture.md section 5.1.
	now := time.Now().UTC()
	input := metadata.PutObjectInput{
		Size:         result.Size,
		ETag:         etag,
		ContentType:  contentType,
		StoragePath:  destPath,
		LastModified: now,
		MetadataJSON: metaJSON,
	}
	if err := s.db.UpsertObject(bucketName, objectKey, input); err != nil {
		log.Printf("ERROR handleObjectUpload UpsertObject(%q, %q): %v", bucketName, objectKey, err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	log.Printf("AUDIT object_uploaded bucket=%q key=%q size=%d", bucketName, objectKey, result.Size)

	// Success response: 201 Created with JSON.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"bucket":       bucketName,
		"key":          objectKey,
		"size":         result.Size,
		"etag":         `"` + etag + `"`,
		"contentType":  contentType,
		"lastModified": now.Format(time.RFC3339),
	})
}

// objectMetaResponse is the JSON response for GET /ui/api/buckets/{name}/objects/meta.
type objectMetaResponse struct {
	Bucket       string            `json:"bucket"`
	Key          string            `json:"key"`
	Size         int64             `json:"size"`
	ETag         string            `json:"etag"` // quoted MD5, e.g. "\"d41d8cd98f00b204e9800998ecf8427e\""
	ContentType  string            `json:"contentType"`
	LastModified string            `json:"lastModified"` // RFC3339 UTC
	StorageClass string            `json:"storageClass"`
	UserMetadata map[string]string `json:"userMetadata"`
}

// handleObjectMeta implements GET /ui/api/buckets/{name}/objects/meta?key=...
//
// Returns metadata for a single object as JSON.
// Query parameter:
//   - key: the object key to query (required)
//
// Success: 200 JSON with object metadata (bucket, key, size, etag, contentType, lastModified, storageClass, userMetadata).
// Errors are JSON responses:
//   - 400: missing key parameter or invalid bucket name
//   - 401: not authenticated
//   - 404: bucket or object not found
//   - 405: method not allowed
//   - 500: internal error (corrupt object, DB error)
//
// Session required; CSRF is NOT required (GET request, read-only).
// Per product-spec.md section 7.3 ("메타데이터 보기") and security-model.md section 6.
//
// Internal fields NOT exposed:
//   - storage_path (internal filesystem path)
//   - object_id (internal UUID)
//   - is_corrupt (internal state flag)
//   - checksum_sha256 (not used in Phase 2)
func (s *Server) handleObjectMeta(w http.ResponseWriter, r *http.Request, bucketName string) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Session required.
	if _, ok := s.requireSession(w, r); !ok {
		return
	}

	// Validate bucket name using S3 rules.
	if err := s3.ValidateBucketName(bucketName); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid bucket name")
		return
	}

	// Get the object key from query parameter.
	objectKey := r.URL.Query().Get("key")
	if objectKey == "" {
		writeJSONError(w, http.StatusBadRequest, "key parameter is required")
		return
	}

	// Check bucket exists.
	exists, err := s.db.BucketExists(bucketName)
	if err != nil {
		log.Printf("ERROR handleObjectMeta BucketExists(%q): %v", bucketName, err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !exists {
		writeJSONError(w, http.StatusNotFound, "bucket not found")
		return
	}

	// Look up object metadata.
	obj, err := s.db.GetObjectByKey(bucketName, objectKey)
	if err != nil {
		if errors.Is(err, metadata.ErrObjectNotFound) {
			writeJSONError(w, http.StatusNotFound, "object not found")
			return
		}
		if errors.Is(err, metadata.ErrCorruptObject) {
			// Object is marked corrupt (metadata row exists but blob is missing).
			// Return a generic 500; do not reveal internal state.
			log.Printf("ERROR handleObjectMeta corrupt object bucket=%q key=%q", bucketName, objectKey)
			writeJSONError(w, http.StatusInternalServerError, "internal error")
			return
		}
		log.Printf("ERROR handleObjectMeta GetObjectByKey(%q, %q): %v", bucketName, objectKey, err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Parse user metadata from stored metadata_json.
	// Per s3-compatibility-matrix.md section 5.1: x-amz-meta-* headers.
	userMeta := make(map[string]string)
	if obj.MetadataJSON != "" && obj.MetadataJSON != "{}" {
		if jsonErr := json.Unmarshal([]byte(obj.MetadataJSON), &userMeta); jsonErr != nil {
			// JSON parse failure: log but continue with empty map (degraded response).
			log.Printf("WARN handleObjectMeta metadata_json parse error bucket=%q key=%q: %v", bucketName, objectKey, jsonErr)
		}
	}

	// Build JSON response.
	// ETag is quoted per S3 convention, matching list and download behavior.
	// Per s3-compatibility-matrix.md section 6.2 and objectItem formatting.
	resp := objectMetaResponse{
		Bucket:       bucketName,
		Key:          objectKey,
		Size:         obj.Size,
		ETag:         `"` + obj.ETag + `"`,
		ContentType:  obj.ContentType,
		LastModified: obj.LastModified.UTC().Format(time.RFC3339),
		StorageClass: "STANDARD", // Phase 2: always STANDARD per system-architecture.md section 4.2
		UserMetadata: userMeta,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// presignRequest is the JSON request body for POST /ui/api/buckets/{name}/objects/presign.
type presignRequest struct {
	Key            string `json:"key"`
	Method         string `json:"method"` // GET or PUT
	ExpiresSeconds int64  `json:"expiresSeconds"`
}

// presignResponse is the JSON response for POST /ui/api/buckets/{name}/objects/presign.
type presignResponse struct {
	URL            string `json:"url"`
	Method         string `json:"method"`
	ExpiresSeconds int64  `json:"expiresSeconds"`
}

// handleObjectPresign implements POST /ui/api/buckets/{name}/objects/presign.
//
// Generates a presigned URL for GET or PUT access to an object.
// Request body:
//
//	{
//	  "key": "path/to/object.txt",
//	  "method": "GET",  // or "PUT"
//	  "expiresSeconds": 3600
//	}
//
// Success: 200 JSON with presigned URL:
//
//	{
//	  "url": "http://...",
//	  "method": "GET",
//	  "expiresSeconds": 3600
//	}
//
// Errors are JSON responses:
//   - 400: invalid JSON body, missing key, invalid method, expiresSeconds too large/invalid, invalid bucket name
//   - 401: not authenticated
//   - 403: CSRF validation failed
//   - 404: bucket not found
//   - 405: method not allowed
//   - 500: internal error (presign config missing, DB error, signer error)
//
// Policies:
//   - GET presign: Does NOT require object to exist (per S3 behavior)
//   - PUT presign: Does NOT require object to exist (allows creating new objects)
//   - expiresSeconds must be positive and <= config.s3.max_presign_ttl
//
// Session and CSRF required; per product-spec.md section 7.3 and security-model.md section 6.
func (s *Server) handleObjectPresign(w http.ResponseWriter, r *http.Request, bucketName string) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Session required.
	if _, ok := s.requireSession(w, r); !ok {
		return
	}

	// CSRF required for state-changing operations.
	if !s.requireCSRF(w, r) {
		return
	}

	// Validate bucket name using S3 rules.
	if err := s3.ValidateBucketName(bucketName); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid bucket name")
		return
	}

	// Check bucket exists.
	exists, err := s.db.BucketExists(bucketName)
	if err != nil {
		log.Printf("ERROR handleObjectPresign BucketExists(%q): %v", bucketName, err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !exists {
		writeJSONError(w, http.StatusNotFound, "bucket not found")
		return
	}

	// Parse request body.
	var body presignRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Validate key.
	if body.Key == "" {
		writeJSONError(w, http.StatusBadRequest, "key is required")
		return
	}

	// Validate method.
	method := strings.ToUpper(body.Method)
	if method != "GET" && method != "PUT" {
		writeJSONError(w, http.StatusBadRequest, "method must be GET or PUT")
		return
	}

	// Validate expiresSeconds.
	if body.ExpiresSeconds <= 0 {
		writeJSONError(w, http.StatusBadRequest, "expiresSeconds must be positive")
		return
	}

	// Check against max TTL.
	maxTTL := s.maxPresignTTL
	if maxTTL == 0 {
		maxTTL = 7 * 24 * time.Hour // AWS default: 7 days
	}
	if time.Duration(body.ExpiresSeconds)*time.Second > maxTTL {
		writeJSONError(w, http.StatusBadRequest, "expiresSeconds exceeds maximum allowed TTL")
		return
	}

	// Check that presign configuration is available.
	if s.publicEndpoint == "" {
		log.Printf("ERROR handleObjectPresign: public_endpoint not configured")
		writeJSONError(w, http.StatusInternalServerError, "presign not available")
		return
	}
	if s.region == "" {
		log.Printf("ERROR handleObjectPresign: region not configured")
		writeJSONError(w, http.StatusInternalServerError, "presign not available")
		return
	}
	if s.masterKey == "" {
		log.Printf("ERROR handleObjectPresign: master_key not configured")
		writeJSONError(w, http.StatusInternalServerError, "presign not available")
		return
	}

	// Get the root access key and secret for signing.
	// Per security-model.md section 8.1: use the root access key for presign generation.
	accessKey, secretKey, err := s.getRootAccessKey()
	if err != nil {
		log.Printf("ERROR handleObjectPresign getRootAccessKey: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Create signer and generate presigned URL.
	signer := auth.PresignSigner{
		Region:         s.region,
		Service:        "s3",
		AccessKeyID:    accessKey,
		SecretKey:      secretKey,
		PublicEndpoint: s.publicEndpoint,
		MaxTTL:         maxTTL,
	}

	result, err := signer.Sign(method, bucketName, body.Key, body.ExpiresSeconds)
	if err != nil {
		log.Printf("ERROR handleObjectPresign Sign: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	log.Printf("AUDIT presign_generated bucket=%q key=%q method=%s expires=%d", bucketName, body.Key, method, body.ExpiresSeconds)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(presignResponse{
		URL:            result.URL,
		Method:         result.Method,
		ExpiresSeconds: result.ExpiresSeconds,
	})
}

// getRootAccessKey retrieves the root access key ID and decrypted secret.
// Per security-model.md section 4.2: secrets are decrypted with auth.master_key.
// Returns error if no root key exists or decryption fails.
func (s *Server) getRootAccessKey() (accessKeyID, secretKey string, err error) {
	// Look up the root access key from the database.
	rootKey, err := s.db.GetRootAccessKey()
	if err != nil {
		return "", "", err
	}

	// Decrypt the secret using the master key.
	secret, err := auth.DecryptSecret(s.masterKey, rootKey.SecretCiphertext)
	if err != nil {
		return "", "", err
	}

	return rootKey.AccessKey, secret, nil
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

// handleAccessKeys routes GET and POST for /ui/api/access-keys.
// Per product-spec.md section 7.4: access key management is part of settings.
func (s *Server) handleAccessKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleAccessKeysList(w, r)
	case http.MethodPost:
		s.handleAccessKeysCreate(w, r)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleAccessKeysList implements GET /ui/api/access-keys.
// Returns a JSON array of access key summaries (without secrets).
// Session required; 401 if not authenticated.
//
// Response fields per key:
//   - accessKey: the access key ID
//   - status: "active" or "inactive"
//   - isRoot: boolean
//   - description: string (may be empty)
//   - createdAt: RFC3339 timestamp
//   - lastUsedAt: RFC3339 timestamp or null
//
// Per security-model.md section 4.2: secret_ciphertext is NEVER included.
func (s *Server) handleAccessKeysList(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireSession(w, r); !ok {
		return
	}

	keys, err := s.db.ListAccessKeys()
	if err != nil {
		log.Printf("ERROR handleAccessKeysList ListAccessKeys: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(keys)
}

// accessKeyCreateRequest is the request body for POST /ui/api/access-keys.
type accessKeyCreateRequest struct {
	Description string `json:"description"` // optional, defaults to empty
}

// accessKeyCreateResponse is the response body for POST /ui/api/access-keys.
// SecretKey is included ONLY in the create response; it is never shown again.
// Per security-model.md section 4.2: no secret re-display after creation.
type accessKeyCreateResponse struct {
	AccessKey   string `json:"accessKey"`
	SecretKey   string `json:"secretKey"` // Only in create response, never again
	Status      string `json:"status"`
	Description string `json:"description"`
	CreatedAt   string `json:"createdAt"`
}

// handleAccessKeysCreate implements POST /ui/api/access-keys.
// Creates a new non-root service access key.
//
// Request body: {"description":"optional description"}
// Success: 201 Created with JSON {accessKey, secretKey, status, description, createdAt}
// Errors:
//   - 400: invalid JSON body
//   - 401: not authenticated
//   - 403: CSRF validation failed
//   - 500: internal error
//
// Per product-spec.md section 8.1: service keys are non-root (is_root=false).
// Per security-model.md sections 4.2 and 8: secret is shown once, key creation is audited.
func (s *Server) handleAccessKeysCreate(w http.ResponseWriter, r *http.Request) {
	// Session required.
	if _, ok := s.requireSession(w, r); !ok {
		return
	}

	// CSRF required for state-changing operations.
	if !s.requireCSRF(w, r) {
		return
	}

	var body accessKeyCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		// Empty body or parse error both result in default empty description.
		// Only reject if the body is malformed JSON that's not empty.
		if err.Error() != "EOF" {
			writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
	}

	// Generate new access key ID.
	accessKeyID, err := auth.GenerateAccessKeyID()
	if err != nil {
		log.Printf("ERROR handleAccessKeysCreate GenerateAccessKeyID: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Generate new secret access key.
	secretKey, err := auth.GenerateSecretAccessKey()
	if err != nil {
		log.Printf("ERROR handleAccessKeysCreate GenerateSecretAccessKey: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Encrypt secret with master key before storing.
	// Per security-model.md section 4.2: plaintext secrets are never stored.
	ciphertext, err := auth.EncryptSecret(s.masterKey, secretKey)
	if err != nil {
		log.Printf("ERROR handleAccessKeysCreate EncryptSecret: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Create the access key in the database.
	summary, err := s.db.CreateAccessKey(accessKeyID, ciphertext, body.Description)
	if err != nil {
		if errors.Is(err, metadata.ErrAccessKeyAlreadyExists) {
			// This should be extremely rare due to random generation, but handle it.
			writeJSONError(w, http.StatusConflict, "access key already exists")
			return
		}
		log.Printf("ERROR handleAccessKeysCreate CreateAccessKey: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Audit log: key creation event (without secret).
	// Per security-model.md section 8: key creation is an auditable event.
	log.Printf("AUDIT access_key_created access_key=%s is_root=false description=%q", accessKeyID, body.Description)

	// Return 201 Created with the access key and secret.
	// Per security-model.md section 4.2: secretKey is returned only this once.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(accessKeyCreateResponse{
		AccessKey:   summary.AccessKey,
		SecretKey:   secretKey, // Only time the secret is shown
		Status:      summary.Status,
		Description: summary.Description,
		CreatedAt:   summary.CreatedAt.Format(time.RFC3339),
	})
}

// accessKeyRevokeRequest is the request body for POST /ui/api/access-keys/revoke.
type accessKeyRevokeRequest struct {
	AccessKey string `json:"accessKey"` // required: the access key ID to revoke
}

// accessKeyRevokeResponse is the response body for POST /ui/api/access-keys/revoke.
// Per security-model.md section 4.2: secret/ciphertext fields are NEVER included.
type accessKeyRevokeResponse struct {
	AccessKey string `json:"accessKey"`
	Status    string `json:"status"`
}

// handleAccessKeysRevoke implements POST /ui/api/access-keys/revoke.
// Revokes (deactivates) an access key by setting its status to "inactive".
// Session required; CSRF required.
//
// Request body: {"accessKey": "AKIA..."}
// Success: 200 OK with JSON {accessKey, status: "inactive"}
// Errors:
//   - 400: missing accessKey field
//   - 401: not authenticated
//   - 403: CSRF validation failed OR attempting to revoke root key
//   - 404: access key not found
//   - 405: method not allowed (only POST)
//   - 500: internal error
//
// Policy decisions:
//   - Root key revocation is rejected (403 Forbidden) per security-model.md section 5.1
//   - Already inactive keys return success (idempotent)
//
// Per security-model.md section 5.1: key deactivation is an auditable event.
// Per security-model.md section 4.3: secret/ciphertext must NEVER appear in logs or responses.
func (s *Server) handleAccessKeysRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Session required.
	if _, ok := s.requireSession(w, r); !ok {
		return
	}

	// CSRF required for state-changing operations.
	if !s.requireCSRF(w, r) {
		return
	}

	var body accessKeyRevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if body.AccessKey == "" {
		writeJSONError(w, http.StatusBadRequest, "accessKey is required")
		return
	}

	// Revoke the access key.
	summary, err := s.db.RevokeAccessKey(body.AccessKey)
	if err != nil {
		if errors.Is(err, metadata.ErrAccessKeyNotFound) {
			writeJSONError(w, http.StatusNotFound, "access key not found")
			return
		}
		if errors.Is(err, metadata.ErrCannotRevokeRootKey) {
			// Per security-model.md section 5.1: at least one active root key must be maintained.
			writeJSONError(w, http.StatusForbidden, "cannot revoke root access key")
			return
		}
		log.Printf("ERROR handleAccessKeysRevoke RevokeAccessKey: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Audit log: key revocation event (without secret).
	// Per security-model.md section 8: key deactivation is an auditable event.
	log.Printf("AUDIT access_key_revoked access_key=%s", body.AccessKey)

	// Return 200 OK with the revoked key summary.
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(accessKeyRevokeResponse{
		AccessKey: summary.AccessKey,
		Status:    summary.Status,
	})
}

// accessKeyDeleteRequest is the request body for POST /ui/api/access-keys/delete.
type accessKeyDeleteRequest struct {
	AccessKey string `json:"accessKey"` // required: the access key ID to delete
}

// accessKeyDeleteResponse is the response body for POST /ui/api/access-keys/delete.
// Per security-model.md section 4.2: secret/ciphertext fields are NEVER included.
type accessKeyDeleteResponse struct {
	AccessKey string `json:"accessKey"`
	Deleted   bool   `json:"deleted"`
}

// handleAccessKeysDelete implements POST /ui/api/access-keys/delete.
// Permanently deletes an access key row from the database.
// Session required; CSRF required.
//
// Request body: {"accessKey": "AKIA..."}
// Success: 200 OK with JSON {accessKey, deleted: true}
// Errors:
//   - 400: missing accessKey field
//   - 401: not authenticated
//   - 403: CSRF validation failed OR attempting to delete root key
//   - 404: access key not found
//   - 405: method not allowed (only POST)
//   - 409: attempting to delete active key (must revoke first)
//   - 500: internal error
//
// Policy decisions (per security-model.md section 5.1):
//   - Root key deletion is rejected (403 Forbidden)
//   - Active key deletion is rejected (409 Conflict) — must revoke first
//   - Only inactive non-root keys can be deleted
//
// Per security-model.md section 8: key deletion is an auditable event.
// Per security-model.md section 4.3: secret/ciphertext must NEVER appear in logs or responses.
func (s *Server) handleAccessKeysDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Session required.
	if _, ok := s.requireSession(w, r); !ok {
		return
	}

	// CSRF required for state-changing operations.
	if !s.requireCSRF(w, r) {
		return
	}

	var body accessKeyDeleteRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if body.AccessKey == "" {
		writeJSONError(w, http.StatusBadRequest, "accessKey is required")
		return
	}

	// Delete the access key.
	err := s.db.DeleteAccessKey(body.AccessKey)
	if err != nil {
		if errors.Is(err, metadata.ErrAccessKeyNotFound) {
			writeJSONError(w, http.StatusNotFound, "access key not found")
			return
		}
		if errors.Is(err, metadata.ErrCannotDeleteRootKey) {
			// Per security-model.md section 5.1: root keys cannot be deleted.
			writeJSONError(w, http.StatusForbidden, "cannot delete root access key")
			return
		}
		if errors.Is(err, metadata.ErrCannotDeleteActiveKey) {
			// Per security-model.md section 5.1: must revoke before delete.
			writeJSONError(w, http.StatusConflict, "cannot delete active access key; revoke first")
			return
		}
		log.Printf("ERROR handleAccessKeysDelete DeleteAccessKey: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Audit log: key deletion event (without secret).
	// Per security-model.md section 8: key deletion is an auditable event.
	log.Printf("AUDIT access_key_deleted access_key=%s", body.AccessKey)

	// Return 200 OK with the deletion confirmation.
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(accessKeyDeleteResponse{
		AccessKey: body.AccessKey,
		Deleted:   true,
	})
}

// passwordChangeRequest is the request body for POST /ui/api/account/password.
type passwordChangeRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

// passwordChangeResponse is the response body for POST /ui/api/account/password.
type passwordChangeResponse struct {
	Changed bool `json:"changed"`
}

// handlePasswordChange implements POST /ui/api/account/password.
//
// Changes the password for the currently logged-in admin user.
//
// Request body:
//
//	{
//	  "currentPassword": "...",
//	  "newPassword": "..."
//	}
//
// Responses:
//   - 200: {"changed": true} — password changed successfully
//   - 400: missing or invalid request body, empty newPassword
//   - 401: not authenticated (no valid session)
//   - 403: CSRF validation failed, or currentPassword mismatch
//   - 405: method not allowed (only POST)
//   - 500: internal error
//
// Per security-model.md section 4.1: passwords are stored as argon2id hashes.
// Per security-model.md section 5.2: password change invalidates existing sessions.
// Per security-model.md section 8: password change is an auditable event.
//
// Session invalidation policy:
// All sessions for the user are invalidated upon password change, not just the current one.
// This is the conservative approach: if the password was compromised, attacker sessions
// should also be terminated. The user must log in again after changing password.
func (s *Server) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Session required — must be logged in to change password.
	sess, ok := s.requireSession(w, r)
	if !ok {
		return
	}

	// CSRF required for state-changing operations.
	if !s.requireCSRF(w, r) {
		return
	}

	var body passwordChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Validate input — do not log password values.
	if body.CurrentPassword == "" {
		writeJSONError(w, http.StatusBadRequest, "currentPassword is required")
		return
	}
	if body.NewPassword == "" {
		writeJSONError(w, http.StatusBadRequest, "newPassword is required")
		return
	}

	// Retrieve user from DB to get current password hash.
	user, err := s.db.LookupUIUser(sess.Username)
	if err != nil {
		// Should not happen for a valid session, but handle gracefully.
		if errors.Is(err, metadata.ErrUserNotFound) {
			log.Printf("ERROR handlePasswordChange user %q from session not found in DB", sess.Username)
			writeJSONError(w, http.StatusUnauthorized, "not authenticated")
			return
		}
		log.Printf("ERROR handlePasswordChange LookupUIUser(%q): %v", sess.Username, err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Verify current password.
	// Per security-model.md section 5.2: password change requires re-authentication.
	match, err := auth.VerifyPassword(body.CurrentPassword, user.PasswordHash)
	if err != nil {
		log.Printf("ERROR handlePasswordChange VerifyPassword for user %q: %v", sess.Username, err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !match {
		// Do not disclose that it was specifically the password that was wrong.
		// Use 403 Forbidden to distinguish from 401 (no session).
		log.Printf("AUDIT password_change_failure username=%q reason=bad_current_password", sess.Username)
		writeJSONError(w, http.StatusForbidden, "current password is incorrect")
		return
	}

	// Hash the new password.
	newHash, err := auth.HashPassword(body.NewPassword)
	if err != nil {
		log.Printf("ERROR handlePasswordChange HashPassword: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Update password in database.
	if err := s.db.UpdateUIUserPassword(sess.Username, newHash); err != nil {
		if errors.Is(err, metadata.ErrUserNotFound) {
			// Race condition: user was deleted between session check and update.
			log.Printf("ERROR handlePasswordChange user %q disappeared during update", sess.Username)
			writeJSONError(w, http.StatusUnauthorized, "not authenticated")
			return
		}
		log.Printf("ERROR handlePasswordChange UpdateUIUserPassword(%q): %v", sess.Username, err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Invalidate ALL sessions for this user.
	// Per security-model.md section 5.2: password change invalidates existing sessions.
	// This includes the current session — user must log in again.
	deleted := s.store.DeleteByUsername(sess.Username)
	log.Printf("AUDIT password_changed username=%q sessions_invalidated=%d", sess.Username, deleted)

	// Clear the session cookie to help the browser forget the now-invalid session.
	http.SetCookie(w, s.clearSessionCookie())
	clearCSRFCookie(w, s.secureCookie)

	// Return success response.
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(passwordChangeResponse{Changed: true})
}
