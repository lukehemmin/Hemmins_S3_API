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
// and extracts storage paths needed for object upload.
// Must be called before Handler() if settings API or object upload is needed.
// Per product-spec.md section 7.4 and configuration-model.md section 10.1.
func (s *Server) SetConfig(cfg *config.Config) {
	s.settingsView = NewSettingsView(cfg)
	s.objectRoot = cfg.Paths.ObjectRoot
	s.tempRoot = cfg.Paths.TempRoot
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
//	GET  /ui/api/settings        → settings and path status
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
//
// Per product-spec.md section 7.3 and security-model.md section 6.
func (s *Server) handleBucketByName(w http.ResponseWriter, r *http.Request) {
	// Extract bucket name and sub-path from: /ui/api/buckets/{name}[/objects[/download|upload]]
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
