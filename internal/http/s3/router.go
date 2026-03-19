// Package s3 implements the S3-compatible HTTP API layer.
// Per system-architecture.md section 10: S3 routing, XML responses, and header
// processing are isolated in internal/http/s3/.
package s3

import (
	"net/http"
	"strings"

	"github.com/lukehemmin/hemmins-s3-api/internal/auth"
	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

// Server is the S3 API HTTP server.
// Construct with NewServer. Optionally call SetReady before calling Handler.
// Call SetStoragePaths before serving PUT Object requests.
type Server struct {
	db         *metadata.DB
	region     string // configured S3 region; used for LocationConstraint validation
	verifier   *auth.Verifier
	pVerifier  *auth.PresignVerifier
	ready      func() bool // optional; if nil every request is treated as ready
	tempRoot   string      // directory for atomic-write temp files
	objectRoot string      // root directory for final object blobs
}

// NewServer constructs a Server backed by db, using region and masterKey for
// SigV4 authentication.
func NewServer(db *metadata.DB, region, masterKey string) *Server {
	sp := makeSecretProvider(db, masterKey)
	return &Server{
		db:     db,
		region: region,
		verifier: &auth.Verifier{
			Region:    region,
			Service:   "s3",
			GetSecret: sp,
		},
		pVerifier: &auth.PresignVerifier{
			Region:    region,
			Service:   "s3",
			GetSecret: sp,
		},
	}
}

// SetStoragePaths configures the storage directories used by the PutObject handler.
// tempRoot is the directory for temporary atomic-write files;
// objectRoot is the root under which final object blobs are stored.
// Per system-architecture.md section 5.1.
func (s *Server) SetStoragePaths(tempRoot, objectRoot string) {
	s.tempRoot = tempRoot
	s.objectRoot = objectRoot
}

// SetReady registers a readiness probe function.
// When fn returns false, all S3 requests receive a 503 ServiceUnavailable XML error.
// Per product-spec.md section 8.4: server must not serve S3 API in setup-required state.
func (s *Server) SetReady(fn func() bool) {
	s.ready = fn
}

// Handler returns the http.Handler that serves all S3 API requests.
// Route map (MVP — Phase 2, six vertical slices):
//
//	GET /                         → ListBuckets (GET Service)
//	PUT /{bucket}                 → CreateBucket
//	HEAD /{bucket}                → HeadBucket
//	DELETE /{bucket}              → DeleteBucket
//	GET /{bucket}?list-type=2     → ListObjectsV2
//	PUT /{bucket}/{key...}        → PutObject
//	anything else                 → 501 NotImplemented
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)

	if s.ready == nil {
		return mux
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.ready() {
			writeError(w, r, http.StatusServiceUnavailable,
				"ServiceUnavailable",
				"Server is not ready: bootstrap required before serving S3 API requests.")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// handleRoot dispatches all S3 requests based on (method, path-depth).
//
//   - path == "/"                  → service-level operations
//   - path == "/{bucket}"          → bucket-level operations (no slash after name)
//   - path == "/{bucket}/{key...}" → object-level operations (not yet implemented)
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Service level: path is exactly "/".
	if path == "/" {
		if r.Method == http.MethodGet {
			s.handleListBuckets(w, r)
			return
		}
		writeError(w, r, http.StatusNotImplemented, "NotImplemented",
			"This S3 API endpoint is not yet implemented.")
		return
	}

	// Strip the leading "/" and check whether this is a bucket-level or object-level path.
	// Bucket-level: /{bucket} — no additional slash after the bucket name.
	// Object-level: /{bucket}/{key...} — contains a slash after the bucket name.
	trimmed := strings.TrimPrefix(path, "/")
	if !strings.Contains(trimmed, "/") {
		// Bucket-level request.
		switch r.Method {
		case http.MethodGet:
			if r.URL.Query().Get("list-type") == "2" {
				s.handleListObjectsV2(w, r, trimmed)
			} else {
				writeError(w, r, http.StatusNotImplemented, "NotImplemented",
					"This S3 API endpoint is not yet implemented.")
			}
		case http.MethodPut:
			s.handleCreateBucket(w, r, trimmed)
		case http.MethodHead:
			s.handleHeadBucket(w, r, trimmed)
		case http.MethodDelete:
			s.handleDeleteBucket(w, r, trimmed)
		default:
			writeError(w, r, http.StatusNotImplemented, "NotImplemented",
				"This S3 API endpoint is not yet implemented.")
		}
		return
	}

	// Object-level request: /{bucket}/{key...}
	// bucketName is everything before the first "/"; objectKey is the remainder
	// (starting after the slash), which may itself contain slashes.
	idx := strings.Index(trimmed, "/")
	bucketName := trimmed[:idx]
	objectKey := trimmed[idx+1:]

	switch r.Method {
	case http.MethodPut:
		s.handlePutObject(w, r, bucketName, objectKey)
	default:
		writeError(w, r, http.StatusNotImplemented, "NotImplemented",
			"This S3 API endpoint is not yet implemented.")
	}
}
