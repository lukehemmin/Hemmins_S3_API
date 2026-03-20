// Package s3 implements the S3-compatible HTTP API layer.
// Per system-architecture.md section 10: S3 routing, XML responses, and header
// processing are isolated in internal/http/s3/.
package s3

import (
	"net/http"
	"strings"
	"time"

	"github.com/lukehemmin/hemmins-s3-api/internal/auth"
	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

// Server is the S3 API HTTP server.
// Construct with NewServer. Optionally call SetReady before calling Handler.
// Call SetStoragePaths before serving PUT Object requests.
// Call SetMultipartRoot before serving UploadPart requests.
// Call SetMultipartExpiry before serving CreateMultipartUpload requests.
type Server struct {
	db              *metadata.DB
	region          string        // configured S3 region; used for LocationConstraint validation
	verifier        *auth.Verifier
	pVerifier       *auth.PresignVerifier
	ready           func() bool   // optional; if nil every request is treated as ready
	tempRoot        string        // directory for atomic-write temp files
	objectRoot      string        // root directory for final object blobs
	multipartRoot   string        // root directory for multipart staging parts
	multipartExpiry time.Duration // TTL for new multipart upload sessions; 0 → 24h default
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

// SetMultipartRoot configures the root directory used for multipart part staging files.
// Parts are written to multipartRoot/<upload_id>/part-<N>.
// multipartRoot must reside on the same filesystem as tempRoot so atomic rename works.
// Per system-architecture.md section 3 and operations-runbook.md section 3.2.
func (s *Server) SetMultipartRoot(multipartRoot string) {
	s.multipartRoot = multipartRoot
}

// SetMultipartExpiry sets the time-to-live for new multipart upload sessions.
// The value comes from gc.multipart_expiry (default 24h per config/loader.go).
// If expiry is 0 or negative the server falls back to 24h.
// Per operations-runbook.md section 4.1: expired sessions are GC candidates.
func (s *Server) SetMultipartExpiry(expiry time.Duration) {
	if expiry <= 0 {
		expiry = 24 * time.Hour
	}
	s.multipartExpiry = expiry
}

// SetReady registers a readiness probe function.
// When fn returns false, all S3 requests receive a 503 ServiceUnavailable XML error.
// Per product-spec.md section 8.4: server must not serve S3 API in setup-required state.
func (s *Server) SetReady(fn func() bool) {
	s.ready = fn
}

// Handler returns the http.Handler that serves all S3 API requests.
// Route map (MVP — Phase 2 + Phase 4):
//
//	GET /                                                          → ListBuckets (GET Service)
//	PUT /{bucket}                                                  → CreateBucket
//	HEAD /{bucket}                                                 → HeadBucket
//	DELETE /{bucket}                                               → DeleteBucket
//	GET /{bucket}?list-type=2                                      → ListObjectsV2
//	PUT /{bucket}/{key...}                                         → PutObject
//	PUT /{bucket}/{key...} + x-amz-copy-source header             → CopyObject
//	PUT /{bucket}/{key...}?partNumber=N&uploadId=X                 → UploadPart
//	GET /{bucket}/{key...}?uploadId=X                             → ListParts
//	GET /{bucket}/{key...}                                         → GetObject
//	HEAD /{bucket}/{key...}                                        → HeadObject
//	DELETE /{bucket}/{key...}?uploadId=X                          → AbortMultipartUpload
//	DELETE /{bucket}/{key...}                                      → DeleteObject
//	POST /{bucket}/{key...}?uploads                                → CreateMultipartUpload
//	POST /{bucket}/{key...}?uploadId=X                             → CompleteMultipartUpload
//	anything else                                                  → 501 NotImplemented
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
	case http.MethodGet:
		// Routing priority for object-level GET:
		//   1. ?uploadId query param present → ListParts
		//   2. otherwise → GetObject
		// Per s3-compatibility-matrix.md §8 and §3.
		if r.URL.Query().Has("uploadId") {
			s.handleListParts(w, r, bucketName, objectKey)
		} else {
			s.handleGetObject(w, r, bucketName, objectKey)
		}
	case http.MethodHead:
		s.handleHeadObject(w, r, bucketName, objectKey)
	case http.MethodPut:
		// Routing priority for object-level PUT:
		//   1. x-amz-copy-source header present → CopyObject
		//   2. ?partNumber or ?uploadId query param present → UploadPart
		//      (either param alone signals UploadPart intent; the handler validates both)
		//   3. otherwise → PutObject
		// Per s3-compatibility-matrix.md §5.3 and §8.
		if r.Header.Get("X-Amz-Copy-Source") != "" {
			s.handleCopyObject(w, r, bucketName, objectKey)
		} else if r.URL.Query().Has("partNumber") || r.URL.Query().Has("uploadId") {
			s.handleUploadPart(w, r, bucketName, objectKey)
		} else {
			s.handlePutObject(w, r, bucketName, objectKey)
		}
	case http.MethodDelete:
		// Routing priority for object-level DELETE:
		//   1. ?uploadId query param present → AbortMultipartUpload
		//   2. otherwise → DeleteObject
		// Per s3-compatibility-matrix.md §8 and §3.
		if r.URL.Query().Has("uploadId") {
			s.handleAbortMultipartUpload(w, r, bucketName, objectKey)
		} else {
			s.handleDeleteObject(w, r, bucketName, objectKey)
		}
	case http.MethodPost:
		// Routing priority for object-level POST:
		//   1. ?uploads query param present → CreateMultipartUpload
		//   2. ?uploadId query param present → CompleteMultipartUpload
		//   3. otherwise → NotImplemented
		// Per s3-compatibility-matrix.md §5.3 and §8, implementation-roadmap.md Phase 4.
		if r.URL.Query().Has("uploads") {
			s.handleCreateMultipartUpload(w, r, bucketName, objectKey)
		} else if r.URL.Query().Has("uploadId") {
			s.handleCompleteMultipartUpload(w, r, bucketName, objectKey)
		} else {
			writeError(w, r, http.StatusNotImplemented, "NotImplemented",
				"This S3 API endpoint is not yet implemented.")
		}
	default:
		writeError(w, r, http.StatusNotImplemented, "NotImplemented",
			"This S3 API endpoint is not yet implemented.")
	}
}
