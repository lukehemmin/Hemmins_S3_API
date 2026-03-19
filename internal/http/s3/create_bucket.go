package s3

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

// createBucketConfiguration is the optional XML body for PUT Bucket (CreateBucket).
// Per AWS S3 API reference and s3-compatibility-matrix.md section 2.2:
// LocationConstraint must be absent, empty, or equal to the configured region.
type createBucketConfiguration struct {
	XMLName            xml.Name `xml:"CreateBucketConfiguration"`
	LocationConstraint string   `xml:"LocationConstraint"`
}

// handleCreateBucket implements PUT /{bucket} (CreateBucket).
// Per s3-compatibility-matrix.md section 3 and product-spec.md section 5.1.
//
// Flow: authenticate → validate name → check LocationConstraint → metadata write → 200 OK.
// On any auth, validation, or internal failure the corresponding S3 XML error is returned.
func (s *Server) handleCreateBucket(w http.ResponseWriter, r *http.Request, bucketName string) {
	_, ok := authenticate(w, r, s.verifier, s.pVerifier, s.db)
	if !ok {
		return
	}

	if err := validateBucketName(bucketName); err != nil {
		writeError(w, r, http.StatusBadRequest, "InvalidBucketName",
			"The specified bucket is not valid.")
		return
	}

	if !s.checkLocationConstraint(w, r) {
		return
	}

	if err := s.db.CreateBucket(bucketName, time.Now().UTC()); err != nil {
		if errors.Is(err, metadata.ErrBucketAlreadyExists) {
			// Single-tenant model: any existing bucket is owned by the same user.
			// Per s3-compatibility-matrix.md section 9.2.
			writeError(w, r, http.StatusConflict, "BucketAlreadyOwnedByYou",
				"Your previous request to create the named bucket succeeded and you already own it.")
			return
		}
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"An internal error occurred creating the bucket.")
		return
	}

	// AWS S3 PUT Bucket returns 200 OK with a Location header and empty body.
	w.Header().Set("Location", "/"+bucketName)
	w.WriteHeader(http.StatusOK)
}

// checkLocationConstraint reads the optional CreateBucketConfiguration body and
// verifies that the LocationConstraint (if provided) is empty or matches the
// configured region. Writes an S3 XML error and returns false on violation.
// Per s3-compatibility-matrix.md section 2.2.
func (s *Server) checkLocationConstraint(w http.ResponseWriter, r *http.Request) bool {
	// r.Body may be nil when constructed by http.NewRequest with a nil body argument
	// (common in tests). In production the HTTP server always provides a non-nil body.
	if r.Body == nil {
		return true
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "InvalidRequest",
			"Failed to read request body.")
		return false
	}

	// Empty body: no LocationConstraint provided — always allowed.
	if len(bytes.TrimSpace(body)) == 0 {
		return true
	}

	var cfg createBucketConfiguration
	if err := xml.Unmarshal(body, &cfg); err != nil {
		writeError(w, r, http.StatusBadRequest, "MalformedXML",
			"The XML you provided was not well-formed or did not validate against our published schema.")
		return false
	}

	// Verify the root element local name is "CreateBucketConfiguration".
	// Go's xml.Unmarshal does NOT enforce the struct's XMLName tag during decoding —
	// the tag is only used when marshaling output. Without this check, any well-formed
	// XML (e.g. <Foo/>) would pass and silently be treated as an empty configuration.
	//
	// Namespace policy: we require the correct local name but do NOT enforce the
	// S3 namespace ("http://s3.amazonaws.com/doc/2006-03-01/"). AWS itself accepts
	// namespace-free bodies, and some SDK versions omit the namespace declaration.
	// Enforcing the namespace would break compliant but minimal clients.
	// Per s3-compatibility-matrix.md section 2.2 and compatibility-first principle.
	if cfg.XMLName.Local != "CreateBucketConfiguration" {
		writeError(w, r, http.StatusBadRequest, "MalformedXML",
			"The XML you provided was not well-formed or did not validate against our published schema.")
		return false
	}

	// LocationConstraint must be absent or match the configured region.
	// Per s3-compatibility-matrix.md section 2.2.
	if cfg.LocationConstraint != "" && cfg.LocationConstraint != s.region {
		writeError(w, r, http.StatusBadRequest, "InvalidLocationConstraint",
			"The specified location-constraint is not valid.")
		return false
	}

	return true
}
