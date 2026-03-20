package s3

import (
	"net/http"
)

// handleHeadBucket implements HEAD /{bucket} (HeadBucket).
// Per s3-compatibility-matrix.md section 3 and product-spec.md section 5.1.
//
// Flow: authenticate → validate name → metadata existence check → 200 OK (no body).
// On any failure the corresponding S3 XML error is written; the net/http server
// automatically strips the body for HEAD responses per RFC 7231.
func (s *Server) handleHeadBucket(w http.ResponseWriter, r *http.Request, bucketName string) {
	_, ok := authenticate(w, r, s.verifier, s.pVerifier, s.db)
	if !ok {
		return
	}

	if err := ValidateBucketName(bucketName); err != nil {
		writeError(w, r, http.StatusBadRequest, "InvalidBucketName",
			"The specified bucket is not valid.")
		return
	}

	exists, err := s.db.BucketExists(bucketName)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"An internal error occurred checking the bucket.")
		return
	}
	if !exists {
		// Per s3-compatibility-matrix.md section 9.2: NoSuchBucket.
		writeError(w, r, http.StatusNotFound, "NoSuchBucket",
			"The specified bucket does not exist.")
		return
	}

	// Success: 200 OK with no body.
	// HEAD responses MUST NOT include a message body (RFC 7231 §4.3.2).
	w.WriteHeader(http.StatusOK)
}
