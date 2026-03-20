package s3

import (
	"errors"
	"net/http"

	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

// handleDeleteBucket implements DELETE /{bucket} (DeleteBucket).
// Per s3-compatibility-matrix.md section 3 and product-spec.md section 5.1.
//
// Flow: authenticate → validate name → metadata delete (preconditions inside) → 204 No Content.
// Preconditions enforced by metadata.DeleteBucket:
//   - bucket must exist → ErrBucketNotFound → 404 NoSuchBucket
//   - bucket must be empty → ErrBucketNotEmpty → 409 BucketNotEmpty
func (s *Server) handleDeleteBucket(w http.ResponseWriter, r *http.Request, bucketName string) {
	_, ok := authenticate(w, r, s.verifier, s.pVerifier, s.db)
	if !ok {
		return
	}

	if err := ValidateBucketName(bucketName); err != nil {
		writeError(w, r, http.StatusBadRequest, "InvalidBucketName",
			"The specified bucket is not valid.")
		return
	}

	if err := s.db.DeleteBucket(bucketName); err != nil {
		switch {
		case errors.Is(err, metadata.ErrBucketNotFound):
			writeError(w, r, http.StatusNotFound, "NoSuchBucket",
				"The specified bucket does not exist.")
		case errors.Is(err, metadata.ErrBucketNotEmpty):
			writeError(w, r, http.StatusConflict, "BucketNotEmpty",
				"The bucket you tried to delete is not empty.")
		default:
			writeError(w, r, http.StatusInternalServerError, "InternalError",
				"An internal error occurred deleting the bucket.")
		}
		return
	}

	// AWS S3 DELETE Bucket returns 204 No Content with no body on success.
	w.WriteHeader(http.StatusNoContent)
}
