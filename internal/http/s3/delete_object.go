package s3

import (
	"errors"
	"log"
	"net/http"
	"os"

	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

// handleDeleteObject implements DELETE /{bucket}/{key...} (DeleteObject).
//
// Request flow:
//  1. Authenticate (SigV4 header or presigned URL).
//  2. Validate bucket name.
//  3. Confirm object key is non-empty (400 InvalidRequest if empty).
//  4. Confirm bucket exists in metadata DB (404 NoSuchBucket if not).
//  5. Delete the metadata row, obtaining the blob storage path.
//     - ErrObjectNotFound → 204 No Content (idempotent per s3-compatibility-matrix.md §3).
//     - Other DB error    → 500 InternalError.
//  6. Remove the blob file at the returned storage path.
//     - If the file is already gone: log a warning and continue.
//       The metadata row has already been removed; the system is clean.
//     - Any other removal error: log a warning and continue.
//       The orphan blob will be reclaimed by startup recovery.
//       Per operations-runbook.md section 4.1.
//  7. 204 No Content — no body.
//
// Deletion order — metadata first, blob second.
// Per operations-runbook.md section 4.1:
//   - orphan blob (metadata gone, blob present) → quarantine candidate, recoverable.
//   - corrupt row (metadata present, blob gone)  → worse state, triggers InternalError on GET/HEAD.
//
// Corrupt object policy:
//
//	is_corrupt=1 rows are cleaned up by this handler. DeleteObject must not be
//	blocked by the same corruption that prevents Get/Head from serving the object.
//	Per operations-runbook.md section 5.1.
//
// InternalError policy: storage/DB failures return a generic client message only.
// Full error details go to the server log. Raw filesystem paths are never exposed
// in any response body or header. Per security-model.md section 4.3.
//
// Per s3-compatibility-matrix.md section 3 and product-spec.md section 5.2.
func (s *Server) handleDeleteObject(w http.ResponseWriter, r *http.Request, bucketName, objectKey string) {
	// Step 1: authenticate.
	if _, ok := authenticate(w, r, s.verifier, s.pVerifier, s.db); !ok {
		return
	}

	// Step 2: validate bucket name.
	if err := validateBucketName(bucketName); err != nil {
		writeError(w, r, http.StatusBadRequest, "InvalidBucketName", err.Error())
		return
	}

	// Step 3: object key must be non-empty.
	if objectKey == "" {
		writeError(w, r, http.StatusBadRequest, "InvalidRequest",
			"Object key must not be empty.")
		return
	}

	// Step 4: bucket must exist.
	exists, err := s.db.BucketExists(bucketName)
	if err != nil {
		log.Printf("ERROR delete_object BucketExists(%q): %v", bucketName, err)
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"We encountered an internal error. Please try again.")
		return
	}
	if !exists {
		writeError(w, r, http.StatusNotFound, "NoSuchBucket",
			"The specified bucket does not exist.")
		return
	}

	// Step 5: delete metadata row.
	// is_corrupt is intentionally ignored inside DeleteObject so that callers
	// can always clean up objects, even when Get/Head would fail for the same key.
	storagePath, err := s.db.DeleteObject(bucketName, objectKey)
	if err != nil {
		if errors.Is(err, metadata.ErrObjectNotFound) {
			// Idempotent: deleting a non-existent key is a no-op success.
			// Per s3-compatibility-matrix.md section 3: "없는 키 삭제는 멱등 처리".
			// No blob to remove; return 204 immediately.
			w.WriteHeader(http.StatusNoContent)
			return
		}
		log.Printf("ERROR delete_object DeleteObject(%q, %q): %v", bucketName, objectKey, err)
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"We encountered an internal error. Please try again.")
		return
	}

	// Step 6: remove blob file.
	// Metadata row is already deleted; any blob removal outcome still results in 204.
	// Never expose storagePath (raw filesystem path) in any response or log message
	// that reaches the client. Per security-model.md section 4.3.
	if removeErr := os.Remove(storagePath); removeErr != nil {
		if os.IsNotExist(removeErr) {
			// Blob already gone (e.g. startup recovery removed it, or prior failed delete).
			// Metadata row is cleaned up; system is consistent.
			log.Printf("WARN delete_object blob already absent bucket=%q key=%q", bucketName, objectKey)
		} else {
			// Unexpected error removing blob. Metadata row is already gone, so the
			// blob becomes an orphan recoverable by startup recovery.
			// Per operations-runbook.md section 4.1 quarantine policy.
			log.Printf("ERROR delete_object remove blob bucket=%q key=%q: %v", bucketName, objectKey, removeErr)
		}
		// Continue: return 204. Raw removeErr is NOT forwarded to the client.
	}

	// Step 7: 204 No Content — AWS S3 DeleteObject success response has no body.
	// Per s3-compatibility-matrix.md section 3.
	w.WriteHeader(http.StatusNoContent)
}
