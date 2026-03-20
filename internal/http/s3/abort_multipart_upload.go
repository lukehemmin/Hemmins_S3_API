package s3

import (
	"errors"
	"log"
	"net/http"

	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

// handleAbortMultipartUpload implements DELETE /{bucket}/{key...}?uploadId=X.
//
// Request flow:
//  1. Authenticate (SigV4 header or presigned URL).
//  2. Validate bucket name per naming rules (400 InvalidBucketName).
//  3. Confirm object key is non-empty (400 InvalidRequest).
//  4. Parse uploadId query param (required; 400 InvalidRequest if absent).
//  5. Retrieve upload session; absent → 404 NoSuchUpload.
//  6. Verify bucket/key match upload session (mismatch → 404 NoSuchUpload).
//  7. List all session parts to obtain staging file paths for cleanup.
//  8. Delete session row from DB (AbortMultipartUpload with RowsAffected check).
//     - Race: session concurrently consumed → ErrUploadNotFound → 404 NoSuchUpload.
//     - ON DELETE CASCADE removes part rows automatically.
//  9. Best-effort cleanup of all staging files and the upload directory.
// 10. 204 No Content — no body.
//
// Expiry policy: expired sessions that still exist in the DB are treated as valid
// abort targets. Per operations-runbook.md section 4.1: "Multipart 세션만 있고
// 만료됨 → AbortMultipartUpload와 동일하게 정리". Rejecting expired sessions with
// NoSuchUpload would prevent cleanup by callers who catch exceptions after expiry.
//
// Cleanup order: DB delete first, file cleanup second.
// Rationale: if the process crashes between DB delete and file cleanup, orphan
// staging files have no DB row and are identifiable by the GC scanner (safe
// orphan state). Deleting files first risks leaving a DB row pointing to missing
// files (corrupt state, harder to recover). Per operations-runbook.md section 4.1.
//
// InternalError policy: storage/DB error details are logged but never sent to the
// client. Raw filesystem paths are never included in any response body or header.
// Per security-model.md section 4.3.
func (s *Server) handleAbortMultipartUpload(w http.ResponseWriter, r *http.Request, bucketName, objectKey string) {
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

	// Step 4: uploadId is required.
	uploadID := r.URL.Query().Get("uploadId")
	if uploadID == "" {
		writeError(w, r, http.StatusBadRequest, "InvalidRequest",
			"Missing required parameter: uploadId.")
		return
	}

	// Step 5: retrieve upload session.
	// Note: we do NOT check expiry. Per operations-runbook.md section 4.1,
	// expired sessions are cleanup targets for AbortMultipartUpload. Clients
	// that call Abort after session expiry must still be able to clean up.
	session, err := s.db.GetMultipartUpload(uploadID)
	if errors.Is(err, metadata.ErrUploadNotFound) {
		writeError(w, r, http.StatusNotFound, "NoSuchUpload",
			"The specified upload does not exist. The upload ID may be invalid, "+
				"or the upload may have been aborted or completed.")
		return
	}
	if err != nil {
		log.Printf("ERROR abort_multipart_upload GetMultipartUpload(%q): %v", uploadID, err)
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"We encountered an internal error. Please try again.")
		return
	}

	// Step 6: bucket and key in the request URL must match the session.
	if session.BucketName != bucketName || session.ObjectKey != objectKey {
		writeError(w, r, http.StatusNotFound, "NoSuchUpload",
			"The specified upload does not exist. The upload ID may be invalid, "+
				"or the upload may have been aborted or completed.")
		return
	}

	// Step 7: list all session parts to obtain staging file paths before deletion.
	// Must be done before the DB delete because ON DELETE CASCADE removes part rows
	// when the session row is deleted, making staging paths unqueryable afterwards.
	parts, err := s.db.ListMultipartParts(uploadID)
	if err != nil {
		log.Printf("ERROR abort_multipart_upload ListMultipartParts(%q): %v", uploadID, err)
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"We encountered an internal error. Please try again.")
		return
	}

	// Step 8: delete session row from DB.
	// AbortMultipartUpload checks RowsAffected; returns ErrUploadNotFound if the
	// session was concurrently consumed (race with CompleteMultipartUpload or
	// another AbortMultipartUpload). CASCADE deletes all part rows atomically.
	if err := s.db.AbortMultipartUpload(uploadID); err != nil {
		if errors.Is(err, metadata.ErrUploadNotFound) {
			// Session was already consumed by a concurrent complete or abort.
			writeError(w, r, http.StatusNotFound, "NoSuchUpload",
				"The specified upload does not exist. The upload ID may be invalid, "+
					"or the upload may have been aborted or completed.")
			return
		}
		log.Printf("ERROR abort_multipart_upload AbortMultipartUpload(%q): %v", uploadID, err)
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"We encountered an internal error. Please try again.")
		return
	}

	// Step 9: best-effort cleanup of all staging files and the upload directory.
	// DB row is already gone; any remaining staging files are safe orphans.
	// cleanupStagingFiles is defined in complete_multipart_upload.go and shared
	// between Complete and Abort because both need identical file cleanup logic.
	// Per operations-runbook.md section 4.1.
	partPaths := make([]string, len(parts))
	for i, p := range parts {
		partPaths[i] = p.StagingPath
	}
	cleanupStagingFiles(uploadID, partPaths, s.multipartRoot)

	// Step 10: 204 No Content — AWS S3 AbortMultipartUpload has no response body.
	// Per s3-compatibility-matrix.md section 3.
	w.WriteHeader(http.StatusNoContent)
}
