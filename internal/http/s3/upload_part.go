package s3

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
	"github.com/lukehemmin/hemmins-s3-api/internal/storage"
)

// multipartUniqueStagingPath returns a request-unique staging file path for a multipart part.
// Each UploadPart request must call this with a fresh token so concurrent requests
// for the same (upload_id, part_number) never share a path.
//
// Format: multipartRoot/<upload_id>/part-<N05d>.<token>.part
//
// Zero-padding to 5 digits ensures correct lexicographic sort order for up to
// part 10000 (which is the S3 maximum per s3-compatibility-matrix.md section 8).
// The token (typically a UUID) makes each request's path unique.
func multipartUniqueStagingPath(multipartRoot, uploadID string, partNumber int, token string) string {
	return filepath.Join(multipartRoot, uploadID,
		fmt.Sprintf("part-%05d.%s.part", partNumber, token))
}

// handleUploadPart implements PUT /{bucket}/{key...}?partNumber=N&uploadId=X.
//
// Request flow:
//  1. Authenticate (SigV4 header or presigned URL).
//  2. Validate bucket name per naming rules (400 InvalidBucketName).
//  3. Confirm object key is non-empty (400 InvalidRequest).
//  4. Parse uploadId query param (required; 400 InvalidRequest if absent).
//  5. Parse partNumber query param (required, integer, 1..10000).
//  6. Parse Content-MD5 header if present (malformed → 400 InvalidDigest; no body read yet).
//  7. Retrieve upload session; absent → 404 NoSuchUpload.
//  8. Verify bucket/key match upload session (mismatch → 404 NoSuchUpload).
//  9. Verify session not expired (expired → 404 NoSuchUpload).
// 10. Generate request-unique staging path; stream body directly to it via AtomicWrite.
// 11. Compute MD5 ETag; verify Content-MD5 if provided (mismatch → remove new file, 400 BadDigest).
// 12. ReplaceMultipartPart: transaction reads old staging path, inserts new row (DB error → remove new file, 500).
// 13. Best-effort delete old staging file (if one existed); 200 OK with quoted ETag.
//
// Integrity guarantee: each UploadPart request writes to a distinct path (UUID token).
// Concurrent requests for the same (upload_id, part_number) cannot overwrite each other's
// in-flight file. The DB row is updated only after the new file exists on disk and its
// MD5 is verified. A failed re-upload leaves the previous row and file fully intact.
//
// Minimum-part-size (5 MiB) is NOT enforced here because whether a part is
// "last" is only known at CompleteMultipartUpload time.
// Per s3-compatibility-matrix.md section 8.
//
// InternalError policy: storage/DB error details are logged but never sent to the
// client. Raw filesystem paths are never included in any response body or header.
// Per security-model.md section 4.3.
func (s *Server) handleUploadPart(w http.ResponseWriter, r *http.Request, bucketName, objectKey string) {
	// Step 1: authenticate.
	if _, ok := authenticate(w, r, s.verifier, s.pVerifier, s.db); !ok {
		return
	}

	// Step 2: validate bucket name.
	if err := ValidateBucketName(bucketName); err != nil {
		writeError(w, r, http.StatusBadRequest, "InvalidBucketName", err.Error())
		return
	}

	// Step 3: object key must be non-empty.
	if objectKey == "" {
		writeError(w, r, http.StatusBadRequest, "InvalidRequest",
			"Object key must not be empty.")
		return
	}

	q := r.URL.Query()

	// Step 4: uploadId is required.
	uploadID := q.Get("uploadId")
	if uploadID == "" {
		writeError(w, r, http.StatusBadRequest, "InvalidRequest",
			"Missing required parameter: uploadId.")
		return
	}

	// Step 5: partNumber is required, must be a valid integer in [1, 10000].
	partNumberStr := q.Get("partNumber")
	if partNumberStr == "" {
		writeError(w, r, http.StatusBadRequest, "InvalidRequest",
			"Missing required parameter: partNumber.")
		return
	}
	partNumber, convErr := strconv.Atoi(partNumberStr)
	if convErr != nil {
		writeError(w, r, http.StatusBadRequest, "InvalidArgument",
			"Part number must be an integer.")
		return
	}
	if partNumber < 1 || partNumber > 10000 {
		writeError(w, r, http.StatusBadRequest, "InvalidArgument",
			"Part number must be an integer between 1 and 10000, inclusive.")
		return
	}

	// Step 6: validate Content-MD5 header format before any body write.
	// Content-MD5 is a Base64-encoded 16-byte MD5 digest per RFC 1864.
	// Malformed Base64 or wrong decoded length → 400 InvalidDigest.
	// Per s3-compatibility-matrix.md section 5.1.
	var declaredMD5 []byte
	if hdr := r.Header.Get("Content-MD5"); hdr != "" {
		decoded, decErr := base64.StdEncoding.DecodeString(hdr)
		if decErr != nil || len(decoded) != 16 {
			writeError(w, r, http.StatusBadRequest, "InvalidDigest",
				"The Content-MD5 you specified is not valid.")
			return
		}
		declaredMD5 = decoded
	}

	// Step 7: retrieve upload session.
	session, err := s.db.GetMultipartUpload(uploadID)
	if errors.Is(err, metadata.ErrUploadNotFound) {
		writeError(w, r, http.StatusNotFound, "NoSuchUpload",
			"The specified upload does not exist. The upload ID may be invalid, "+
				"or the upload may have been aborted or completed.")
		return
	}
	if err != nil {
		log.Printf("ERROR upload_part GetMultipartUpload(%q): %v", uploadID, err)
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"We encountered an internal error. Please try again.")
		return
	}

	// Step 8: bucket and key in the request URL must match the session.
	// The upload_id is scoped to a specific bucket+key at initiation time;
	// using it against a different bucket/key is treated as not-found.
	if session.BucketName != bucketName || session.ObjectKey != objectKey {
		writeError(w, r, http.StatusNotFound, "NoSuchUpload",
			"The specified upload does not exist. The upload ID may be invalid, "+
				"or the upload may have been aborted or completed.")
		return
	}

	// Step 9: session must not be expired.
	// Expired sessions are cleaned up by the GC; if one is still in the DB it
	// is treated the same as not-found (NoSuchUpload).
	// Per operations-runbook.md section 4.1.
	if time.Now().UTC().After(session.ExpiresAt) {
		writeError(w, r, http.StatusNotFound, "NoSuchUpload",
			"The specified upload has expired.")
		return
	}

	// Step 10: generate a request-unique staging path and stream body via AtomicWrite.
	//
	// Each UploadPart attempt uses a fresh UUID token so concurrent requests for the
	// same (upload_id, part_number) write to different paths and cannot clobber each
	// other's in-flight file.
	//
	// AtomicWrite streams temp→newStagingPath atomically. newStagingPath IS the final
	// staging location — no second rename is needed. This eliminates the DB/file
	// inconsistency window that exists when the DB is written before the rename.
	//
	// Precondition: tempRoot and multipartRoot must reside on the same filesystem
	// so that rename(2) from tempRoot into multipartRoot/<upload_id>/ is atomic.
	// Enforced by config.InitializePaths.
	// Per system-architecture.md section 6.1.
	token := uuid.NewString()
	newStagingPath := multipartUniqueStagingPath(s.multipartRoot, uploadID, partNumber, token)
	bodyReader := r.Body
	if bodyReader == nil {
		bodyReader = http.NoBody
	}
	h := md5.New()
	body := io.TeeReader(bodyReader, h)

	result, writeErr := storage.AtomicWrite(r.Context(), s.tempRoot, newStagingPath, body)
	if writeErr != nil {
		log.Printf("ERROR upload_part AtomicWrite(%q): %v", newStagingPath, writeErr)
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"We encountered an internal error. Please try again.")
		return
	}

	// Step 11: ETag is the raw MD5 hex of the full part bytes.
	actualMD5 := h.Sum(nil) // 16-byte raw digest
	etag := hex.EncodeToString(actualMD5)

	// Step 11b: verify Content-MD5 if provided.
	// On mismatch: remove the new unique file; any previously committed part is untouched.
	// Per s3-compatibility-matrix.md section 5.1.
	if declaredMD5 != nil && !bytes.Equal(actualMD5, declaredMD5) {
		if rmErr := os.Remove(newStagingPath); rmErr != nil && !os.IsNotExist(rmErr) {
			log.Printf("WARNING upload_part cleanup %q after BadDigest: %v", newStagingPath, rmErr)
		}
		writeError(w, r, http.StatusBadRequest, "BadDigest",
			"The Content-MD5 you specified did not match what we received.")
		return
	}

	// Step 12: atomically replace the DB row, retrieving the previous staging path.
	// ReplaceMultipartPart runs a transaction: read old path → insert new row → commit.
	// After commit, newStagingPath is the canonical file and oldPath (if any) is obsolete.
	// On DB error: remove the new unique file and return 500.
	input := metadata.UpsertPartInput{
		UploadID:    uploadID,
		PartNumber:  partNumber,
		ETag:        etag,
		Size:        result.Size,
		StagingPath: newStagingPath,
		CreatedAt:   time.Now().UTC(),
	}
	oldPath, hadOld, dbErr := s.db.ReplaceMultipartPart(input)
	if dbErr != nil {
		if rmErr := os.Remove(newStagingPath); rmErr != nil && !os.IsNotExist(rmErr) {
			log.Printf("WARNING upload_part cleanup %q after DB error: %v", newStagingPath, rmErr)
		}
		log.Printf("ERROR upload_part ReplaceMultipartPart(%q, %d): %v", uploadID, partNumber, dbErr)
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"We encountered an internal error. Please try again.")
		return
	}

	// Step 13: best-effort delete the superseded staging file.
	// The DB row now points to newStagingPath; oldPath is an orphan.
	// Deletion failure is non-fatal: the GC can collect orphan part files.
	// Guard: skip deletion if oldPath == newStagingPath (should not happen, but safe).
	// Per operations-runbook.md section 3.2.
	if hadOld && oldPath != newStagingPath {
		if rmErr := os.Remove(oldPath); rmErr != nil && !os.IsNotExist(rmErr) {
			log.Printf("WARNING upload_part stale part cleanup %q: %v", oldPath, rmErr)
		}
	}

	// Step 14: 200 OK with quoted ETag header per S3 spec.
	// Per s3-compatibility-matrix.md section 6.2: ETag is a quoted string.
	w.Header().Set("ETag", `"`+etag+`"`)
	w.WriteHeader(http.StatusOK)
}
