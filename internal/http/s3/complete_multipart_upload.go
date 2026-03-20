package s3

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
	"github.com/lukehemmin/hemmins-s3-api/internal/storage"
)

// completeMultipartUploadRequest is the XML request body for CompleteMultipartUpload.
// Per AWS S3 API reference.
type completeMultipartUploadRequest struct {
	XMLName xml.Name       `xml:"CompleteMultipartUpload"`
	Parts   []completePart `xml:"Part"`
}

// completePart is a single <Part> entry in the CompleteMultipartUpload request body.
type completePart struct {
	PartNumber int    `xml:"PartNumber"`
	ETag       string `xml:"ETag"`
}

// completeMultipartUploadResult is the XML response body for CompleteMultipartUpload.
// Per AWS S3 API reference and s3-compatibility-matrix.md section 9.1.
type completeMultipartUploadResult struct {
	XMLName  xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CompleteMultipartUploadResult"`
	Location string   `xml:"Location"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	ETag     string   `xml:"ETag"`
}

// minPartSize is the S3 minimum size for any non-last multipart part (5 MiB).
// Per s3-compatibility-matrix.md section 8.
const minPartSize = 5 * 1024 * 1024

// handleCompleteMultipartUpload implements POST /{bucket}/{key...}?uploadId=X.
//
// Request flow:
//  1. Authenticate (SigV4 header or presigned URL).
//  2. Validate bucket name per naming rules (400 InvalidBucketName).
//  3. Confirm object key is non-empty (400 InvalidRequest).
//  4. Parse uploadId query param (required; 400 InvalidRequest if absent).
//  5. Parse XML request body: list of (PartNumber, ETag) pairs.
//  6. Validate submitted parts: non-empty, ascending part numbers.
//  7. Retrieve upload session; absent → 404 NoSuchUpload.
//  8. Verify bucket/key match upload session (mismatch → 404 NoSuchUpload).
//  9. Verify session not expired (expired → 404 NoSuchUpload).
// 10. List all parts from DB ordered by part_number ASC.
// 11. Validate each submitted part: ETag matches DB → 400 InvalidPart on mismatch.
// 12. Enforce 5 MiB minimum on all parts except the last → 400 EntityTooSmall.
// 13. Compute multipart ETag (MD5 of concatenated raw part MD5 bytes + "-N").
// 14. Merge staging files into final object via AtomicWrite (sequential reader, one fd at a time).
// 15. Parse session metadata_json: extract content-type, re-marshal user metadata.
// 16. Atomically commit final object row and delete multipart session via FinalizeMultipartUpload.
// 17. Best-effort cleanup of ALL session staging files (including unsubmitted parts) and upload dir.
// 18. 200 OK with XML CompleteMultipartUploadResult body.
//
// Durability contract: final blob is written and fsync'd before metadata commit;
// success response is sent only after DB commit. Per operations-runbook.md section 3.2.
//
// InternalError policy: storage/DB error details are logged but never sent to the
// client. Raw filesystem paths are never included in any response body or header.
// Per security-model.md section 4.3.
func (s *Server) handleCompleteMultipartUpload(w http.ResponseWriter, r *http.Request, bucketName, objectKey string) {
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

	// Step 5: parse XML request body.
	// Guard against nil body (e.g. in tests that forget to set it).
	if r.Body == nil {
		writeError(w, r, http.StatusBadRequest, "MalformedXML",
			"The XML you provided was not well-formed or did not include a CompleteMultipartUpload element.")
		return
	}
	rawBody, readErr := io.ReadAll(r.Body)
	if readErr != nil {
		log.Printf("ERROR complete_multipart_upload reading body: %v", readErr)
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"We encountered an internal error. Please try again.")
		return
	}
	var req completeMultipartUploadRequest
	if xmlErr := xml.Unmarshal(rawBody, &req); xmlErr != nil {
		writeError(w, r, http.StatusBadRequest, "MalformedXML",
			"The XML you provided was not well-formed or did not include a CompleteMultipartUpload element.")
		return
	}

	// Step 6: submitted parts list must be non-empty and in ascending order.
	if len(req.Parts) == 0 {
		writeError(w, r, http.StatusBadRequest, "InvalidRequest",
			"You must specify at least one part.")
		return
	}
	for i := 1; i < len(req.Parts); i++ {
		if req.Parts[i].PartNumber <= req.Parts[i-1].PartNumber {
			writeError(w, r, http.StatusBadRequest, "InvalidPartOrder",
				"The list of parts was not in ascending order. Parts must be ordered by part number.")
			return
		}
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
		log.Printf("ERROR complete_multipart_upload GetMultipartUpload(%q): %v", uploadID, err)
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"We encountered an internal error. Please try again.")
		return
	}

	// Step 8: bucket and key in the request URL must match the session.
	if session.BucketName != bucketName || session.ObjectKey != objectKey {
		writeError(w, r, http.StatusNotFound, "NoSuchUpload",
			"The specified upload does not exist. The upload ID may be invalid, "+
				"or the upload may have been aborted or completed.")
		return
	}

	// Step 9: session must not be expired.
	if time.Now().UTC().After(session.ExpiresAt) {
		writeError(w, r, http.StatusNotFound, "NoSuchUpload",
			"The specified upload has expired.")
		return
	}

	// Step 10: list all DB parts, ordered by part_number ASC.
	dbParts, err := s.db.ListMultipartParts(uploadID)
	if err != nil {
		log.Printf("ERROR complete_multipart_upload ListMultipartParts(%q): %v", uploadID, err)
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"We encountered an internal error. Please try again.")
		return
	}

	// Build lookup map: partNumber → PartRow for O(1) access.
	dbPartMap := make(map[int]metadata.PartRow, len(dbParts))
	for _, p := range dbParts {
		dbPartMap[p.PartNumber] = p
	}

	// Step 11: validate submitted parts against the DB.
	// Each submitted (PartNumber, ETag) must match an existing DB row.
	// Submitted ETags may be quoted ("hex") or unquoted (hex); strip quotes for comparison.
	// Per s3-compatibility-matrix.md section 8.
	mergeOrder := make([]metadata.PartRow, 0, len(req.Parts))
	for _, sp := range req.Parts {
		dbPart, ok := dbPartMap[sp.PartNumber]
		if !ok {
			writeError(w, r, http.StatusBadRequest, "InvalidPart",
				fmt.Sprintf("One or more of the specified parts could not be found or the "+
					"specified entity tag does not match the part's entity tag. Part number: %d.", sp.PartNumber))
			return
		}
		submittedETag := strings.Trim(sp.ETag, `"`)
		if submittedETag != dbPart.ETag {
			writeError(w, r, http.StatusBadRequest, "InvalidPart",
				fmt.Sprintf("One or more of the specified parts could not be found or the "+
					"specified entity tag does not match the part's entity tag. Part number: %d.", sp.PartNumber))
			return
		}
		mergeOrder = append(mergeOrder, dbPart)
	}

	// Step 12: enforce 5 MiB minimum on all parts except the last.
	// The last part has no minimum size. Per s3-compatibility-matrix.md section 8.
	for i, p := range mergeOrder {
		if i < len(mergeOrder)-1 && p.Size < minPartSize {
			writeError(w, r, http.StatusBadRequest, "EntityTooSmall",
				fmt.Sprintf("Your proposed upload is smaller than the minimum allowed object size. "+
					"Each part (except the last) must be at least 5 MiB. Part number: %d.", p.PartNumber))
			return
		}
	}

	// Step 13: compute multipart ETag from DB part ETags.
	// AWS multipart ETag = hex(MD5(concat(raw_md5_bytes_of_each_part))) + "-" + part_count.
	// This depends only on the part ETags (hex strings from DB), not on the file data.
	// Per s3-compatibility-matrix.md section 6.2.
	multipartETag := computeMultipartETag(mergeOrder)

	// Step 14: merge staging files into the final object blob using AtomicWrite.
	// Parts are read sequentially (one fd open at a time) to support sessions with
	// many parts without exhausting the process file-descriptor limit.
	// AtomicWrite handles: temp-file creation, streaming copy, fsync, rename, dir-fsync.
	// Per operations-runbook.md section 3.2 and system-architecture.md section 5.3.
	objectID := uuid.NewString()
	destPath := storage.StoragePath(s.objectRoot, objectID)

	partPaths := make([]string, len(mergeOrder))
	for i, p := range mergeOrder {
		partPaths[i] = p.StagingPath
	}

	sr := newSequentialFileReader(partPaths)
	defer sr.Close()

	writeResult, writeErr := storage.AtomicWrite(r.Context(), s.tempRoot, destPath, sr)
	if writeErr != nil {
		log.Printf("ERROR complete_multipart_upload AtomicWrite(%q): %v", destPath, writeErr)
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"We encountered an internal error. Please try again.")
		return
	}

	// Step 15: parse session metadata_json to extract content-type and user metadata.
	// content-type is stored under key "content-type" in the session metadata_json alongside
	// x-amz-meta-* keys. Extract it as a separate field for the objects table, and
	// re-marshal the remaining user metadata as the objects.metadata_json.
	// Per create_multipart_upload.go convention.
	contentType, metaJSON := parseSessionMetadata(session.MetadataJSON)

	// Step 16: atomically commit final object row and delete multipart session.
	// Blob is already durably written and renamed to destPath at this point.
	// FinalizeMultipartUpload runs both the object upsert and the session delete in
	// a single transaction; if either fails the tx is rolled back and we return 500.
	// Per system-architecture.md section 5.1 and operations-runbook.md section 3.2.
	now := time.Now().UTC()
	finalizeInput := metadata.FinalizeMultipartUploadInput{
		BucketName: bucketName,
		ObjectKey:  objectKey,
		ObjInput: metadata.PutObjectInput{
			Size:         writeResult.Size,
			ETag:         multipartETag,
			ContentType:  contentType,
			StoragePath:  destPath,
			LastModified: now,
			MetadataJSON: metaJSON,
		},
		UploadID: uploadID,
	}
	if err := s.db.FinalizeMultipartUpload(finalizeInput); err != nil {
		if errors.Is(err, metadata.ErrUploadNotFound) {
			// Session row was not consumed (concurrent complete/abort consumed it first).
			// Never return 200; the final object TX was rolled back atomically.
			writeError(w, r, http.StatusNotFound, "NoSuchUpload",
				"The specified upload does not exist. The upload ID may be invalid, "+
					"or the upload may have been aborted or completed.")
			return
		}
		log.Printf("ERROR complete_multipart_upload FinalizeMultipartUpload(%q, %q): %v",
			bucketName, objectKey, err)
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"We encountered an internal error. Please try again.")
		return
	}

	// Step 17: best-effort cleanup of ALL session staging files and the upload directory.
	// Cleanup target is the full dbParts list, not just the submitted mergeOrder.
	// This ensures extra uploaded-but-unsubmitted parts are removed too.
	// Per operations-runbook.md section 3.2.
	allStagingPaths := make([]string, len(dbParts))
	for i, p := range dbParts {
		allStagingPaths[i] = p.StagingPath
	}
	cleanupStagingFiles(uploadID, allStagingPaths, s.multipartRoot)

	// Step 18: 200 OK with XML CompleteMultipartUploadResult body.
	// ETag in response is a quoted string per s3-compatibility-matrix.md section 6.2.
	// Location is the canonical URL of the newly committed object.
	location := "http://" + r.Host + "/" + bucketName + "/" + objectKey
	respResult := completeMultipartUploadResult{
		Location: location,
		Bucket:   bucketName,
		Key:      objectKey,
		ETag:     `"` + multipartETag + `"`,
	}
	respBody, marshalErr := xml.Marshal(&respResult)
	if marshalErr != nil {
		log.Printf("ERROR complete_multipart_upload marshal response: %v", marshalErr)
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"We encountered an internal error. Please try again.")
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(respBody)
}

// computeMultipartETag computes the AWS S3 multipart upload ETag.
// Formula: hex(MD5(concat(raw_bytes(part1_md5), raw_bytes(part2_md5), ...))) + "-N"
// where N is the number of parts. Per s3-compatibility-matrix.md section 6.2.
func computeMultipartETag(parts []metadata.PartRow) string {
	h := md5.New()
	for _, p := range parts {
		raw, decErr := hex.DecodeString(p.ETag)
		if decErr != nil {
			// Fallback: hash the string bytes directly; should not occur for well-formed ETags.
			h.Write([]byte(p.ETag))
			continue
		}
		h.Write(raw)
	}
	return hex.EncodeToString(h.Sum(nil)) + "-" + strconv.Itoa(len(parts))
}

// parseSessionMetadata extracts content-type and user metadata from the multipart session
// metadata_json. The session stores content-type under key "content-type" alongside
// x-amz-meta-* keys (per create_multipart_upload.go convention).
// Returns contentType (defaults to "application/octet-stream") and a re-marshaled
// metadata JSON string containing only the x-amz-meta-* keys (no content-type).
func parseSessionMetadata(metadataJSON string) (contentType, metaJSON string) {
	contentType = "application/octet-stream"
	metaJSON = "{}"

	if metadataJSON == "" || metadataJSON == "{}" {
		return
	}

	var m map[string]string
	if err := json.Unmarshal([]byte(metadataJSON), &m); err != nil {
		return
	}

	if ct, ok := m["content-type"]; ok && ct != "" {
		contentType = ct
		delete(m, "content-type")
	}

	if len(m) > 0 {
		if b, err := json.Marshal(m); err == nil {
			metaJSON = string(b)
		}
	}
	return
}

// sequentialFileReader reads a list of files sequentially, opening each file only
// after the previous file is fully exhausted. At most one file descriptor is open
// at any time, so the number of concurrent open fds equals one regardless of how
// many parts are in the session. This satisfies the 10,000-part contract without
// hitting OS fd limits.
// Per system-architecture.md section 5.3.
type sequentialFileReader struct {
	paths []string
	idx   int
	cur   *os.File
}

// newSequentialFileReader returns a reader that streams paths[0], paths[1], … in order.
func newSequentialFileReader(paths []string) *sequentialFileReader {
	return &sequentialFileReader{paths: paths}
}

// Read implements io.Reader. It opens the next file only when the current file
// returns io.EOF. An empty paths slice returns io.EOF immediately.
func (s *sequentialFileReader) Read(p []byte) (int, error) {
	for {
		if s.cur == nil {
			if s.idx >= len(s.paths) {
				return 0, io.EOF
			}
			f, err := os.Open(s.paths[s.idx])
			if err != nil {
				return 0, fmt.Errorf("opening part staging file %q: %w", s.paths[s.idx], err)
			}
			s.cur = f
			s.idx++
		}
		n, err := s.cur.Read(p)
		if err == io.EOF {
			s.cur.Close()
			s.cur = nil
			if n > 0 {
				// Return the final bytes from this file; caller will get io.EOF
				// on the next Read when we advance to the next file (or exhaust paths).
				return n, nil
			}
			continue // no data; advance to next file
		}
		return n, err
	}
}

// Close closes the currently-open file handle, if any.
// It is safe to call multiple times.
func (s *sequentialFileReader) Close() error {
	if s.cur != nil {
		err := s.cur.Close()
		s.cur = nil
		return err
	}
	return nil
}

// cleanupStagingFiles removes part staging files and attempts to remove the empty
// upload directory. All failures are logged as warnings; cleanup errors never fail
// the request because the object has already been committed.
// Per operations-runbook.md section 3.2 and security-model.md section 4.3:
// raw filesystem paths must never appear in response bodies or headers.
func cleanupStagingFiles(uploadID string, partPaths []string, multipartRoot string) {
	for _, p := range partPaths {
		if rmErr := os.Remove(p); rmErr != nil && !os.IsNotExist(rmErr) {
			log.Printf("WARNING complete_multipart_upload cleanup part file: %v", rmErr)
		}
	}
	// Remove the upload directory if now empty (best-effort; fails silently if non-empty).
	uploadDir := filepath.Join(multipartRoot, uploadID)
	if rmErr := os.Remove(uploadDir); rmErr != nil && !os.IsNotExist(rmErr) {
		log.Printf("WARNING complete_multipart_upload cleanup upload dir: %v", rmErr)
	}
}
