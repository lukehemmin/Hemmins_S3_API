package s3

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

// parseByteRange parses a single HTTP Range header value against a file of
// totalSize bytes. Only a single byte-range specifier is supported; a
// multi-range value (containing a comma) is rejected.
//
// Supported forms (RFC 7233):
//
//	bytes=start-end   standard closed interval (end is inclusive)
//	bytes=start-      open-ended; reads from start to EOF
//	bytes=-N          last N bytes (suffix form)
//
// Returns (rangeStart, rangeEnd, true) on success.
// rangeStart and rangeEnd are zero-based, inclusive indices.
// Returns (0, 0, false) when the range is syntactically invalid or
// unsatisfied (start >= totalSize, suffixLen == 0, etc.).
//
// Per s3-compatibility-matrix.md section 6.3 and RFC 7233 §2.1.
func parseByteRange(rangeHeader string, totalSize int64) (rangeStart, rangeEnd int64, ok bool) {
	const prefix = "bytes="
	if !strings.HasPrefix(rangeHeader, prefix) {
		return 0, 0, false
	}
	spec := rangeHeader[len(prefix):]

	// Reject multi-range (comma present).
	if strings.Contains(spec, ",") {
		return 0, 0, false
	}

	parts := strings.SplitN(spec, "-", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	startStr, endStr := parts[0], parts[1]

	if startStr == "" {
		// Suffix form: bytes=-N (last N bytes).
		if endStr == "" {
			return 0, 0, false
		}
		suffixLen, err := strconv.ParseInt(endStr, 10, 64)
		if err != nil || suffixLen <= 0 {
			return 0, 0, false
		}
		if suffixLen > totalSize {
			suffixLen = totalSize
		}
		if suffixLen == 0 {
			return 0, 0, false
		}
		return totalSize - suffixLen, totalSize - 1, true
	}

	start, err := strconv.ParseInt(startStr, 10, 64)
	if err != nil || start < 0 {
		return 0, 0, false
	}
	// Range start must be within file bounds.
	if start >= totalSize {
		return 0, 0, false
	}

	if endStr == "" {
		// Open-ended form: bytes=start-
		return start, totalSize - 1, true
	}

	end, err := strconv.ParseInt(endStr, 10, 64)
	if err != nil || end < start {
		return 0, 0, false
	}
	// Cap end at last byte index.
	if end >= totalSize {
		end = totalSize - 1
	}
	return start, end, true
}

// handleGetObject implements GET /{bucket}/{key...} (GetObject).
//
// Request flow:
//  1. Authenticate (SigV4 header or presigned URL).
//  2. Validate bucket name.
//  3. Confirm object key is non-empty (400 InvalidRequest if empty).
//  4. Confirm bucket exists in metadata DB (404 NoSuchBucket if not).
//  5. Look up object metadata row (404 NoSuchKey if not found).
//  6. is_corrupt=1 → 500 InternalError (blob may be unreadable).
//  7. Evaluate conditional request headers (RFC 7232 §6):
//     If-Match, If-None-Match, If-Modified-Since, If-Unmodified-Since.
//     → 304 Not Modified (no body) or 412 Precondition Failed if a condition fails.
//  8. Open blob file at storage_path.
//     A missing blob with a valid metadata row is a corruption state:
//     return 500 InternalError, never 404, and never expose the raw path.
//  9. Parse optional Range header.
//     - No Range header         → 200 OK + full body.
//     - Invalid / unsatisfied   → 416 + Content-Range: bytes */size.
//     - Valid single byte range → 206 Partial Content + Content-Range + partial body.
// 10. Restore x-amz-meta-* user headers from stored metadata_json.
// 11. Write status + stream body (full or partial).
//
// Accept-Ranges: bytes is present on both 200 and 206 responses.
// ETag, Last-Modified, Content-Type are present on both 200 and 206 responses.
//
// Not implemented in this turn: multi-range, Content-Disposition.
//
// InternalError policy: storage / DB failures return a generic client message only.
// Full error details go to the server log. Raw filesystem paths are never included
// in any response body. Per security-model.md section 4.3.
//
// Per system-architecture.md section 5.2 and s3-compatibility-matrix.md section 6.2–6.3.
func (s *Server) handleGetObject(w http.ResponseWriter, r *http.Request, bucketName, objectKey string) {
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
		log.Printf("ERROR get_object BucketExists(%q): %v", bucketName, err)
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"We encountered an internal error. Please try again.")
		return
	}
	if !exists {
		writeError(w, r, http.StatusNotFound, "NoSuchBucket",
			"The specified bucket does not exist.")
		return
	}

	// Step 5–6: look up object metadata; handle corruption.
	obj, err := s.db.GetObjectByKey(bucketName, objectKey)
	if err != nil {
		switch {
		case errors.Is(err, metadata.ErrObjectNotFound):
			writeError(w, r, http.StatusNotFound, "NoSuchKey",
				"The specified key does not exist.")
		case errors.Is(err, metadata.ErrCorruptObject):
			// Blob is expected to be present but is unreadable or flagged corrupt.
			// Return a generic 500; do not reveal internal state to the client.
			// Per system-architecture.md section 6.3 and security-model.md section 4.3.
			log.Printf("ERROR get_object corrupt object bucket=%q key=%q", bucketName, objectKey)
			writeError(w, r, http.StatusInternalServerError, "InternalError",
				"We encountered an internal error. Please try again.")
		default:
			log.Printf("ERROR get_object GetObjectByKey(%q, %q): %v", bucketName, objectKey, err)
			writeError(w, r, http.StatusInternalServerError, "InternalError",
				"We encountered an internal error. Please try again.")
		}
		return
	}

	// Step 7: evaluate conditional request headers (RFC 7232 §6).
	// ETag and LastModified come from the metadata row retrieved above.
	// Evaluated before opening the blob to short-circuit I/O on 304/412.
	// Per s3-compatibility-matrix.md section 5.2.
	switch checkConditionalHeaders(obj.ETag, obj.LastModified, r) {
	case conditionalNotModified:
		// 304 Not Modified — send validation headers but no message body.
		// Per RFC 7232 §4.1: "the server SHOULD NOT send a response body".
		w.Header().Set("ETag", `"`+obj.ETag+`"`)
		w.Header().Set("Last-Modified", obj.LastModified.UTC().Format(http.TimeFormat))
		w.WriteHeader(http.StatusNotModified)
		return
	case conditionalPrecondFailed:
		writeError(w, r, http.StatusPreconditionFailed, "PreconditionFailed",
			"At least one of the pre-conditions you specified did not hold.")
		return
	}

	// Step 8: open blob file.
	// A missing blob with a valid metadata row is a corruption state, not a
	// "not found" case. Return a generic 500 InternalError. Never expose the
	// raw storage_path in the response.
	// Per system-architecture.md section 6.3 and security-model.md section 4.3.
	f, err := os.Open(obj.StoragePath)
	if err != nil {
		log.Printf("ERROR get_object open blob bucket=%q key=%q: %v", bucketName, objectKey, err)
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"We encountered an internal error. Please try again.")
		return
	}
	defer f.Close()

	// Step 8: parse optional Range header.
	// Accept-Ranges: bytes must appear on both 200 and 206 responses.
	// Per s3-compatibility-matrix.md section 6.3.
	rangeHeader := r.Header.Get("Range")
	w.Header().Set("Accept-Ranges", "bytes")

	// Step 9: common headers present on both 200 and 206 responses.
	// ETag is a quoted MD5 hex string per s3-compatibility-matrix.md section 6.2.
	// Last-Modified uses the HTTP/1.1 date format (RFC 1123) per HTTP spec.
	w.Header().Set("ETag", `"`+obj.ETag+`"`)
	w.Header().Set("Last-Modified", obj.LastModified.UTC().Format(http.TimeFormat))
	w.Header().Set("Content-Type", obj.ContentType)

	// Restore x-amz-meta-* user metadata from stored metadata_json.
	// Keys in metadata_json have the "x-amz-meta-" prefix already stripped;
	// we add it back when setting the response header.
	// Per s3-compatibility-matrix.md section 5.1.
	if obj.MetadataJSON != "" && obj.MetadataJSON != "{}" {
		var userMeta map[string]string
		if jsonErr := json.Unmarshal([]byte(obj.MetadataJSON), &userMeta); jsonErr == nil {
			for k, v := range userMeta {
				w.Header().Set("X-Amz-Meta-"+k, v)
			}
		}
	}

	// Step 10: write status and stream body.
	if rangeHeader == "" {
		// No Range header → 200 OK + full body.
		w.Header().Set("Content-Length", strconv.FormatInt(obj.Size, 10))
		w.WriteHeader(http.StatusOK)
		if _, copyErr := io.Copy(w, f); copyErr != nil {
			// Headers already sent; nothing useful we can do for the client here.
			log.Printf("ERROR get_object stream bucket=%q key=%q: %v", bucketName, objectKey, copyErr)
		}
		return
	}

	// Range header present: parse single byte-range specifier.
	rangeStart, rangeEnd, ok := parseByteRange(rangeHeader, obj.Size)
	if !ok {
		// Invalid or unsatisfied range → 416 with Content-Range: bytes */size.
		// Content-Range must be set before writeError calls WriteHeader.
		// Per RFC 7233 §4.4 and s3-compatibility-matrix.md section 6.3.
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", obj.Size))
		writeError(w, r, http.StatusRequestedRangeNotSatisfiable, "InvalidRange",
			"The requested range is not satisfiable.")
		return
	}

	// Valid single byte range → 206 Partial Content.
	rangeLen := rangeEnd - rangeStart + 1
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", rangeStart, rangeEnd, obj.Size))
	w.Header().Set("Content-Length", strconv.FormatInt(rangeLen, 10))
	w.WriteHeader(http.StatusPartialContent)

	// Seek to rangeStart and stream exactly rangeLen bytes.
	if _, seekErr := f.Seek(rangeStart, io.SeekStart); seekErr != nil {
		// Status already sent; log only. Client will receive truncated body.
		log.Printf("ERROR get_object seek bucket=%q key=%q offset=%d: %v",
			bucketName, objectKey, rangeStart, seekErr)
		return
	}
	if _, copyErr := io.CopyN(w, f, rangeLen); copyErr != nil {
		log.Printf("ERROR get_object range stream bucket=%q key=%q: %v",
			bucketName, objectKey, copyErr)
	}
}
