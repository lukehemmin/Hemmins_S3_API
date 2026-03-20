package s3

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

// handleHeadObject implements HEAD /{bucket}/{key...} (HeadObject).
//
// HeadObject returns the same metadata headers as GetObject but with no response body.
// Per HTTP/1.1 RFC 9110 §9.3.2: a HEAD response MUST NOT include a message body;
// the headers MUST be identical to what a GET would return.
//
// Request flow:
//  1. Authenticate (SigV4 header or presigned URL).
//  2. Validate bucket name.
//  3. Confirm object key is non-empty (400 InvalidRequest if empty).
//  4. Confirm bucket exists in metadata DB (404 NoSuchBucket if not).
//  5. Look up object metadata row (404 NoSuchKey if not found).
//  6. is_corrupt=1 → 500 InternalError (do not reveal internal state).
//  7. Evaluate conditional request headers (RFC 7232 §6):
//     If-Match, If-None-Match, If-Modified-Since, If-Unmodified-Since.
//     → 304 Not Modified (no body) or 412 Precondition Failed if a condition fails.
//  8. Stat blob file at storage_path.
//     A missing blob with a valid metadata row is a corruption state:
//     return 500 InternalError, never 404, and never expose the raw path.
//  9. Write response headers:
//     Content-Type, Content-Length, ETag (quoted), Last-Modified (HTTP format).
// 10. Restore x-amz-meta-* user headers from stored metadata_json.
// 11. 200 OK — no body written.
//
// Not implemented in this turn: Range.
//
// InternalError policy: storage/DB failures return a generic client message only.
// Full error details go to the server log. Raw filesystem paths are never included
// in any response body or header. Per security-model.md section 4.3.
//
// Per system-architecture.md section 5.2 and s3-compatibility-matrix.md section 6.2.
func (s *Server) handleHeadObject(w http.ResponseWriter, r *http.Request, bucketName, objectKey string) {
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

	// Step 4: bucket must exist.
	exists, err := s.db.BucketExists(bucketName)
	if err != nil {
		log.Printf("ERROR head_object BucketExists(%q): %v", bucketName, err)
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
			// Row marked corrupt — blob may be unreadable. Return a generic 500;
			// do not reveal internal state to the client.
			// Per system-architecture.md section 6.3 and security-model.md section 4.3.
			log.Printf("ERROR head_object corrupt object bucket=%q key=%q", bucketName, objectKey)
			writeError(w, r, http.StatusInternalServerError, "InternalError",
				"We encountered an internal error. Please try again.")
		default:
			log.Printf("ERROR head_object GetObjectByKey(%q, %q): %v", bucketName, objectKey, err)
			writeError(w, r, http.StatusInternalServerError, "InternalError",
				"We encountered an internal error. Please try again.")
		}
		return
	}

	// Step 7: evaluate conditional request headers (RFC 7232 §6).
	// ETag and LastModified come from the metadata row retrieved above.
	// Evaluated before statting the blob to short-circuit I/O on 304/412.
	// Per s3-compatibility-matrix.md section 5.2.
	switch checkConditionalHeaders(obj.ETag, obj.LastModified, r) {
	case conditionalNotModified:
		// 304 Not Modified — send validation headers but no message body.
		// HEAD already has no body; WriteHeader here is the only write.
		// Per RFC 7232 §4.1 and RFC 9110 §9.3.2.
		w.Header().Set("ETag", `"`+obj.ETag+`"`)
		w.Header().Set("Last-Modified", obj.LastModified.UTC().Format(http.TimeFormat))
		w.WriteHeader(http.StatusNotModified)
		return
	case conditionalPrecondFailed:
		// writeError writes an XML body; the net/http server automatically
		// discards it for HEAD requests when serving real traffic.
		// Per RFC 7232 §4.2.
		writeError(w, r, http.StatusPreconditionFailed, "PreconditionFailed",
			"At least one of the pre-conditions you specified did not hold.")
		return
	}

	// Step 8: verify blob file exists without opening it.
	// A missing blob with a valid metadata row is a corruption state, not a
	// "not found" case. Return a generic 500 InternalError. Never expose the
	// raw storage_path in the response.
	// Per system-architecture.md section 6.3 and security-model.md section 4.3.
	if _, statErr := os.Stat(obj.StoragePath); statErr != nil {
		log.Printf("ERROR head_object stat blob bucket=%q key=%q: %v", bucketName, objectKey, statErr)
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"We encountered an internal error. Please try again.")
		return
	}

	// Step 9: standard response headers.
	// ETag is a quoted MD5 hex string per s3-compatibility-matrix.md section 6.2.
	// Last-Modified uses the HTTP/1.1 date format (RFC 1123) per HTTP spec.
	w.Header().Set("Content-Type", obj.ContentType)
	w.Header().Set("Content-Length", strconv.FormatInt(obj.Size, 10))
	w.Header().Set("ETag", `"`+obj.ETag+`"`)
	w.Header().Set("Last-Modified", obj.LastModified.UTC().Format(http.TimeFormat))

	// Step 10: restore x-amz-meta-* user metadata from stored metadata_json.
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

	// Step 11: 200 OK — no body.
	// Per RFC 9110 §9.3.2: HEAD response body MUST NOT be written.
	w.WriteHeader(http.StatusOK)
}
