package s3

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
	"github.com/lukehemmin/hemmins-s3-api/internal/storage"
)

// copyObjectResult is the XML response body returned on a successful CopyObject.
// Per AWS S3 API reference: ETag is a quoted MD5 hex string, LastModified is ISO 8601.
// No XML namespace is used (matches AWS S3 CopyObject response format).
type copyObjectResult struct {
	XMLName      xml.Name `xml:"CopyObjectResult"`
	ETag         string   `xml:"ETag"`
	LastModified string   `xml:"LastModified"`
}

// parseCopySource parses the x-amz-copy-source header value into a source bucket
// and object key. The header value may optionally start with "/" and may be
// URL-encoded (percent-encoding).
//
// Supported formats (after URL decoding):
//
//	/bucket/key   (path-style with leading slash)
//	bucket/key    (path-style without leading slash)
//
// Returns ErrInvalidArgument-style errors; the caller converts them to 400 responses.
// Per s3-compatibility-matrix.md section 5.3: only same-instance copies are supported.
func parseCopySource(hdr string) (srcBucket, srcKey string, err error) {
	decoded, decErr := url.PathUnescape(hdr)
	if decErr != nil {
		return "", "", fmt.Errorf("invalid x-amz-copy-source encoding: %w", decErr)
	}
	// Strip optional leading slash (both /bucket/key and bucket/key are accepted).
	source := strings.TrimPrefix(decoded, "/")
	idx := strings.Index(source, "/")
	if idx < 0 {
		return "", "", errors.New("x-amz-copy-source must be in the form [/]bucket/key")
	}
	return source[:idx], source[idx+1:], nil
}

// handleCopyObject implements PUT /{dst-bucket}/{dst-key} when the request carries
// an x-amz-copy-source header (CopyObject).
//
// Request flow:
//  1. Authenticate (SigV4 header or presigned URL).
//  2. Parse x-amz-copy-source → source bucket + key (400 on malformed value).
//  3. Validate source bucket name per naming rules (400 InvalidBucketName).
//  4. Validate destination bucket name per naming rules (400 InvalidBucketName).
//  5. Confirm destination key is non-empty (400 InvalidRequest).
//  6. Confirm source key is non-empty (400 InvalidArgument).
//  7. Parse x-amz-metadata-directive; default COPY. Reject unknown values (400).
//  8. Verify destination bucket exists (404 NoSuchBucket).
//  9. Verify source bucket exists (404 NoSuchBucket).
// 10. Look up source object metadata (404 NoSuchKey / 500 InternalError).
// 11. Open source blob file (500 InternalError if missing or unreadable).
// 12. Stream-copy source blob to new destination path via AtomicWrite.
//     No full-memory load: source file is streamed directly into AtomicWrite.
// 13. Assemble destination metadata per directive:
//     COPY    → preserve source Content-Type and x-amz-meta-* unchanged.
//     REPLACE → use Content-Type and x-amz-meta-* from this request's headers.
//     ETag is always reused from source (blob content is byte-for-byte identical).
// 14. Commit destination metadata via UpsertObject.
// 15. 200 OK with XML CopyObjectResult body (ETag quoted, LastModified ISO 8601).
//
// Scope: same-instance copies only. No conditional copy, cross-instance copy,
// versioning, ACL, or multipart copy. Per product-spec.md section 4.2 and
// s3-compatibility-matrix.md section 5.3.
//
// InternalError policy: storage/DB error details are logged but never sent to the
// client. Raw filesystem paths are never included in any response body or header.
// Per security-model.md section 4.3.
func (s *Server) handleCopyObject(w http.ResponseWriter, r *http.Request, dstBucket, dstKey string) {
	// Step 1: authenticate.
	if _, ok := authenticate(w, r, s.verifier, s.pVerifier, s.db); !ok {
		return
	}

	// Step 2: parse x-amz-copy-source header.
	srcBucket, srcKey, err := parseCopySource(r.Header.Get("X-Amz-Copy-Source"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "InvalidArgument", err.Error())
		return
	}

	// Step 3: validate source bucket name.
	if err := ValidateBucketName(srcBucket); err != nil {
		writeError(w, r, http.StatusBadRequest, "InvalidBucketName",
			"The source bucket name is not valid.")
		return
	}

	// Step 4: validate destination bucket name.
	if err := ValidateBucketName(dstBucket); err != nil {
		writeError(w, r, http.StatusBadRequest, "InvalidBucketName", err.Error())
		return
	}

	// Step 5: destination key must be non-empty.
	if dstKey == "" {
		writeError(w, r, http.StatusBadRequest, "InvalidRequest",
			"Object key must not be empty.")
		return
	}

	// Step 6: source key must be non-empty.
	if srcKey == "" {
		writeError(w, r, http.StatusBadRequest, "InvalidArgument",
			"Source object key must not be empty.")
		return
	}

	// Step 7: parse x-amz-metadata-directive; default is COPY.
	// Only COPY and REPLACE are supported per s3-compatibility-matrix.md section 5.3.
	// Unknown values are explicitly rejected (never silently ignored).
	directive := r.Header.Get("X-Amz-Metadata-Directive")
	if directive == "" {
		directive = "COPY"
	}
	switch directive {
	case "COPY", "REPLACE":
		// supported
	default:
		writeError(w, r, http.StatusBadRequest, "InvalidArgument",
			"x-amz-metadata-directive must be COPY or REPLACE.")
		return
	}

	// Step 8: destination bucket must exist.
	dstExists, err := s.db.BucketExists(dstBucket)
	if err != nil {
		log.Printf("ERROR copy_object BucketExists(dst=%q): %v", dstBucket, err)
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"We encountered an internal error. Please try again.")
		return
	}
	if !dstExists {
		writeError(w, r, http.StatusNotFound, "NoSuchBucket",
			"The destination bucket does not exist.")
		return
	}

	// Step 9: source bucket must exist.
	srcExists, err := s.db.BucketExists(srcBucket)
	if err != nil {
		log.Printf("ERROR copy_object BucketExists(src=%q): %v", srcBucket, err)
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"We encountered an internal error. Please try again.")
		return
	}
	if !srcExists {
		writeError(w, r, http.StatusNotFound, "NoSuchBucket",
			"The source bucket does not exist.")
		return
	}

	// Step 10: look up source object metadata.
	// BucketExists was called first so GetObjectByKey sees the correct bucket scope.
	// Per metadata/objects.go: is_corrupt=1 → ErrCorruptObject → 500 InternalError.
	srcObj, err := s.db.GetObjectByKey(srcBucket, srcKey)
	if err != nil {
		switch {
		case errors.Is(err, metadata.ErrObjectNotFound):
			writeError(w, r, http.StatusNotFound, "NoSuchKey",
				"The specified key does not exist.")
		case errors.Is(err, metadata.ErrCorruptObject):
			// Source blob is flagged corrupt; refuse the copy silently from the client's
			// perspective. Never expose the storage path or internal state.
			log.Printf("ERROR copy_object corrupt source bucket=%q key=%q", srcBucket, srcKey)
			writeError(w, r, http.StatusInternalServerError, "InternalError",
				"We encountered an internal error. Please try again.")
		default:
			log.Printf("ERROR copy_object GetObjectByKey(%q, %q): %v", srcBucket, srcKey, err)
			writeError(w, r, http.StatusInternalServerError, "InternalError",
				"We encountered an internal error. Please try again.")
		}
		return
	}

	// Step 11: open source blob file.
	// A missing blob with a valid metadata row is a corruption state.
	// Return 500 InternalError; never expose the storage path.
	// Per system-architecture.md section 6.3 and security-model.md section 4.3.
	srcFile, err := os.Open(srcObj.StoragePath)
	if err != nil {
		log.Printf("ERROR copy_object open source blob bucket=%q key=%q: %v",
			srcBucket, srcKey, err)
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"We encountered an internal error. Please try again.")
		return
	}
	defer srcFile.Close()

	// Step 12: stream-copy source blob to a new destination path.
	// AtomicWrite handles: temp file → fsync → rename → dir fsync.
	// The source ETag is reused: blob content is byte-for-byte identical.
	// Per system-architecture.md section 5.1: blob must be written before metadata commit.
	// Per operations-runbook.md section 3.1: durability sequence is preserved.
	dstObjectID := uuid.NewString()
	dstPath := storage.StoragePath(s.objectRoot, dstObjectID)
	if _, err := storage.AtomicWrite(r.Context(), s.tempRoot, dstPath, srcFile); err != nil {
		log.Printf("ERROR copy_object AtomicWrite dst=%q: %v", dstPath, err)
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"We encountered an internal error. Please try again.")
		return
	}

	// Step 13: build destination metadata per directive.
	var dstContentType, dstMetaJSON string
	if directive == "COPY" {
		// Preserve source Content-Type and x-amz-meta-* user metadata exactly.
		dstContentType = srcObj.ContentType
		dstMetaJSON = srcObj.MetadataJSON
		if dstMetaJSON == "" {
			dstMetaJSON = "{}"
		}
	} else {
		// directive == "REPLACE": use Content-Type and x-amz-meta-* from this request.
		dstContentType = r.Header.Get("Content-Type")
		if dstContentType == "" {
			dstContentType = "application/octet-stream"
		}
		userMeta := make(map[string]string)
		for k, vv := range r.Header {
			lower := strings.ToLower(k)
			if strings.HasPrefix(lower, "x-amz-meta-") {
				metaKey := lower[len("x-amz-meta-"):]
				if len(vv) > 0 {
					userMeta[metaKey] = vv[0]
				}
			}
		}
		if len(userMeta) > 0 {
			b, jerr := json.Marshal(userMeta)
			if jerr == nil {
				dstMetaJSON = string(b)
			}
		}
		if dstMetaJSON == "" {
			dstMetaJSON = "{}"
		}
	}

	lastModified := time.Now().UTC()
	input := metadata.PutObjectInput{
		Size:         srcObj.Size,
		ETag:         srcObj.ETag, // raw MD5 hex; blob content is identical to source
		ContentType:  dstContentType,
		StoragePath:  dstPath,
		LastModified: lastModified,
		MetadataJSON: dstMetaJSON,
	}

	// Step 14: commit destination metadata.
	// Blob is already durably written to dstPath (AtomicWrite succeeded above).
	// Per system-architecture.md section 5.1: metadata commit follows blob write.
	if err := s.db.UpsertObject(dstBucket, dstKey, input); err != nil {
		log.Printf("ERROR copy_object UpsertObject(dst=%q, %q): %v", dstBucket, dstKey, err)
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"We encountered an internal error. Please try again.")
		return
	}

	// Step 15: 200 OK with XML CopyObjectResult body.
	// ETag in the response body is quoted per S3 spec (s3-compatibility-matrix.md §6.2).
	// LastModified uses the S3 ISO 8601 timestamp format.
	result := copyObjectResult{
		ETag:         `"` + srcObj.ETag + `"`,
		LastModified: lastModified.Format(s3TimeFormat),
	}
	body, err := xml.Marshal(&result)
	if err != nil {
		// xml.Marshal cannot fail for this simple flat struct, but handle defensively.
		log.Printf("ERROR copy_object marshal response: %v", err)
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"We encountered an internal error. Please try again.")
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(body)
}
