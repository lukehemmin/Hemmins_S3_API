package s3

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
	"github.com/lukehemmin/hemmins-s3-api/internal/storage"
)

// handlePutObject implements PUT /{bucket}/{key...} (single-part upload).
//
// Request flow:
//  1. Authenticate (SigV4 header or presigned URL).
//  2. Validate bucket name.
//  3. Confirm bucket exists in metadata DB (404 NoSuchBucket if not).
//  4. Confirm object key is non-empty (400 InvalidRequest if empty).
//  4b. Parse Content-MD5 header if present; malformed → 400 InvalidDigest (fails before any write).
//  5. Generate a UUID-based object ID; compute destPath via storage.StoragePath.
//  6. Stream request body through an MD5 hasher into storage.AtomicWrite.
//  7. Compute ETag as raw MD5 hex string.
//  7b. If Content-MD5 was provided, verify it matches actual body digest → 400 BadDigest.
//  8. Commit object metadata row via metadata.UpsertObject.
//  9. Return 200 OK with ETag header (quoted per S3 spec).
//
// InternalError policy: internal errors (storage, DB) return a generic client message only;
// full error details are written to the server log and never exposed in XML responses.
// Per security-model.md section 4.3.
//
// Per system-architecture.md section 5.1: blob must be durably written and
// renamed to its final path before the metadata row is committed.
// Per s3-compatibility-matrix.md section 6.1–6.2.
func (s *Server) handlePutObject(w http.ResponseWriter, r *http.Request, bucketName, objectKey string) {
	// Step 1: authenticate.
	if _, ok := authenticate(w, r, s.verifier, s.pVerifier, s.db); !ok {
		return
	}

	// Step 2: validate bucket name.
	if err := ValidateBucketName(bucketName); err != nil {
		writeError(w, r, http.StatusBadRequest, "InvalidBucketName", err.Error())
		return
	}

	// Step 3: bucket must exist.
	exists, err := s.db.BucketExists(bucketName)
	if err != nil {
		log.Printf("ERROR put_object BucketExists(%q): %v", bucketName, err)
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"We encountered an internal error. Please try again.")
		return
	}
	if !exists {
		writeError(w, r, http.StatusNotFound, "NoSuchBucket",
			"The specified bucket does not exist.")
		return
	}

	// Step 4: object key must be non-empty.
	if objectKey == "" {
		writeError(w, r, http.StatusBadRequest, "InvalidRequest",
			"Object key must not be empty.")
		return
	}

	// Step 4b: validate Content-MD5 header format before writing any data.
	// Content-MD5 is a Base64-encoded 16-byte MD5 digest per RFC 1864.
	// Malformed Base64 or wrong decoded length → 400 InvalidDigest (clean fail, no blob written).
	// Per s3-compatibility-matrix.md section 5.1: Content-MD5 must be validated if present.
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

	// Step 5: generate a UUID for the blob file name and compute its storage path.
	// storage.StoragePath shards by the first 4 hex chars of the ID so directories
	// stay manageable. Per system-architecture.md section 3.
	objectID := uuid.NewString()
	destPath := storage.StoragePath(s.objectRoot, objectID)

	// Step 6: stream body through MD5 hasher; AtomicWrite handles temp → rename → fsync.
	// r.Body may be nil for zero-byte requests; guard so TeeReader doesn't panic.
	bodyReader := r.Body
	if bodyReader == nil {
		bodyReader = http.NoBody
	}
	h := md5.New()
	body := io.TeeReader(bodyReader, h)

	result, err := storage.AtomicWrite(r.Context(), s.tempRoot, destPath, body)
	if err != nil {
		log.Printf("ERROR put_object AtomicWrite(%q): %v", destPath, err)
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"We encountered an internal error. Please try again.")
		return
	}

	// Step 7: ETag is the raw MD5 hex of the full body bytes.
	actualMD5 := h.Sum(nil) // 16-byte raw digest
	etag := hex.EncodeToString(actualMD5)

	// Step 7b: verify Content-MD5 if provided. Comparison happens here because the
	// full digest is only known after streaming through AtomicWrite. On mismatch the
	// metadata row is NOT committed, but the blob at destPath is an orphan; it will
	// be reclaimed by background recovery (operations-runbook.md orphan policy).
	// Per s3-compatibility-matrix.md section 5.1.
	if declaredMD5 != nil && !bytes.Equal(actualMD5, declaredMD5) {
		writeError(w, r, http.StatusBadRequest, "BadDigest",
			"The Content-MD5 you specified did not match what we received.")
		return
	}

	// Resolve content-type; default per RFC 7233 / S3 docs.
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	// Collect x-amz-meta-* headers and serialize to JSON.
	// If no user-defined metadata is present, store an empty JSON object "{}".
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
	metaJSON := "{}"
	if len(userMeta) > 0 {
		b, jerr := json.Marshal(userMeta)
		if jerr == nil {
			metaJSON = string(b)
		}
	}

	// Step 8: commit metadata. Blob is already durably written at this point.
	input := metadata.PutObjectInput{
		Size:         result.Size,
		ETag:         etag,
		ContentType:  contentType,
		StoragePath:  destPath,
		LastModified: time.Now().UTC(),
		MetadataJSON: metaJSON,
	}
	if err := s.db.UpsertObject(bucketName, objectKey, input); err != nil {
		log.Printf("ERROR put_object UpsertObject(%q, %q): %v", bucketName, objectKey, err)
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"We encountered an internal error. Please try again.")
		return
	}

	// Step 9: 200 OK with quoted ETag header per S3 spec.
	w.Header().Set("ETag", `"`+etag+`"`)
	w.WriteHeader(http.StatusOK)
}
