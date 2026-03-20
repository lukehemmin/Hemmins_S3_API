package s3

import (
	"encoding/json"
	"encoding/xml"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

// initiateMultipartUploadResult is the XML response body returned on a successful
// CreateMultipartUpload. The XML namespace is required by S3 SDKs.
// Per AWS S3 API reference.
type initiateMultipartUploadResult struct {
	XMLName  xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ InitiateMultipartUploadResult"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	UploadId string   `xml:"UploadId"`
}

// handleCreateMultipartUpload implements POST /{bucket}/{key...}?uploads.
//
// Request flow:
//  1. Authenticate (SigV4 header or presigned URL).
//  2. Validate bucket name per naming rules (400 InvalidBucketName).
//  3. Confirm object key is non-empty (400 InvalidRequest).
//  4. Verify bucket exists (404 NoSuchBucket).
//  5. Generate a new upload_id (UUID).
//  6. Collect Content-Type and x-amz-meta-* headers.
//  7. Compute expires_at = now + s.multipartExpiry.
//  8. Insert multipart_uploads row.
//  9. 200 OK with XML InitiateMultipartUploadResult body.
//
// InternalError policy: storage/DB error details are logged but never sent to the
// client. Raw filesystem paths are never included in any response body or header.
// Per security-model.md section 4.3.
//
// expiry policy: expires_at = initiated_at + s.multipartExpiry.
// s.multipartExpiry comes from gc.multipart_expiry (default 24h).
// Per operations-runbook.md section 4.1: expired multipart sessions are cleaned
// up on startup and by the GC worker.
// Per s3-compatibility-matrix.md section 8 and implementation-roadmap.md Phase 4.
func (s *Server) handleCreateMultipartUpload(w http.ResponseWriter, r *http.Request, bucketName, objectKey string) {
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
		log.Printf("ERROR create_multipart_upload BucketExists(%q): %v", bucketName, err)
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"We encountered an internal error. Please try again.")
		return
	}
	if !exists {
		writeError(w, r, http.StatusNotFound, "NoSuchBucket",
			"The specified bucket does not exist.")
		return
	}

	// Step 5: generate a unique upload ID.
	uploadID := uuid.NewString()

	// Step 6: collect Content-Type and x-amz-meta-* from request headers.
	// Content-Type: stored in metadata_json alongside x-amz-meta-* keys so that
	// CompleteMultipartUpload can apply it to the final object.
	// Per put_object.go convention: default to application/octet-stream when absent.
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
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
	// Store content-type alongside user metadata in metadata_json so that
	// CompleteMultipartUpload can retrieve it without a separate column.
	// Key "content-type" uses lowercase to match x-amz-meta-* convention.
	userMeta["content-type"] = contentType

	metaJSON := "{}"
	if b, jerr := json.Marshal(userMeta); jerr == nil {
		metaJSON = string(b)
	}

	// Step 7: compute expiry time.
	// Uses s.multipartExpiry (from gc.multipart_expiry, default 24h).
	// If multipartExpiry was never set (zero value), fall back to 24h.
	// Per operations-runbook.md section 4.1: expired sessions are GC candidates.
	expiry := s.multipartExpiry
	if expiry <= 0 {
		expiry = 24 * time.Hour
	}
	now := time.Now().UTC()
	expiresAt := now.Add(expiry)

	// Step 8: insert multipart_uploads row.
	input := metadata.CreateMultipartUploadInput{
		UploadID:     uploadID,
		BucketName:   bucketName,
		ObjectKey:    objectKey,
		InitiatedAt:  now,
		ExpiresAt:    expiresAt,
		MetadataJSON: metaJSON,
	}
	if err := s.db.CreateMultipartUpload(input); err != nil {
		log.Printf("ERROR create_multipart_upload CreateMultipartUpload(%q, %q): %v",
			bucketName, objectKey, err)
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"We encountered an internal error. Please try again.")
		return
	}

	// Step 9: 200 OK with XML body.
	// XML namespace is required by S3 SDKs (s3-compatibility-matrix.md §9.1).
	result := initiateMultipartUploadResult{
		Bucket:   bucketName,
		Key:      objectKey,
		UploadId: uploadID,
	}
	body, err := xml.Marshal(&result)
	if err != nil {
		// xml.Marshal cannot fail for this simple flat struct, but handle defensively.
		log.Printf("ERROR create_multipart_upload marshal response: %v", err)
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"We encountered an internal error. Please try again.")
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(body)
}
