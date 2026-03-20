package s3

import (
	"encoding/xml"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

// listPartsResult is the XML response body for ListParts.
// The XML namespace is required by S3 SDKs.
// Per AWS S3 API reference and s3-compatibility-matrix.md section 9.1.
type listPartsResult struct {
	XMLName  xml.Name    `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListPartsResult"`
	Bucket   string      `xml:"Bucket"`
	Key      string      `xml:"Key"`
	UploadId string      `xml:"UploadId"`
	Parts    []s3PartItem `xml:"Part"`
}

// s3PartItem represents a single <Part> entry in a ListParts response.
// ETag is stored as a raw hex string in the DB; it is returned as a quoted
// string in the XML per s3-compatibility-matrix.md section 6.2.
type s3PartItem struct {
	PartNumber   int    `xml:"PartNumber"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
}

// handleListParts implements GET /{bucket}/{key...}?uploadId=X (ListParts).
//
// Request flow:
//  1. Authenticate (SigV4 header or presigned URL).
//  2. Validate bucket name per naming rules (400 InvalidBucketName).
//  3. Confirm object key is non-empty (400 InvalidRequest).
//  4. Parse uploadId query param (required; 400 InvalidRequest if absent).
//  5. Retrieve upload session; absent → 404 NoSuchUpload.
//  6. Verify bucket/key match upload session (mismatch → 404 NoSuchUpload).
//  7. Verify session not expired (expired → 404 NoSuchUpload).
//  8. List parts from DB, ordered by part_number ascending.
//  9. 200 OK with XML ListPartsResult body.
//
// ETag in XML is a quoted string per s3-compatibility-matrix.md section 6.2.
// Timestamp format matches existing XML responses (s3TimeFormat).
//
// InternalError policy: DB error details are logged but never sent to the client.
// Per security-model.md section 4.3.
func (s *Server) handleListParts(w http.ResponseWriter, r *http.Request, bucketName, objectKey string) {
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

	// Step 4: uploadId is required.
	uploadID := r.URL.Query().Get("uploadId")
	if uploadID == "" {
		writeError(w, r, http.StatusBadRequest, "InvalidRequest",
			"Missing required parameter: uploadId.")
		return
	}

	// Step 5: retrieve upload session.
	session, err := s.db.GetMultipartUpload(uploadID)
	if errors.Is(err, metadata.ErrUploadNotFound) {
		writeError(w, r, http.StatusNotFound, "NoSuchUpload",
			"The specified upload does not exist. The upload ID may be invalid, "+
				"or the upload may have been aborted or completed.")
		return
	}
	if err != nil {
		log.Printf("ERROR list_parts GetMultipartUpload(%q): %v", uploadID, err)
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

	// Step 7: session must not be expired.
	if time.Now().UTC().After(session.ExpiresAt) {
		writeError(w, r, http.StatusNotFound, "NoSuchUpload",
			"The specified upload has expired.")
		return
	}

	// Step 8: list parts ordered by part_number ascending.
	parts, err := s.db.ListMultipartParts(uploadID)
	if err != nil {
		log.Printf("ERROR list_parts ListMultipartParts(%q): %v", uploadID, err)
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"We encountered an internal error. Please try again.")
		return
	}

	// Step 9: build and marshal XML response.
	items := make([]s3PartItem, len(parts))
	for i, p := range parts {
		items[i] = s3PartItem{
			PartNumber:   p.PartNumber,
			LastModified: p.LastModified.UTC().Format(s3TimeFormat),
			ETag:         `"` + p.ETag + `"`,
			Size:         p.Size,
		}
	}

	result := listPartsResult{
		Bucket:   bucketName,
		Key:      objectKey,
		UploadId: uploadID,
		Parts:    items,
	}
	body, err := xml.Marshal(&result)
	if err != nil {
		log.Printf("ERROR list_parts marshal response: %v", err)
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"We encountered an internal error. Please try again.")
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(body)
}
