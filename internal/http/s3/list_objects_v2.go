package s3

import (
	"encoding/xml"
	"errors"
	"net/http"
	"strconv"

	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

const listObjectsV2MaxKeys = 1000

// handleListObjectsV2 implements GET /{bucket}?list-type=2 (ListObjectsV2).
// Per s3-compatibility-matrix.md section 2.4 and implementation-roadmap.md Phase 2.
//
// Supported query parameters:
//
//	prefix            – filter by key prefix
//	delimiter         – group keys that share a common prefix before the delimiter
//	max-keys          – maximum number of items to return (default 1000, range 1–1000)
//	continuation-token – opaque cursor from a previous truncated response
//
// Authentication: SigV4 or presigned URL, same as all other S3 endpoints.
func (s *Server) handleListObjectsV2(w http.ResponseWriter, r *http.Request, bucketName string) {
	_, ok := authenticate(w, r, s.verifier, s.pVerifier, s.db)
	if !ok {
		return
	}

	if err := ValidateBucketName(bucketName); err != nil {
		writeError(w, r, http.StatusBadRequest, "InvalidBucketName",
			"The specified bucket is not valid.")
		return
	}

	exists, err := s.db.BucketExists(bucketName)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"An internal error occurred.")
		return
	}
	if !exists {
		writeError(w, r, http.StatusNotFound, "NoSuchBucket",
			"The specified bucket does not exist.")
		return
	}

	q := r.URL.Query()

	// Resolve effective max-keys: default 1000, cap 1000, reject zero and negative.
	// Per s3-compatibility-matrix.md section 7: max-keys is a paging upper bound.
	// max-keys=0 is rejected because it is ambiguous and unsupported by this implementation.
	maxKeys := listObjectsV2MaxKeys
	if mk := q.Get("max-keys"); mk != "" {
		n, err := strconv.Atoi(mk)
		if err != nil || n <= 0 {
			writeError(w, r, http.StatusBadRequest, "InvalidArgument",
				"Argument max-keys must be an integer between 1 and 1000.")
			return
		}
		if n > listObjectsV2MaxKeys {
			n = listObjectsV2MaxKeys
		}
		maxKeys = n
	}

	opts := metadata.ListOptions{
		Prefix:            q.Get("prefix"),
		Delimiter:         q.Get("delimiter"),
		MaxKeys:           maxKeys,
		ContinuationToken: q.Get("continuation-token"),
	}

	listResult, err := s.db.ListObjectsV2(bucketName, opts)
	if err != nil {
		if errors.Is(err, metadata.ErrInvalidContinuationToken) {
			writeError(w, r, http.StatusBadRequest, "InvalidArgument",
				"The continuation token provided is invalid.")
			return
		}
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"An internal error occurred listing objects.")
		return
	}

	// Build the XML response.
	resp := ListBucketV2Result{
		Name:                  bucketName,
		Prefix:                opts.Prefix,
		Delimiter:             opts.Delimiter,
		MaxKeys:               maxKeys,
		KeyCount:              listResult.KeyCount,
		IsTruncated:           listResult.IsTruncated,
		ContinuationToken:     opts.ContinuationToken,
		NextContinuationToken: listResult.NextContinuationToken,
	}

	for _, obj := range listResult.Objects {
		resp.Contents = append(resp.Contents, s3ObjectItem{
			Key:          obj.Key,
			LastModified: obj.LastModified.UTC().Format(s3TimeFormat),
			ETag:         "\"" + obj.ETag + "\"",
			Size:         obj.Size,
			StorageClass: obj.StorageClass,
		})
	}

	for _, cp := range listResult.CommonPrefixes {
		resp.CommonPrefixes = append(resp.CommonPrefixes, s3CPEntry{Prefix: cp})
	}

	body, err := xml.Marshal(&resp)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"An internal error occurred marshaling the response.")
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(body)
}
