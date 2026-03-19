package metadata

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ErrInvalidContinuationToken is returned by ListObjectsV2 when the caller
// supplies a continuation-token that cannot be decoded.
// The HTTP layer maps this to the S3 error code InvalidArgument (400).
// Per s3-compatibility-matrix.md section 2.4.
var ErrInvalidContinuationToken = errors.New("invalid continuation token")

// ListOptions holds the query parameters for a ListObjectsV2 request.
// MaxKeys must be a positive integer (1–1000); the HTTP handler validates this
// before calling ListObjectsV2. Values above 1000 are silently capped at 1000
// as a defensive ceiling. The zero value is not handled specially: callers
// that do not set MaxKeys explicitly will receive 0 results.
// ContinuationToken is an opaque base64-encoded last-key cursor produced by a
// previous truncated response. Per s3-compatibility-matrix.md section 2.4.
type ListOptions struct {
	Prefix            string
	Delimiter         string
	MaxKeys           int
	ContinuationToken string
}

// ObjectRecord holds the columns needed to render a single <Contents> entry in a
// ListObjectsV2 XML response.
// StorageClass is always "STANDARD" in Phase 2.
// Per system-architecture.md section 4.2 and s3-compatibility-matrix.md section 2.4.
type ObjectRecord struct {
	Key          string
	Size         int64
	ETag         string
	LastModified time.Time
	ContentType  string
	StorageClass string
}

// ListResult is the output of ListObjectsV2.
type ListResult struct {
	Objects               []ObjectRecord
	CommonPrefixes        []string
	IsTruncated           bool
	NextContinuationToken string
	KeyCount              int
}

const listMaxKeysDefault = 1000

// ListObjectsV2 lists objects in bucketName matching the given options.
//
// Pagination cursor: the continuation token is base64(lastConsumedKey) where
// lastConsumedKey is the last raw object_key processed in the previous page
// (including keys that were grouped into a CommonPrefix entry). This guarantees
// correct no-delimiter pagination. With a delimiter, a prefix group that straddles
// a page boundary may re-appear on the next page; this is a known Phase 2
// limitation. Per s3-compatibility-matrix.md section 2.4 and
// implementation-roadmap.md Phase 2 scope.
//
// The DB query uses a sequential scan over the prefix range and streams rows into
// a Go-level grouping loop that stops after maxKeys accumulated items. No
// artificial row LIMIT is applied so that delimiter grouping is always correct;
// for Phase 2 dataset sizes this is acceptable.
// Per implementation-roadmap.md section 3.2.
func (db *DB) ListObjectsV2(bucketName string, opts ListOptions) (ListResult, error) {
	maxKeys := opts.MaxKeys
	// Apply only the upper-bound cap. The HTTP handler is responsible for
	// rejecting max-keys=0 and negative values before reaching this layer.
	// Per s3-compatibility-matrix.md section 7.
	if maxKeys > listMaxKeysDefault {
		maxKeys = listMaxKeysDefault
	}

	// Decode the opaque continuation token to a raw startAfter key.
	var startAfter string
	if opts.ContinuationToken != "" {
		decoded, err := base64.StdEncoding.DecodeString(opts.ContinuationToken)
		if err != nil {
			return ListResult{}, ErrInvalidContinuationToken
		}
		startAfter = string(decoded)
	}

	query := `
		SELECT o.object_key, o.size, o.etag, o.last_modified, o.content_type
		FROM objects o
		JOIN buckets b ON o.bucket_id = b.id
		WHERE b.name = ?`
	args := []interface{}{bucketName}

	if opts.Prefix != "" {
		query += ` AND o.object_key LIKE ? ESCAPE '\'`
		args = append(args, escapeLike(opts.Prefix)+"%")
	}
	if startAfter != "" {
		query += ` AND o.object_key > ?`
		args = append(args, startAfter)
	}
	query += ` ORDER BY o.object_key ASC`

	rows, err := db.sqldb.Query(query, args...)
	if err != nil {
		return ListResult{}, fmt.Errorf("listing objects in %q: %w", bucketName, err)
	}
	defer rows.Close()

	var result ListResult
	cpSeen := make(map[string]struct{})
	var lastConsumedKey string
	itemCount := 0

	for rows.Next() {
		var key, etag, lastModStr, contentType string
		var size int64
		if err := rows.Scan(&key, &size, &etag, &lastModStr, &contentType); err != nil {
			return ListResult{}, fmt.Errorf("scanning object row: %w", err)
		}

		// Apply delimiter grouping when a delimiter is set.
		if opts.Delimiter != "" {
			suffix := key
			if opts.Prefix != "" {
				suffix = key[len(opts.Prefix):]
			}
			if idx := strings.Index(suffix, opts.Delimiter); idx >= 0 {
				cp := opts.Prefix + suffix[:idx+len(opts.Delimiter)]
				if _, seen := cpSeen[cp]; seen {
					// Key consumed into an already-recorded CommonPrefix;
					// advance the cursor but do not add another item.
					lastConsumedKey = key
					continue
				}
				// New CommonPrefix: check page limit before recording.
				if itemCount >= maxKeys {
					result.IsTruncated = true
					result.NextContinuationToken = base64.StdEncoding.EncodeToString([]byte(lastConsumedKey))
					break
				}
				cpSeen[cp] = struct{}{}
				result.CommonPrefixes = append(result.CommonPrefixes, cp)
				lastConsumedKey = key
				itemCount++
				continue
			}
		}

		// Regular object: check page limit before recording.
		if itemCount >= maxKeys {
			result.IsTruncated = true
			result.NextContinuationToken = base64.StdEncoding.EncodeToString([]byte(lastConsumedKey))
			break
		}

		var lm time.Time
		if t, err := time.Parse(time.RFC3339, lastModStr); err == nil {
			lm = t
		}
		result.Objects = append(result.Objects, ObjectRecord{
			Key:          key,
			Size:         size,
			ETag:         etag,
			LastModified: lm,
			ContentType:  contentType,
			StorageClass: "STANDARD",
		})
		lastConsumedKey = key
		itemCount++
	}
	if err := rows.Err(); err != nil {
		return ListResult{}, fmt.Errorf("iterating object rows: %w", err)
	}

	// CommonPrefixes must be returned in UTF-8 lexicographic order.
	// Per s3-compatibility-matrix.md section 7.
	sort.Strings(result.CommonPrefixes)

	result.KeyCount = len(result.Objects) + len(result.CommonPrefixes)
	return result, nil
}

// PutObjectInput holds the values needed to insert or replace an object row.
// ETag must be a raw MD5 hex string (no surrounding quotes); the HTTP layer adds
// quotes when setting the response header. Per s3-compatibility-matrix.md section 6.2.
// checksum_sha256 is intentionally empty in Phase 2; the column will be populated
// when SHA256 streaming verification is added. Per implementation-roadmap.md Phase 2.
type PutObjectInput struct {
	Size         int64
	ETag         string // raw MD5 hex, no surrounding quotes
	ContentType  string
	StoragePath  string
	LastModified time.Time
	MetadataJSON string // JSON of x-amz-meta-* headers; must be valid JSON, e.g. "{}"
}

// UpsertObject inserts a new object row or atomically replaces an existing one for
// the given (bucketName, objectKey) pair using SQLite's ON CONFLICT DO UPDATE.
// The UNIQUE(bucket_id, object_key) constraint is the conflict target.
//
// Overwrite policy: the existing row is fully replaced; metadata_json is not merged.
// Per s3-compatibility-matrix.md section 6.1.
//
// checksum_sha256 is set to empty on both insert and update in Phase 2.
// The caller (HTTP handler) must call AtomicWrite and receive a successful WriteResult
// before calling UpsertObject. Per system-architecture.md section 5.1: metadata commit
// happens only after the blob is durably written and renamed to its final path.
func (db *DB) UpsertObject(bucketName, objectKey string, input PutObjectInput) error {
	_, err := db.sqldb.Exec(`
		INSERT INTO objects
			(bucket_id, object_key, size, etag, content_type, storage_path,
			 last_modified, metadata_json, checksum_sha256)
		VALUES (
			(SELECT id FROM buckets WHERE name = ?),
			?, ?, ?, ?, ?, ?, ?, ''
		)
		ON CONFLICT(bucket_id, object_key) DO UPDATE SET
			size            = excluded.size,
			etag            = excluded.etag,
			content_type    = excluded.content_type,
			storage_path    = excluded.storage_path,
			last_modified   = excluded.last_modified,
			metadata_json   = excluded.metadata_json,
			checksum_sha256 = '',
			is_corrupt      = 0
	`,
		bucketName,
		objectKey,
		input.Size,
		input.ETag,
		input.ContentType,
		input.StoragePath,
		input.LastModified.UTC().Format(time.RFC3339),
		input.MetadataJSON,
	)
	if err != nil {
		return fmt.Errorf("upserting object %q in bucket %q: %w", objectKey, bucketName, err)
	}
	return nil
}

// escapeLike escapes the LIKE special characters (%, _, \) in s so that it
// can be used safely as a prefix pattern with "LIKE ? ESCAPE '\'".
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}
