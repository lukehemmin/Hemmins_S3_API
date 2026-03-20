package metadata

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrUploadNotFound is returned by multipart helpers when the upload_id does not
// exist in the multipart_uploads table.
// The HTTP layer maps this to the S3 error code NoSuchUpload (404).
// Per s3-compatibility-matrix.md section 9.2.
var ErrUploadNotFound = errors.New("multipart upload not found")

// CreateMultipartUploadInput holds the values needed to insert a new
// multipart_uploads row.
// UploadID must be globally unique (UUID recommended).
// ExpiresAt is computed by the caller from gc.multipart_expiry.
// Per system-architecture.md section 5.3.
type CreateMultipartUploadInput struct {
	UploadID     string
	BucketName   string // resolved to bucket_id via subquery
	ObjectKey    string
	InitiatedAt  time.Time
	ExpiresAt    time.Time
	MetadataJSON string // JSON of x-amz-meta-* pairs; must be valid JSON, e.g. "{}"
}

// MultipartUploadRow holds the fields from multipart_uploads needed by UploadPart,
// ListParts, and CompleteMultipartUpload.
// BucketName is resolved via JOIN with the buckets table.
// MetadataJSON holds the content-type and x-amz-meta-* pairs stored at initiation time;
// CompleteMultipartUpload reads this to set the final object's metadata.
// Per system-architecture.md section 4.3.
type MultipartUploadRow struct {
	UploadID     string
	BucketName   string
	ObjectKey    string
	ExpiresAt    time.Time
	MetadataJSON string
}

// GetMultipartUpload retrieves the multipart_uploads row for uploadID.
// Returns ErrUploadNotFound if no such session exists.
// The HTTP layer maps ErrUploadNotFound to NoSuchUpload (404).
// Per s3-compatibility-matrix.md section 9.2.
func (db *DB) GetMultipartUpload(uploadID string) (MultipartUploadRow, error) {
	var row MultipartUploadRow
	var expiresAtStr string
	err := db.sqldb.QueryRow(`
		SELECT mu.id, b.name, mu.object_key, mu.expires_at, mu.metadata_json
		FROM multipart_uploads mu
		JOIN buckets b ON mu.bucket_id = b.id
		WHERE mu.id = ?
	`, uploadID).Scan(&row.UploadID, &row.BucketName, &row.ObjectKey, &expiresAtStr, &row.MetadataJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return MultipartUploadRow{}, ErrUploadNotFound
	}
	if err != nil {
		return MultipartUploadRow{}, fmt.Errorf("getting multipart upload %q: %w", uploadID, err)
	}
	t, parseErr := time.Parse(time.RFC3339, expiresAtStr)
	if parseErr != nil {
		return MultipartUploadRow{}, fmt.Errorf("parsing expires_at for upload %q: %w", uploadID, parseErr)
	}
	row.ExpiresAt = t
	return row, nil
}

// UpsertPartInput holds the values needed to insert or replace a multipart_parts row.
// Re-uploading the same partNumber replaces the previous part per S3 semantics.
// Per s3-compatibility-matrix.md section 8.
type UpsertPartInput struct {
	UploadID    string
	PartNumber  int
	ETag        string
	Size        int64
	StagingPath string
	CreatedAt   time.Time
}

// ReplaceMultipartPart replaces the multipart_parts row for (upload_id, part_number)
// with the new values in input, and returns the previous staging path if a row existed.
//
// The operation runs inside a transaction:
//  1. SELECT existing staging_path for (upload_id, part_number).
//  2. INSERT OR REPLACE new row with input values.
//  3. COMMIT.
//
// On success, oldPath holds the previous staging file path (hadOld == true),
// or is empty (hadOld == false) when no prior row existed.
// The caller must delete oldPath (best-effort) when hadOld is true and
// oldPath != input.StagingPath, to avoid leaving orphan staging files.
//
// Per system-architecture.md section 4.4 and s3-compatibility-matrix.md section 8.
func (db *DB) ReplaceMultipartPart(input UpsertPartInput) (oldPath string, hadOld bool, err error) {
	tx, err := db.sqldb.Begin()
	if err != nil {
		return "", false, fmt.Errorf("begin transaction for part replacement: %w", err)
	}
	defer tx.Rollback() // no-op after Commit

	// Step 1: read existing staging path, if any.
	var existingPath string
	scanErr := tx.QueryRow(
		"SELECT staging_path FROM multipart_parts WHERE upload_id = ? AND part_number = ?",
		input.UploadID, input.PartNumber,
	).Scan(&existingPath)
	switch {
	case errors.Is(scanErr, sql.ErrNoRows):
		// No previous row; hadOld remains false.
	case scanErr != nil:
		return "", false, fmt.Errorf("reading existing staging path for upload %q part %d: %w",
			input.UploadID, input.PartNumber, scanErr)
	default:
		hadOld = true
		oldPath = existingPath
	}

	// Step 2: replace the row.
	_, execErr := tx.Exec(`
		INSERT OR REPLACE INTO multipart_parts
			(upload_id, part_number, etag, size, staging_path, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`,
		input.UploadID,
		input.PartNumber,
		input.ETag,
		input.Size,
		input.StagingPath,
		input.CreatedAt.UTC().Format(time.RFC3339),
	)
	if execErr != nil {
		return "", false, fmt.Errorf("replacing part %d for upload %q: %w",
			input.PartNumber, input.UploadID, execErr)
	}

	// Step 3: commit.
	if commitErr := tx.Commit(); commitErr != nil {
		return "", false, fmt.Errorf("committing part replacement for upload %q part %d: %w",
			input.UploadID, input.PartNumber, commitErr)
	}

	return oldPath, hadOld, nil
}

// PartRow holds a single multipart_parts row returned by ListMultipartParts.
// LastModified is parsed from the created_at column.
// StagingPath is the filesystem path of the part's staging file; used by
// CompleteMultipartUpload to merge parts and clean up after commit.
// Per s3-compatibility-matrix.md section 8 and system-architecture.md section 4.4.
type PartRow struct {
	PartNumber   int
	ETag         string
	Size         int64
	LastModified time.Time
	StagingPath  string
}

// ListMultipartParts returns all parts for uploadID, sorted by part_number ascending.
// Returns an empty slice (not nil) when no parts exist.
// The upload session must exist; callers should verify via GetMultipartUpload first.
// Per s3-compatibility-matrix.md section 8 and implementation-roadmap.md Phase 4.
func (db *DB) ListMultipartParts(uploadID string) ([]PartRow, error) {
	rows, err := db.sqldb.Query(`
		SELECT part_number, etag, size, created_at, staging_path
		FROM multipart_parts
		WHERE upload_id = ?
		ORDER BY part_number ASC
	`, uploadID)
	if err != nil {
		return nil, fmt.Errorf("listing parts for upload %q: %w", uploadID, err)
	}
	defer rows.Close()

	parts := make([]PartRow, 0)
	for rows.Next() {
		var p PartRow
		var createdAtStr string
		if scanErr := rows.Scan(&p.PartNumber, &p.ETag, &p.Size, &createdAtStr, &p.StagingPath); scanErr != nil {
			return nil, fmt.Errorf("scanning part row for upload %q: %w", uploadID, scanErr)
		}
		t, parseErr := time.Parse(time.RFC3339, createdAtStr)
		if parseErr != nil {
			return nil, fmt.Errorf("parsing created_at for upload %q: %w", uploadID, parseErr)
		}
		p.LastModified = t
		parts = append(parts, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating parts for upload %q: %w", uploadID, err)
	}
	return parts, nil
}

// DeleteMultipartUpload removes the multipart_uploads row for uploadID.
// The ON DELETE CASCADE on multipart_parts.upload_id ensures all part rows are
// automatically removed when the session row is deleted.
// Used by CompleteMultipartUpload after the final object is committed to disk and DB.
// Per operations-runbook.md section 3.2 and s3-compatibility-matrix.md section 8.
func (db *DB) DeleteMultipartUpload(uploadID string) error {
	_, err := db.sqldb.Exec(
		"DELETE FROM multipart_uploads WHERE id = ?",
		uploadID,
	)
	if err != nil {
		return fmt.Errorf("deleting multipart upload %q: %w", uploadID, err)
	}
	return nil
}

// FinalizeMultipartUploadInput holds the values needed by FinalizeMultipartUpload.
// Per system-architecture.md section 5.3 and operations-runbook.md section 3.2.
type FinalizeMultipartUploadInput struct {
	BucketName string
	ObjectKey  string
	ObjInput   PutObjectInput
	UploadID   string
}

// FinalizeMultipartUpload atomically upserts the final object row and deletes
// the multipart session (ON DELETE CASCADE removes all part rows) in a single
// database transaction.
//
// The caller MUST call storage.AtomicWrite and receive a successful result
// before calling this function. Per system-architecture.md section 5.1:
// metadata commit happens only after the blob is durably written.
//
// If either the upsert or the delete fails the entire transaction is rolled
// back and an error is returned. The caller MUST NOT return a success response
// on error. Per operations-runbook.md section 3.2: the finalization boundary
// must be all-or-nothing.
func (db *DB) FinalizeMultipartUpload(input FinalizeMultipartUploadInput) error {
	tx, err := db.sqldb.Begin()
	if err != nil {
		return fmt.Errorf("beginning finalize transaction for upload %q: %w", input.UploadID, err)
	}
	defer tx.Rollback() // no-op after Commit

	_, err = tx.Exec(`
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
		input.BucketName,
		input.ObjectKey,
		input.ObjInput.Size,
		input.ObjInput.ETag,
		input.ObjInput.ContentType,
		input.ObjInput.StoragePath,
		input.ObjInput.LastModified.UTC().Format(time.RFC3339),
		input.ObjInput.MetadataJSON,
	)
	if err != nil {
		return fmt.Errorf("upserting object %q in bucket %q: %w", input.ObjectKey, input.BucketName, err)
	}

	delResult, err := tx.Exec("DELETE FROM multipart_uploads WHERE id = ?", input.UploadID)
	if err != nil {
		return fmt.Errorf("deleting multipart upload %q: %w", input.UploadID, err)
	}
	n, err := delResult.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking rows affected for upload %q: %w", input.UploadID, err)
	}
	if n != 1 {
		// Session row is already gone (concurrent complete or abort). Roll back the
		// object upsert too so the final object is never committed without a valid
		// session being consumed. Per operations-runbook.md section 3.2.
		return fmt.Errorf("upload %q: %w", input.UploadID, ErrUploadNotFound)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing finalization for upload %q: %w", input.UploadID, err)
	}
	return nil
}

// AbortMultipartUpload deletes the multipart_uploads row for uploadID and verifies
// that exactly one row was removed. Returns ErrUploadNotFound if no row was deleted,
// which indicates the session was never created or was already consumed by a
// concurrent CompleteMultipartUpload or AbortMultipartUpload.
// The ON DELETE CASCADE on multipart_parts.upload_id ensures all part rows are
// automatically removed when the session row is deleted.
// The HTTP layer maps ErrUploadNotFound to NoSuchUpload (404).
// Per s3-compatibility-matrix.md section 9.2.
func (db *DB) AbortMultipartUpload(uploadID string) error {
	result, err := db.sqldb.Exec("DELETE FROM multipart_uploads WHERE id = ?", uploadID)
	if err != nil {
		return fmt.Errorf("aborting multipart upload %q: %w", uploadID, err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking rows affected for abort %q: %w", uploadID, err)
	}
	if n == 0 {
		return fmt.Errorf("abort upload %q: %w", uploadID, ErrUploadNotFound)
	}
	return nil
}

// UpsertMultipartPart inserts or replaces a multipart_parts row.
// Using INSERT OR REPLACE allows re-uploading the same part number (overwrite policy).
// Per s3-compatibility-matrix.md section 8 and system-architecture.md section 4.4.
func (db *DB) UpsertMultipartPart(input UpsertPartInput) error {
	_, err := db.sqldb.Exec(`
		INSERT OR REPLACE INTO multipart_parts
			(upload_id, part_number, etag, size, staging_path, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`,
		input.UploadID,
		input.PartNumber,
		input.ETag,
		input.Size,
		input.StagingPath,
		input.CreatedAt.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("upserting part %d for upload %q: %w", input.PartNumber, input.UploadID, err)
	}
	return nil
}

// CreateMultipartUpload inserts a new multipart_uploads row.
//
// Precondition: the bucket named by input.BucketName must exist; otherwise the
// subquery (SELECT id FROM buckets WHERE name = ?) returns NULL and the INSERT
// fails with a NOT NULL constraint on bucket_id.  The HTTP handler is responsible
// for verifying bucket existence via BucketExists before calling this function.
//
// Per system-architecture.md section 5.3 and s3-compatibility-matrix.md section 8.
func (db *DB) CreateMultipartUpload(input CreateMultipartUploadInput) error {
	_, err := db.sqldb.Exec(`
		INSERT INTO multipart_uploads
			(id, bucket_id, object_key, initiated_at, expires_at, metadata_json)
		VALUES (
			?,
			(SELECT id FROM buckets WHERE name = ?),
			?, ?, ?, ?
		)
	`,
		input.UploadID,
		input.BucketName,
		input.ObjectKey,
		input.InitiatedAt.UTC().Format(time.RFC3339),
		input.ExpiresAt.UTC().Format(time.RFC3339),
		input.MetadataJSON,
	)
	if err != nil {
		return fmt.Errorf("creating multipart upload %q in bucket %q: %w",
			input.UploadID, input.BucketName, err)
	}
	return nil
}
