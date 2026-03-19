package metadata

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrBucketAlreadyExists is returned by CreateBucket when a bucket with the
// same name already exists in the metadata DB.
// In the single-tenant model every bucket is owned by the same user, so the
// HTTP layer maps this to the S3 error code BucketAlreadyOwnedByYou.
// Per s3-compatibility-matrix.md section 9.2.
var ErrBucketAlreadyExists = errors.New("bucket already exists")

// ErrBucketNotFound is returned by DeleteBucket when the named bucket does not exist.
// The HTTP layer maps this to the S3 error code NoSuchBucket (404).
// Per s3-compatibility-matrix.md section 9.2.
var ErrBucketNotFound = errors.New("bucket not found")

// ErrBucketNotEmpty is returned by DeleteBucket when the bucket still contains objects.
// The HTTP layer maps this to the S3 error code BucketNotEmpty (409).
// Per s3-compatibility-matrix.md section 3.
var ErrBucketNotEmpty = errors.New("bucket not empty")

// BucketRecord holds the name and creation time of a bucket row from the DB.
// Per system-architecture.md section 4.1.
type BucketRecord struct {
	Name      string
	CreatedAt time.Time
}

// ListBuckets returns all buckets ordered alphabetically by name.
// Per s3-compatibility-matrix.md: GET Service returns buckets owned by the
// authenticated user; ordering by name provides stable, predictable output.
func (db *DB) ListBuckets() ([]BucketRecord, error) {
	rows, err := db.sqldb.Query(
		`SELECT name, created_at FROM buckets ORDER BY name ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("listing buckets: %w", err)
	}
	defer rows.Close()

	var out []BucketRecord
	for rows.Next() {
		var name, createdAtStr string
		if err := rows.Scan(&name, &createdAtStr); err != nil {
			return nil, fmt.Errorf("scanning bucket row: %w", err)
		}
		rec := BucketRecord{Name: name}
		if t, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
			rec.CreatedAt = t
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating bucket rows: %w", err)
	}
	return out, nil
}

// CreateBucket inserts a new bucket row with the given name and creation time.
// Returns ErrBucketAlreadyExists if a bucket with that name already exists
// (SQLite UNIQUE constraint on buckets.name).
// The caller (HTTP layer) is responsible for validating the bucket name before
// calling this function — only trusted, pre-validated names should be passed.
// Per system-architecture.md section 4.1.
func (db *DB) CreateBucket(name string, createdAt time.Time) error {
	_, err := db.sqldb.Exec(
		"INSERT INTO buckets (name, created_at) VALUES (?, ?)",
		name, createdAt.UTC().Format(time.RFC3339),
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return ErrBucketAlreadyExists
		}
		return fmt.Errorf("creating bucket %q: %w", name, err)
	}
	return nil
}

// BucketExists reports whether a bucket with the given name exists in the DB.
// Returns (true, nil) if found, (false, nil) if not found, and (false, err)
// on a database error.
// Per system-architecture.md section 4.1.
func (db *DB) BucketExists(name string) (bool, error) {
	var count int
	if err := db.sqldb.QueryRow(
		"SELECT COUNT(*) FROM buckets WHERE name = ?", name,
	).Scan(&count); err != nil {
		return false, fmt.Errorf("checking bucket %q existence: %w", name, err)
	}
	return count > 0, nil
}

// BucketIsEmpty reports whether the bucket contains no objects.
//
// Emptiness policy (Phase 2): only rows in the objects table are considered.
// Pending multipart_uploads rows are intentionally excluded — a bucket with
// only in-progress multipart uploads may still be deleted at this stage; any
// leftover staging paths are handled by the orphan-recovery process (Phase 1).
// This policy will be revisited in Phase 4 when multipart upload is fully
// implemented. Per implementation-roadmap.md sections 1 and 4.
func (db *DB) BucketIsEmpty(name string) (bool, error) {
	var count int
	if err := db.sqldb.QueryRow(
		`SELECT COUNT(*) FROM objects
		 WHERE bucket_id = (SELECT id FROM buckets WHERE name = ?)`,
		name,
	).Scan(&count); err != nil {
		return false, fmt.Errorf("checking bucket %q emptiness: %w", name, err)
	}
	return count == 0, nil
}

// DeleteBucket removes the bucket row for name inside a single transaction.
// The existence check, emptiness check, DELETE, and RowsAffected verification
// are all performed atomically to prevent TOCTOU race conditions.
// Returns ErrBucketNotFound if the bucket does not exist or was concurrently deleted.
// Returns ErrBucketNotEmpty if the bucket still contains objects.
// The caller (HTTP layer) is responsible for validating the name before calling.
// Per s3-compatibility-matrix.md section 3 and system-architecture.md section 4.1.
func (db *DB) DeleteBucket(name string) error {
	tx, err := db.sqldb.Begin()
	if err != nil {
		return fmt.Errorf("beginning delete bucket transaction: %w", err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	var bucketID int64
	err = tx.QueryRow("SELECT id FROM buckets WHERE name = ?", name).Scan(&bucketID)
	if err == sql.ErrNoRows {
		err = ErrBucketNotFound
		return err
	}
	if err != nil {
		return fmt.Errorf("querying bucket id for %q: %w", name, err)
	}

	var count int
	err = tx.QueryRow("SELECT COUNT(*) FROM objects WHERE bucket_id = ?", bucketID).Scan(&count)
	if err != nil {
		return fmt.Errorf("checking emptiness for bucket %q: %w", name, err)
	}
	if count > 0 {
		err = ErrBucketNotEmpty
		return err
	}

	var res sql.Result
	res, err = tx.Exec("DELETE FROM buckets WHERE id = ?", bucketID)
	if err != nil {
		return fmt.Errorf("deleting bucket %q: %w", name, err)
	}

	var rowsAffected int64
	rowsAffected, err = res.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking rows affected for bucket %q: %w", name, err)
	}
	if rowsAffected != 1 {
		err = ErrBucketNotFound
		return err
	}

	return tx.Commit()
}
