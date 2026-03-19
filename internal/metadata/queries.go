package metadata

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// AccessKeyRecord holds the database record for an access key retrieved from the DB.
// SecretCiphertext is AES-256-GCM encrypted; callers must use auth.DecryptSecret to
// obtain the plaintext. Per security-model.md section 4.2.
type AccessKeyRecord struct {
	AccessKey        string
	SecretCiphertext string     // AES-256-GCM ciphertext; never log or display
	Status           string     // "active" or "inactive"
	IsRoot           bool
	Description      string
	CreatedAt        time.Time
	LastUsedAt       *time.Time // nil if never used
}

// ErrAccessKeyNotFound is returned by LookupAccessKey when no matching record exists.
var ErrAccessKeyNotFound = errors.New("access key not found")

// Bootstrap atomically inserts the initial admin user and root access key.
// Both records are created in a single transaction: either both succeed or neither.
// Per security-model.md section 3.2: bootstrap is a one-time atomic operation.
//
// Preconditions (enforced by callers, not this function):
//   - passwordHash must be an argon2id hash — never plaintext.
//   - secretCiphertext must be AES-256-GCM encrypted — never plaintext.
func (db *DB) Bootstrap(adminUsername, passwordHash, accessKeyID, secretCiphertext string) error {
	tx, err := db.sqldb.Begin()
	if err != nil {
		return fmt.Errorf("beginning bootstrap transaction: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)

	_, err = tx.Exec(
		"INSERT INTO ui_users (username, password_hash, role, created_at) VALUES (?, ?, 'admin', ?)",
		adminUsername, passwordHash, now,
	)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("inserting admin user %q: %w", adminUsername, err)
	}

	_, err = tx.Exec(
		"INSERT INTO access_keys (access_key, secret_ciphertext, status, is_root, created_at) VALUES (?, ?, 'active', 1, ?)",
		accessKeyID, secretCiphertext, now,
	)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("inserting root access key %q: %w", accessKeyID, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing bootstrap transaction: %w", err)
	}

	return nil
}

// LookupAccessKey retrieves an access key record by its access key ID.
// Returns ErrAccessKeyNotFound when no matching record exists.
// The returned SecretCiphertext must be decrypted with auth.DecryptSecret before use.
// Per security-model.md section 4.2: inactive keys must not be used for authentication.
func (db *DB) LookupAccessKey(accessKeyID string) (*AccessKeyRecord, error) {
	var rec AccessKeyRecord
	var isRoot int
	var createdAt string
	var lastUsedAt sql.NullString

	err := db.sqldb.QueryRow(`
		SELECT access_key, secret_ciphertext, status, is_root, description, created_at, last_used_at
		FROM access_keys WHERE access_key = ?`,
		accessKeyID,
	).Scan(&rec.AccessKey, &rec.SecretCiphertext, &rec.Status, &isRoot, &rec.Description, &createdAt, &lastUsedAt)

	if err == sql.ErrNoRows {
		return nil, ErrAccessKeyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("looking up access key %q: %w", accessKeyID, err)
	}

	rec.IsRoot = isRoot != 0

	if t, parseErr := time.Parse(time.RFC3339, createdAt); parseErr == nil {
		rec.CreatedAt = t
	}
	if lastUsedAt.Valid {
		if t, parseErr := time.Parse(time.RFC3339, lastUsedAt.String); parseErr == nil {
			rec.LastUsedAt = &t
		}
	}

	return &rec, nil
}

// TouchAccessKeyLastUsed updates the last_used_at timestamp for the given access key.
// Intended to be called after successful SigV4 authentication.
// Per security-model.md section 5.1.
func (db *DB) TouchAccessKeyLastUsed(accessKeyID string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := db.sqldb.Exec(
		"UPDATE access_keys SET last_used_at = ? WHERE access_key = ?",
		now, accessKeyID,
	); err != nil {
		return fmt.Errorf("updating last_used_at for key %q: %w", accessKeyID, err)
	}
	return nil
}
