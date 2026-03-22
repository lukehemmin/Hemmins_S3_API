package metadata

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
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

// AccessKeySummary holds a safe-to-display summary of an access key.
// Per security-model.md section 4.2: secretCiphertext must NEVER be included in API responses.
type AccessKeySummary struct {
	AccessKey   string     `json:"accessKey"`
	Status      string     `json:"status"`
	IsRoot      bool       `json:"isRoot"`
	Description string     `json:"description"`
	CreatedAt   time.Time  `json:"createdAt"`
	LastUsedAt  *time.Time `json:"lastUsedAt"` // nil if never used
}

// ListAccessKeys returns all access keys sorted by created_at ASC, then access_key ASC.
// The sort order is deterministic and pinned by tests.
// Per security-model.md section 4.2: secret_ciphertext is never returned.
func (db *DB) ListAccessKeys() ([]AccessKeySummary, error) {
	rows, err := db.sqldb.Query(`
		SELECT access_key, status, is_root, description, created_at, last_used_at
		FROM access_keys
		ORDER BY created_at ASC, access_key ASC`)
	if err != nil {
		return nil, fmt.Errorf("listing access keys: %w", err)
	}
	defer rows.Close()

	var result []AccessKeySummary
	for rows.Next() {
		var summary AccessKeySummary
		var isRoot int
		var createdAt string
		var lastUsedAt sql.NullString

		if err := rows.Scan(&summary.AccessKey, &summary.Status, &isRoot, &summary.Description, &createdAt, &lastUsedAt); err != nil {
			return nil, fmt.Errorf("scanning access key row: %w", err)
		}

		summary.IsRoot = isRoot != 0

		if t, parseErr := time.Parse(time.RFC3339, createdAt); parseErr == nil {
			summary.CreatedAt = t
		}
		if lastUsedAt.Valid {
			if t, parseErr := time.Parse(time.RFC3339, lastUsedAt.String); parseErr == nil {
				summary.LastUsedAt = &t
			}
		}

		result = append(result, summary)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating access keys: %w", err)
	}

	// Return empty slice (not nil) for consistency.
	if result == nil {
		result = []AccessKeySummary{}
	}
	return result, nil
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

// ErrNoRootAccessKey is returned when no root access key exists in the database.
var ErrNoRootAccessKey = errors.New("no root access key found")

// ErrAccessKeyAlreadyExists is returned by CreateAccessKey when the access_key already exists.
var ErrAccessKeyAlreadyExists = errors.New("access key already exists")

// CreateAccessKey inserts a new non-root access key into the database.
// The secretCiphertext must already be encrypted with auth.EncryptSecret.
// Per security-model.md section 4.2: plaintext secrets must never be stored.
// Per security-model.md section 5.1: key creation is an auditable event.
func (db *DB) CreateAccessKey(accessKeyID, secretCiphertext, description string) (*AccessKeySummary, error) {
	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)

	_, err := db.sqldb.Exec(`
		INSERT INTO access_keys (access_key, secret_ciphertext, status, is_root, description, created_at)
		VALUES (?, ?, 'active', 0, ?, ?)`,
		accessKeyID, secretCiphertext, description, nowStr,
	)
	if err != nil {
		// Check for unique constraint violation.
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return nil, ErrAccessKeyAlreadyExists
		}
		return nil, fmt.Errorf("inserting access key %q: %w", accessKeyID, err)
	}

	return &AccessKeySummary{
		AccessKey:   accessKeyID,
		Status:      "active",
		IsRoot:      false,
		Description: description,
		CreatedAt:   now,
		LastUsedAt:  nil,
	}, nil
}

// GetRootAccessKey retrieves the root access key record (is_root=1, status='active').
// Returns ErrNoRootAccessKey if no active root key exists.
// Per security-model.md section 8.1: there must always be at least one active root key.
func (db *DB) GetRootAccessKey() (*AccessKeyRecord, error) {
	var rec AccessKeyRecord
	var isRoot int
	var createdAt string
	var lastUsedAt sql.NullString

	err := db.sqldb.QueryRow(`
		SELECT access_key, secret_ciphertext, status, is_root, description, created_at, last_used_at
		FROM access_keys WHERE is_root = 1 AND status = 'active'
		LIMIT 1`,
	).Scan(&rec.AccessKey, &rec.SecretCiphertext, &rec.Status, &isRoot, &rec.Description, &createdAt, &lastUsedAt)

	if err == sql.ErrNoRows {
		return nil, ErrNoRootAccessKey
	}
	if err != nil {
		return nil, fmt.Errorf("looking up root access key: %w", err)
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

// ErrCannotRevokeRootKey is returned when attempting to revoke a root access key.
// Per security-model.md section 5.1: at least one active root-scoped key must be maintained.
var ErrCannotRevokeRootKey = errors.New("cannot revoke root access key")

// RevokeAccessKey sets the status of the specified access key to "inactive".
// Returns ErrAccessKeyNotFound if the key does not exist.
// Returns ErrCannotRevokeRootKey if the key is a root key (is_root=1).
// If the key is already inactive, this is idempotent (returns success).
// Per security-model.md section 5.1: key deactivation is an auditable event.
func (db *DB) RevokeAccessKey(accessKeyID string) (*AccessKeySummary, error) {
	// First, look up the key to check existence and is_root.
	rec, err := db.LookupAccessKey(accessKeyID)
	if err != nil {
		return nil, err // includes ErrAccessKeyNotFound
	}

	// Reject revocation of root keys.
	// Per security-model.md section 5.1: at least one active root-scoped key must be maintained.
	if rec.IsRoot {
		return nil, ErrCannotRevokeRootKey
	}

	// Update status to inactive (idempotent if already inactive).
	_, err = db.sqldb.Exec(
		"UPDATE access_keys SET status = 'inactive' WHERE access_key = ?",
		accessKeyID,
	)
	if err != nil {
		return nil, fmt.Errorf("revoking access key %q: %w", accessKeyID, err)
	}

	// Return updated summary.
	return &AccessKeySummary{
		AccessKey:   rec.AccessKey,
		Status:      "inactive",
		IsRoot:      rec.IsRoot,
		Description: rec.Description,
		CreatedAt:   rec.CreatedAt,
		LastUsedAt:  rec.LastUsedAt,
	}, nil
}

// ErrCannotDeleteRootKey is returned when attempting to delete a root access key.
// Per security-model.md section 5.1: root keys cannot be deleted via this API.
var ErrCannotDeleteRootKey = errors.New("cannot delete root access key")

// ErrCannotDeleteActiveKey is returned when attempting to delete an active (non-revoked) key.
// Per security-model.md section 5.1: key rotation procedure requires revocation before deletion.
var ErrCannotDeleteActiveKey = errors.New("cannot delete active access key; revoke first")

// DeleteAccessKey permanently removes an access key from the database.
// Returns ErrAccessKeyNotFound if the key does not exist.
// Returns ErrCannotDeleteRootKey if the key is a root key (is_root=1).
// Returns ErrCannotDeleteActiveKey if the key is still active (status='active').
// Per security-model.md section 5.1: delete is only allowed for inactive non-root keys.
// Per security-model.md section 8: key deletion is an auditable event.
func (db *DB) DeleteAccessKey(accessKeyID string) error {
	// First, look up the key to check existence, is_root, and status.
	rec, err := db.LookupAccessKey(accessKeyID)
	if err != nil {
		return err // includes ErrAccessKeyNotFound
	}

	// Reject deletion of root keys.
	// Per security-model.md section 5.1: root keys cannot be deleted via this API.
	if rec.IsRoot {
		return ErrCannotDeleteRootKey
	}

	// Reject deletion of active keys.
	// Per security-model.md section 5.1: key rotation requires revoke → delete order.
	if rec.Status == "active" {
		return ErrCannotDeleteActiveKey
	}

	// Delete the key row.
	result, err := db.sqldb.Exec(
		"DELETE FROM access_keys WHERE access_key = ?",
		accessKeyID,
	)
	if err != nil {
		return fmt.Errorf("deleting access key %q: %w", accessKeyID, err)
	}

	// Verify row was actually deleted (defensive check).
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrAccessKeyNotFound
	}

	return nil
}
