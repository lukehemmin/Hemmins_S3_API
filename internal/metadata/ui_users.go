package metadata

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrUserNotFound is returned by LookupUIUser when no matching user exists.
// The HTTP layer maps this to a generic 401 — do not distinguish from wrong password.
var ErrUserNotFound = errors.New("ui user not found")

// UIUserRecord holds the fields from ui_users needed for session authentication.
// PasswordHash is an argon2id hash; callers must use auth.VerifyPassword.
// Per system-architecture.md section 4.6 and security-model.md section 4.1.
type UIUserRecord struct {
	Username     string
	PasswordHash string // argon2id; never log or display
	Role         string
}

// LookupUIUser retrieves the ui_users row for username.
// Returns ErrUserNotFound if no such user exists.
// The HTTP layer must call auth.VerifyPassword to validate the submitted password.
// Per security-model.md section 4.1: password plaintext must never be stored or returned.
func (db *DB) LookupUIUser(username string) (*UIUserRecord, error) {
	var rec UIUserRecord
	err := db.sqldb.QueryRow(
		"SELECT username, password_hash, role FROM ui_users WHERE username = ?",
		username,
	).Scan(&rec.Username, &rec.PasswordHash, &rec.Role)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("looking up ui user %q: %w", username, err)
	}
	return &rec, nil
}

// TouchUIUserLastLogin updates the last_login_at timestamp for username.
// Called after successful login to maintain audit trail.
// Per security-model.md section 8: login success is an auditable event.
func (db *DB) TouchUIUserLastLogin(username string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := db.sqldb.Exec(
		"UPDATE ui_users SET last_login_at = ? WHERE username = ?",
		now, username,
	); err != nil {
		return fmt.Errorf("updating last_login_at for user %q: %w", username, err)
	}
	return nil
}
