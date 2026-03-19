package metadata

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// DB wraps a SQLite database connection with metadata-specific methods.
type DB struct {
	sqldb *sql.DB
	path  string
}

// Open opens (or creates) the SQLite metadata database at path.
// Sets WAL journal mode, synchronous=FULL, foreign keys, and busy_timeout.
// Runs schema migration to bring the database up to currentSchemaVersion.
// Per system-architecture.md sections 2.1 and 6.1.
func Open(path string) (*DB, error) {
	sqldb, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite database at %q: %w", path, err)
	}

	// SQLite requires single-writer serialization; limit to one connection.
	sqldb.SetMaxOpenConns(1)

	db := &DB{sqldb: sqldb, path: path}

	if err := db.configurePragmas(); err != nil {
		sqldb.Close()
		return nil, fmt.Errorf("configuring database pragmas: %w", err)
	}

	if err := db.migrate(); err != nil {
		sqldb.Close()
		return nil, fmt.Errorf("migrating database schema: %w", err)
	}

	return db, nil
}

// configurePragmas sets the required SQLite pragmas for durability and correctness.
func (db *DB) configurePragmas() error {
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=FULL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
	}
	for _, p := range pragmas {
		if _, err := db.sqldb.Exec(p); err != nil {
			return fmt.Errorf("executing %q: %w", p, err)
		}
	}
	return nil
}

// migrate applies any pending schema migrations.
func (db *DB) migrate() error {
	if _, err := db.sqldb.Exec(createSchemaVersionTable); err != nil {
		return fmt.Errorf("creating schema_version table: %w", err)
	}

	var version int
	if err := db.sqldb.QueryRow(
		"SELECT COALESCE(MAX(version), 0) FROM schema_version",
	).Scan(&version); err != nil {
		return fmt.Errorf("reading current schema version: %w", err)
	}

	if version >= currentSchemaVersion {
		return nil
	}

	tx, err := db.sqldb.Begin()
	if err != nil {
		return fmt.Errorf("beginning migration transaction: %w", err)
	}

	if _, err := tx.Exec(schemaV1); err != nil {
		tx.Rollback()
		return fmt.Errorf("applying schema v1: %w", err)
	}

	if _, err := tx.Exec(
		"INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
		currentSchemaVersion, time.Now().UTC().Format(time.RFC3339),
	); err != nil {
		tx.Rollback()
		return fmt.Errorf("recording schema version %d: %w", currentSchemaVersion, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing schema migration: %w", err)
	}

	return nil
}

// DBState describes the initialization state of the metadata database.
// Per security-model.md section 3.1 and configuration-model.md section 2.2:
// bootstrap input is only consumed when the DB is in the Empty state.
type DBState int

const (
	// DBStateEmpty means all metadata tables are empty (ui_users, access_keys,
	// buckets, objects, multipart_uploads, and multipart_parts all have zero rows).
	// Bootstrap input may be consumed ONLY in this state.
	// Per configuration-model.md 2.2: bootstrap is consumed from an empty metadata DB.
	DBStateEmpty DBState = iota

	// DBStatePartial means some credential records exist but bootstrap is not
	// complete (e.g. admin user without a root key, or vice versa).
	// This is an inconsistent state that requires operator intervention.
	// Bootstrap input must NOT be consumed in this state.
	DBStatePartial

	// DBStateBootstrapped means the database is fully initialized:
	// at least one admin user and at least one active root access key exist.
	DBStateBootstrapped
)

// String returns a human-readable label for logging.
func (s DBState) String() string {
	switch s {
	case DBStateEmpty:
		return "empty"
	case DBStatePartial:
		return "partial"
	case DBStateBootstrapped:
		return "bootstrapped"
	default:
		return fmt.Sprintf("unknown(%d)", int(s))
	}
}

// BootstrapState returns the database's initialization state.
// It distinguishes between three states:
//   - DBStateEmpty: all metadata tables are empty; bootstrap input may be applied.
//   - DBStatePartial: some records exist but bootstrap is not complete;
//     this is an inconsistent state requiring operator intervention.
//   - DBStateBootstrapped: at least one admin user (role='admin') AND at least
//     one active root access key exist; server is ready.
//
// Per security-model.md section 3.1 and configuration-model.md section 2.2:
// bootstrap input is consumed ONLY when the DB is in DBStateEmpty.
// "empty" means all six content tables have zero rows, not just the auth tables.
func (db *DB) BootstrapState() (DBState, error) {
	// Check whether the entire metadata DB is empty.
	// All six content tables must be zero for DBStateEmpty.
	// Per configuration-model.md 2.2: bootstrap is consumed from an empty metadata DB.
	var totalRows int
	if err := db.sqldb.QueryRow(`
		SELECT
			(SELECT COUNT(*) FROM ui_users) +
			(SELECT COUNT(*) FROM access_keys) +
			(SELECT COUNT(*) FROM buckets) +
			(SELECT COUNT(*) FROM objects) +
			(SELECT COUNT(*) FROM multipart_uploads) +
			(SELECT COUNT(*) FROM multipart_parts)
	`).Scan(&totalRows); err != nil {
		return DBStateEmpty, fmt.Errorf("counting total metadata rows: %w", err)
	}
	if totalRows == 0 {
		return DBStateEmpty, nil
	}

	// Some data exists; check whether fully bootstrapped.
	// Per security-model.md 3.1: bootstrapped = admin user (role='admin') AND active root key.
	var adminCount int
	if err := db.sqldb.QueryRow(
		"SELECT COUNT(*) FROM ui_users WHERE role = 'admin'",
	).Scan(&adminCount); err != nil {
		return DBStatePartial, fmt.Errorf("counting admin users: %w", err)
	}

	var rootKeyCount int
	if err := db.sqldb.QueryRow(
		"SELECT COUNT(*) FROM access_keys WHERE is_root = 1 AND status = 'active'",
	).Scan(&rootKeyCount); err != nil {
		return DBStatePartial, fmt.Errorf("counting active root access_keys: %w", err)
	}

	if adminCount > 0 && rootKeyCount > 0 {
		return DBStateBootstrapped, nil
	}

	return DBStatePartial, nil
}

// IsBootstrapped reports whether the database has been fully initialized.
// Per security-model.md section 3.1 and configuration-model.md section 6,
// bootstrap is complete only when BOTH conditions hold:
//   - at least one admin user (role = 'admin') exists in ui_users, AND
//   - at least one active root-scoped access key exists in access_keys
//
// Non-admin users (e.g. role = 'viewer') are not counted towards bootstrap.
// Partial initialization (user only, or key only) is treated as not bootstrapped.
// A server in a non-bootstrapped state must remain in setup-required state and
// must not serve S3 API requests.
func (db *DB) IsBootstrapped() (bool, error) {
	var adminCount int
	if err := db.sqldb.QueryRow(
		"SELECT COUNT(*) FROM ui_users WHERE role = 'admin'",
	).Scan(&adminCount); err != nil {
		return false, fmt.Errorf("counting admin users: %w", err)
	}
	if adminCount == 0 {
		return false, nil
	}

	var rootKeyCount int
	if err := db.sqldb.QueryRow(
		"SELECT COUNT(*) FROM access_keys WHERE is_root = 1 AND status = 'active'",
	).Scan(&rootKeyCount); err != nil {
		return false, fmt.Errorf("counting active root access_keys: %w", err)
	}
	return rootKeyCount > 0, nil
}

// IntegrityCheck runs SQLite's integrity_check pragma.
// Returns an error if the database is corrupt.
// Per system-architecture.md section 6.3: integrity_check failure → readiness failure.
func (db *DB) IntegrityCheck(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	rows, err := db.sqldb.QueryContext(ctx, "PRAGMA integrity_check")
	if err != nil {
		return fmt.Errorf("running integrity_check: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var result string
		if err := rows.Scan(&result); err != nil {
			return fmt.Errorf("scanning integrity_check result: %w", err)
		}
		if result != "ok" {
			return fmt.Errorf("integrity_check: %s", result)
		}
	}
	return rows.Err()
}

// SchemaVersion returns the current schema version stored in the database.
func (db *DB) SchemaVersion() (int, error) {
	var version int
	err := db.sqldb.QueryRow(
		"SELECT COALESCE(MAX(version), 0) FROM schema_version",
	).Scan(&version)
	return version, err
}

// SQLDB returns the underlying *sql.DB for use by other packages.
func (db *DB) SQLDB() *sql.DB {
	return db.sqldb
}

// Close closes the database connection.
func (db *DB) Close() error {
	return db.sqldb.Close()
}
