package metadata

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOpen_CreatesSchema(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	ver, err := db.SchemaVersion()
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if ver != currentSchemaVersion {
		t.Errorf("schema version: got %d, want %d", ver, currentSchemaVersion)
	}
}

func TestOpen_Idempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	db1, err := Open(path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	db1.Close()

	db2, err := Open(path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer db2.Close()

	ver, err := db2.SchemaVersion()
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if ver != currentSchemaVersion {
		t.Errorf("schema version after reopen: got %d, want %d", ver, currentSchemaVersion)
	}
}

// ---- IsBootstrapped tests ----
// Per security-model.md section 3.1 and configuration-model.md section 6:
// bootstrapped = admin user in ui_users AND active root key in access_keys.
// Partial state (either alone) must NOT be considered bootstrapped.

func TestIsBootstrapped_NewDB(t *testing.T) {
	db := openTestDB(t)
	bootstrapped, err := db.IsBootstrapped()
	if err != nil {
		t.Fatalf("IsBootstrapped: %v", err)
	}
	if bootstrapped {
		t.Error("expected new DB to not be bootstrapped")
	}
}

func TestIsBootstrapped_OnlyUIUser(t *testing.T) {
	// User exists but no active root access key → partial init, not bootstrapped.
	db := openTestDB(t)
	insertUIUser(t, db, "admin")

	bootstrapped, err := db.IsBootstrapped()
	if err != nil {
		t.Fatalf("IsBootstrapped: %v", err)
	}
	if bootstrapped {
		t.Error("expected DB with only UI user (no root key) to not be bootstrapped")
	}
}

func TestIsBootstrapped_OnlyAccessKey(t *testing.T) {
	// Root key exists but no admin user → partial init, not bootstrapped.
	db := openTestDB(t)
	insertActiveRootKey(t, db, "AKIAROOT")

	bootstrapped, err := db.IsBootstrapped()
	if err != nil {
		t.Fatalf("IsBootstrapped: %v", err)
	}
	if bootstrapped {
		t.Error("expected DB with only root key (no UI user) to not be bootstrapped")
	}
}

func TestIsBootstrapped_UserPlusNonRootKey(t *testing.T) {
	// Admin user + non-root key: not bootstrapped (requires active ROOT key).
	db := openTestDB(t)
	insertUIUser(t, db, "admin")
	_, err := db.sqldb.Exec(
		"INSERT INTO access_keys (access_key, secret_ciphertext, status, is_root, created_at) VALUES (?, ?, 'active', 0, datetime('now'))",
		"AKIANORMAL", "enc:placeholder",
	)
	if err != nil {
		t.Fatalf("inserting non-root access_key: %v", err)
	}

	bootstrapped, err := db.IsBootstrapped()
	if err != nil {
		t.Fatalf("IsBootstrapped: %v", err)
	}
	if bootstrapped {
		t.Error("expected DB with user + non-root key to not be bootstrapped")
	}
}

func TestIsBootstrapped_UserPlusInactiveRootKey(t *testing.T) {
	// Admin user + inactive root key: not bootstrapped (key must be active).
	db := openTestDB(t)
	insertUIUser(t, db, "admin")
	_, err := db.sqldb.Exec(
		"INSERT INTO access_keys (access_key, secret_ciphertext, status, is_root, created_at) VALUES (?, ?, 'inactive', 1, datetime('now'))",
		"AKIAROOT", "enc:placeholder",
	)
	if err != nil {
		t.Fatalf("inserting inactive root access_key: %v", err)
	}

	bootstrapped, err := db.IsBootstrapped()
	if err != nil {
		t.Fatalf("IsBootstrapped: %v", err)
	}
	if bootstrapped {
		t.Error("expected DB with user + inactive root key to not be bootstrapped")
	}
}

func TestIsBootstrapped_FullyBootstrapped(t *testing.T) {
	// Both admin user AND active root key → bootstrapped.
	db := openTestDB(t)
	insertUIUser(t, db, "admin")
	insertActiveRootKey(t, db, "AKIAROOT")

	bootstrapped, err := db.IsBootstrapped()
	if err != nil {
		t.Fatalf("IsBootstrapped: %v", err)
	}
	if !bootstrapped {
		t.Error("expected DB with admin user + active root key to be bootstrapped")
	}
}

// insertUIUser inserts a placeholder admin user (role='admin') for testing.
func insertUIUser(t *testing.T, db *DB, username string) {
	t.Helper()
	_, err := db.sqldb.Exec(
		"INSERT INTO ui_users (username, password_hash, role, created_at) VALUES (?, ?, 'admin', datetime('now'))",
		username, "$argon2id$placeholder",
	)
	if err != nil {
		t.Fatalf("insertUIUser(%q): %v", username, err)
	}
}

// insertNonAdminUser inserts a placeholder user with role='viewer' for testing.
// Used to verify that non-admin users are not counted towards bootstrap.
func insertNonAdminUser(t *testing.T, db *DB, username string) {
	t.Helper()
	_, err := db.sqldb.Exec(
		"INSERT INTO ui_users (username, password_hash, role, created_at) VALUES (?, ?, 'viewer', datetime('now'))",
		username, "$argon2id$placeholder",
	)
	if err != nil {
		t.Fatalf("insertNonAdminUser(%q): %v", username, err)
	}
}

// insertActiveRootKey inserts a placeholder active root access key for testing.
func insertActiveRootKey(t *testing.T, db *DB, accessKey string) {
	t.Helper()
	_, err := db.sqldb.Exec(
		"INSERT INTO access_keys (access_key, secret_ciphertext, status, is_root, created_at) VALUES (?, ?, 'active', 1, datetime('now'))",
		accessKey, "enc:placeholder",
	)
	if err != nil {
		t.Fatalf("insertActiveRootKey(%q): %v", accessKey, err)
	}
}

// ---- BootstrapState tests ----
// Verify that BootstrapState() correctly distinguishes the three states.
// Per security-model.md 3.1 and configuration-model.md 2.2:
// bootstrap input may only be consumed in the Empty state.

func TestBootstrapState_EmptyDB(t *testing.T) {
	db := openTestDB(t)
	state, err := db.BootstrapState()
	if err != nil {
		t.Fatalf("BootstrapState: %v", err)
	}
	if state != DBStateEmpty {
		t.Errorf("expected DBStateEmpty for new DB, got %s", state)
	}
}

func TestBootstrapState_OnlyUIUser_IsPartial(t *testing.T) {
	// Admin user exists but no access keys → partial.
	db := openTestDB(t)
	insertUIUser(t, db, "admin")

	state, err := db.BootstrapState()
	if err != nil {
		t.Fatalf("BootstrapState: %v", err)
	}
	if state != DBStatePartial {
		t.Errorf("expected DBStatePartial (user only), got %s", state)
	}
}

func TestBootstrapState_OnlyAccessKey_IsPartial(t *testing.T) {
	// Root key exists but no admin user → partial.
	db := openTestDB(t)
	insertActiveRootKey(t, db, "AKIAROOT")

	state, err := db.BootstrapState()
	if err != nil {
		t.Fatalf("BootstrapState: %v", err)
	}
	if state != DBStatePartial {
		t.Errorf("expected DBStatePartial (key only), got %s", state)
	}
}

func TestBootstrapState_NonRootKeyWithUser_IsPartial(t *testing.T) {
	// User + non-root key: root key is required for bootstrap; still partial.
	db := openTestDB(t)
	insertUIUser(t, db, "admin")
	_, err := db.sqldb.Exec(
		"INSERT INTO access_keys (access_key, secret_ciphertext, status, is_root, created_at) VALUES (?, ?, 'active', 0, datetime('now'))",
		"AKIANORMAL", "enc:placeholder",
	)
	if err != nil {
		t.Fatalf("inserting non-root key: %v", err)
	}

	state, err := db.BootstrapState()
	if err != nil {
		t.Fatalf("BootstrapState: %v", err)
	}
	if state != DBStatePartial {
		t.Errorf("expected DBStatePartial (user + non-root key), got %s", state)
	}
}

func TestBootstrapState_InactiveRootKeyWithUser_IsPartial(t *testing.T) {
	// User + inactive root key: active root key is required; still partial.
	db := openTestDB(t)
	insertUIUser(t, db, "admin")
	_, err := db.sqldb.Exec(
		"INSERT INTO access_keys (access_key, secret_ciphertext, status, is_root, created_at) VALUES (?, ?, 'inactive', 1, datetime('now'))",
		"AKIAROOT", "enc:placeholder",
	)
	if err != nil {
		t.Fatalf("inserting inactive root key: %v", err)
	}

	state, err := db.BootstrapState()
	if err != nil {
		t.Fatalf("BootstrapState: %v", err)
	}
	if state != DBStatePartial {
		t.Errorf("expected DBStatePartial (user + inactive root key), got %s", state)
	}
}

func TestBootstrapState_FullyBootstrapped(t *testing.T) {
	// User + active root key → bootstrapped.
	db := openTestDB(t)
	insertUIUser(t, db, "admin")
	insertActiveRootKey(t, db, "AKIAROOT")

	state, err := db.BootstrapState()
	if err != nil {
		t.Fatalf("BootstrapState: %v", err)
	}
	if state != DBStateBootstrapped {
		t.Errorf("expected DBStateBootstrapped, got %s", state)
	}
}

func TestBootstrapState_UIUserNonAdminOnly_IsPartial(t *testing.T) {
	// Non-admin user only → totalRows > 0, no admin user → partial.
	// Per security-model.md 3.1: bootstrapped requires role='admin' user.
	db := openTestDB(t)
	insertNonAdminUser(t, db, "viewer-user")

	state, err := db.BootstrapState()
	if err != nil {
		t.Fatalf("BootstrapState: %v", err)
	}
	if state != DBStatePartial {
		t.Errorf("expected DBStatePartial for non-admin user only, got %s", state)
	}
}

func TestBootstrapState_AdminUserPlusActiveRootKey_IsBootstrapped(t *testing.T) {
	// Explicit: role='admin' user + active root key → bootstrapped.
	// Per security-model.md 3.1: bootstrapped = admin user AND active root key.
	db := openTestDB(t)
	insertUIUser(t, db, "admin") // role='admin' explicitly set by helper
	insertActiveRootKey(t, db, "AKIAROOT")

	state, err := db.BootstrapState()
	if err != nil {
		t.Fatalf("BootstrapState: %v", err)
	}
	if state != DBStateBootstrapped {
		t.Errorf("expected DBStateBootstrapped for admin user + active root key, got %s", state)
	}
}

func TestBootstrapState_BucketsExistButNoAuth_IsPartial(t *testing.T) {
	// Bucket data exists but no auth records → not empty, not bootstrapped → partial.
	// Per configuration-model.md 2.2: bootstrap is consumed from an EMPTY metadata DB.
	// A DB with bucket data is not empty even if ui_users and access_keys are empty.
	db := openTestDB(t)
	_, err := db.sqldb.Exec(
		"INSERT INTO buckets (name, created_at) VALUES (?, datetime('now'))",
		"existing-bucket",
	)
	if err != nil {
		t.Fatalf("inserting bucket: %v", err)
	}

	state, err := db.BootstrapState()
	if err != nil {
		t.Fatalf("BootstrapState: %v", err)
	}
	if state != DBStatePartial {
		t.Errorf("expected DBStatePartial when buckets exist but no auth, got %s", state)
	}
}

func TestBootstrapState_MultipartDataExists_IsPartial(t *testing.T) {
	// Multipart upload data exists → not empty → partial.
	// Per configuration-model.md 2.2: bootstrap is consumed from an EMPTY metadata DB.
	db := openTestDB(t)
	// Need a bucket first (FK constraint).
	_, err := db.sqldb.Exec(
		"INSERT INTO buckets (name, created_at) VALUES (?, datetime('now'))",
		"multipart-bucket",
	)
	if err != nil {
		t.Fatalf("inserting bucket: %v", err)
	}
	_, err = db.sqldb.Exec(`
		INSERT INTO multipart_uploads (id, bucket_id, object_key, initiated_at, expires_at)
		VALUES ('upload-id-1', 1, 'test-key', datetime('now'), datetime('now', '+1 day'))
	`)
	if err != nil {
		t.Fatalf("inserting multipart_upload: %v", err)
	}

	state, err := db.BootstrapState()
	if err != nil {
		t.Fatalf("BootstrapState: %v", err)
	}
	if state != DBStatePartial {
		t.Errorf("expected DBStatePartial when multipart data exists, got %s", state)
	}
}

func TestIsBootstrapped_NonAdminUser_NotBootstrapped(t *testing.T) {
	// Non-admin user + active root key → NOT bootstrapped.
	// Per security-model.md 3.1: bootstrapped requires role='admin' user.
	db := openTestDB(t)
	insertNonAdminUser(t, db, "viewer-user")
	insertActiveRootKey(t, db, "AKIAROOT")

	bootstrapped, err := db.IsBootstrapped()
	if err != nil {
		t.Fatalf("IsBootstrapped: %v", err)
	}
	if bootstrapped {
		t.Error("expected non-admin user + root key to NOT be bootstrapped (role='admin' required)")
	}
}

func TestBootstrapState_StringRepresentation(t *testing.T) {
	cases := []struct {
		state DBState
		want  string
	}{
		{DBStateEmpty, "empty"},
		{DBStatePartial, "partial"},
		{DBStateBootstrapped, "bootstrapped"},
	}
	for _, tc := range cases {
		if got := tc.state.String(); got != tc.want {
			t.Errorf("DBState(%d).String() = %q, want %q", int(tc.state), got, tc.want)
		}
	}
}

func TestIntegrityCheck_CleanDB(t *testing.T) {
	db := openTestDB(t)
	if err := db.IntegrityCheck(nil); err != nil {
		t.Errorf("IntegrityCheck on clean DB: %v", err)
	}
}

func TestStartupRecovery_CleanSlatePasses(t *testing.T) {
	dir := t.TempDir()
	db := openTestDB(t)
	cfg := RecoveryConfig{
		TempRoot:      dir,
		ObjectRoot:    dir,
		MultipartRoot: dir,
	}
	if err := StartupRecovery(db, cfg); err != nil {
		t.Fatalf("StartupRecovery on clean slate: %v", err)
	}
}

func TestStartupRecovery_RemovesStaleTempFiles(t *testing.T) {
	// With OrphanGracePeriod=0, all matching temp files are removed regardless of age.
	dir := t.TempDir()

	stale := filepath.Join(dir, ".hemmins-upload-staletest")
	if err := os.WriteFile(stale, []byte("junk"), 0600); err != nil {
		t.Fatalf("creating stale temp file: %v", err)
	}

	db := openTestDB(t)
	// OrphanGracePeriod zero value: remove all matching temp files.
	cfg := RecoveryConfig{TempRoot: dir, ObjectRoot: dir, MultipartRoot: dir}
	if err := StartupRecovery(db, cfg); err != nil {
		t.Fatalf("StartupRecovery: %v", err)
	}

	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Error("expected stale temp file to be removed after StartupRecovery (grace period = 0)")
	}
}

func TestStartupRecovery_RespectsGracePeriod_PreservesRecentFile(t *testing.T) {
	// With OrphanGracePeriod > 0, a fresh temp file (age < grace period) must NOT be removed.
	// Per operations-runbook.md section 4.1: "temp_root files → orphan candidate after grace period".
	dir := t.TempDir()

	fresh := filepath.Join(dir, ".hemmins-upload-freshfile")
	if err := os.WriteFile(fresh, []byte("junk"), 0600); err != nil {
		t.Fatalf("creating fresh temp file: %v", err)
	}

	db := openTestDB(t)
	cfg := RecoveryConfig{
		TempRoot:          dir,
		ObjectRoot:        dir,
		MultipartRoot:     dir,
		OrphanGracePeriod: time.Hour, // file just created → age << 1h → must be preserved
	}
	if err := StartupRecovery(db, cfg); err != nil {
		t.Fatalf("StartupRecovery: %v", err)
	}

	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("fresh temp file should be preserved within grace period: %v", err)
	}
}

func TestStartupRecovery_RespectsGracePeriod_RemovesOldFile(t *testing.T) {
	// With OrphanGracePeriod > 0, a file older than the grace period MUST be removed.
	dir := t.TempDir()

	old := filepath.Join(dir, ".hemmins-upload-oldfile")
	if err := os.WriteFile(old, []byte("junk"), 0600); err != nil {
		t.Fatalf("creating old temp file: %v", err)
	}
	// Backdate the file to 2 hours ago (beyond the 1h grace period).
	twoHoursAgo := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(old, twoHoursAgo, twoHoursAgo); err != nil {
		t.Fatalf("backdating temp file: %v", err)
	}

	db := openTestDB(t)
	cfg := RecoveryConfig{
		TempRoot:          dir,
		ObjectRoot:        dir,
		MultipartRoot:     dir,
		OrphanGracePeriod: time.Hour,
	}
	if err := StartupRecovery(db, cfg); err != nil {
		t.Fatalf("StartupRecovery: %v", err)
	}

	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("expected old temp file (beyond grace period) to be removed")
	}
}

func TestStartupRecovery_PreservesNonTempFiles(t *testing.T) {
	dir := t.TempDir()

	keep := filepath.Join(dir, "important.blob")
	if err := os.WriteFile(keep, []byte("data"), 0600); err != nil {
		t.Fatalf("creating test blob: %v", err)
	}

	db := openTestDB(t)
	cfg := RecoveryConfig{TempRoot: dir, ObjectRoot: dir, MultipartRoot: dir}
	if err := StartupRecovery(db, cfg); err != nil {
		t.Fatalf("StartupRecovery: %v", err)
	}

	if _, err := os.Stat(keep); err != nil {
		t.Errorf("non-temp file was incorrectly removed: %v", err)
	}
}

func TestMarkMissingBlobsCorrupt(t *testing.T) {
	db := openTestDB(t)

	_, err := db.sqldb.Exec(
		"INSERT INTO buckets (name, created_at) VALUES (?, datetime('now'))",
		"test-bucket",
	)
	if err != nil {
		t.Fatalf("inserting bucket: %v", err)
	}

	_, err = db.sqldb.Exec(`
		INSERT INTO objects (bucket_id, object_key, storage_path, last_modified)
		VALUES (1, 'missing-blob.txt', '/nonexistent/path/object.blob', datetime('now'))`,
	)
	if err != nil {
		t.Fatalf("inserting object: %v", err)
	}

	if err := markMissingBlobsCorrupt(db); err != nil {
		t.Fatalf("markMissingBlobsCorrupt: %v", err)
	}

	var isCorrupt int
	err = db.sqldb.QueryRow(
		"SELECT is_corrupt FROM objects WHERE object_key = 'missing-blob.txt'",
	).Scan(&isCorrupt)
	if err != nil {
		t.Fatalf("querying is_corrupt: %v", err)
	}
	if isCorrupt != 1 {
		t.Errorf("expected is_corrupt=1, got %d", isCorrupt)
	}
}

// ---- LookupAccessKey tests (requirement: metadata lookup returns expected key record) ----

func TestLookupAccessKey_ReturnsExpectedRecord(t *testing.T) {
	db := openTestDB(t)

	const (
		wantAccessKey  = "AKIATESTLOOKUP0001"
		wantCiphertext = "v1:nonce123:ciphertext456"
		wantStatus     = "active"
		wantIsRoot     = true
		wantDesc       = "test root key"
	)

	_, err := db.sqldb.Exec(`
		INSERT INTO access_keys (access_key, secret_ciphertext, status, is_root, description, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		wantAccessKey, wantCiphertext, wantStatus, 1, wantDesc, "2024-01-01T00:00:00Z",
	)
	if err != nil {
		t.Fatalf("inserting access key: %v", err)
	}

	rec, err := db.LookupAccessKey(wantAccessKey)
	if err != nil {
		t.Fatalf("LookupAccessKey: %v", err)
	}

	if rec.AccessKey != wantAccessKey {
		t.Errorf("AccessKey: got %q, want %q", rec.AccessKey, wantAccessKey)
	}
	if rec.SecretCiphertext != wantCiphertext {
		t.Errorf("SecretCiphertext: got %q, want %q", rec.SecretCiphertext, wantCiphertext)
	}
	if rec.Status != wantStatus {
		t.Errorf("Status: got %q, want %q", rec.Status, wantStatus)
	}
	if rec.IsRoot != wantIsRoot {
		t.Errorf("IsRoot: got %v, want %v", rec.IsRoot, wantIsRoot)
	}
	if rec.Description != wantDesc {
		t.Errorf("Description: got %q, want %q", rec.Description, wantDesc)
	}
	if rec.LastUsedAt != nil {
		t.Errorf("LastUsedAt: expected nil for key never used, got %v", rec.LastUsedAt)
	}
	if rec.CreatedAt.IsZero() {
		t.Error("CreatedAt: expected non-zero time, got zero")
	}
}

func TestLookupAccessKey_NotFound(t *testing.T) {
	db := openTestDB(t)

	_, err := db.LookupAccessKey("AKIADOESNOTEXIST")
	if err == nil {
		t.Fatal("expected ErrAccessKeyNotFound, got nil")
	}
	if !errors.Is(err, ErrAccessKeyNotFound) {
		t.Errorf("expected ErrAccessKeyNotFound, got %v", err)
	}
}

func TestLookupAccessKey_InactiveKey_FieldReturned(t *testing.T) {
	// Inactive keys are returned by LookupAccessKey; the CALLER (Verifier) decides to reject them.
	// Per security-model.md 5.1: the DB layer must return the status faithfully.
	db := openTestDB(t)

	_, err := db.sqldb.Exec(`
		INSERT INTO access_keys (access_key, secret_ciphertext, status, is_root, created_at)
		VALUES ('AKIAINACTIVE', 'v1:n:c', 'inactive', 0, '2024-01-01T00:00:00Z')`)
	if err != nil {
		t.Fatalf("inserting inactive key: %v", err)
	}

	rec, err := db.LookupAccessKey("AKIAINACTIVE")
	if err != nil {
		t.Fatalf("LookupAccessKey: %v", err)
	}
	if rec.Status != "inactive" {
		t.Errorf("Status: got %q, want %q", rec.Status, "inactive")
	}
}

func TestTouchAccessKeyLastUsed_UpdatesTimestamp(t *testing.T) {
	db := openTestDB(t)

	const keyID = "AKIATOUCH0001"
	_, err := db.sqldb.Exec(`
		INSERT INTO access_keys (access_key, secret_ciphertext, status, is_root, created_at)
		VALUES (?, 'v1:n:c', 'active', 0, '2024-01-01T00:00:00Z')`, keyID)
	if err != nil {
		t.Fatalf("inserting access key: %v", err)
	}

	// Before touching: last_used_at should be NULL.
	rec, err := db.LookupAccessKey(keyID)
	if err != nil {
		t.Fatalf("LookupAccessKey before touch: %v", err)
	}
	if rec.LastUsedAt != nil {
		t.Errorf("LastUsedAt before touch: expected nil, got %v", rec.LastUsedAt)
	}

	if err := db.TouchAccessKeyLastUsed(keyID); err != nil {
		t.Fatalf("TouchAccessKeyLastUsed: %v", err)
	}

	// After touching: last_used_at should be set.
	rec2, err := db.LookupAccessKey(keyID)
	if err != nil {
		t.Fatalf("LookupAccessKey after touch: %v", err)
	}
	if rec2.LastUsedAt == nil {
		t.Error("LastUsedAt after touch: expected non-nil, got nil")
	}
}

// openTestDB creates a fresh in-memory SQLite DB for each test.
func openTestDB(t *testing.T) *DB {
	t.Helper()
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("openTestDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}
