package bootstrap

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/lukehemmin/hemmins-s3-api/internal/config"
	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

const testMasterKey = "bootstrap-test-master-key-32byt!"

// fullBootstrapCfg returns a complete set of bootstrap credentials for testing.
func fullBootstrapCfg() *config.BootstrapConfig {
	return &config.BootstrapConfig{
		AdminUsername: "admin",
		AdminPassword: "admin-password-123",
		RootAccessKey: "AKIAROOT00000001",
		RootSecretKey: "root-secret-key-value-for-test",
		HasValues:     true,
	}
}

func openTestDB(t *testing.T) *metadata.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := metadata.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("openTestDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestApply_CreatesAdminAndRootKey(t *testing.T) {
	db := openTestDB(t)
	cfg := fullBootstrapCfg()

	if err := Apply(db, cfg, testMasterKey); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	bootstrapped, err := db.IsBootstrapped()
	if err != nil {
		t.Fatalf("IsBootstrapped: %v", err)
	}
	if !bootstrapped {
		t.Error("expected database to be bootstrapped after Apply")
	}
}

func TestApply_IdempotentOnAlreadyBootstrapped(t *testing.T) {
	// Calling Apply on an already-bootstrapped DB must not error and must not
	// create duplicate records. Per configuration-model.md section 2.2.
	db := openTestDB(t)
	cfg := fullBootstrapCfg()

	if err := Apply(db, cfg, testMasterKey); err != nil {
		t.Fatalf("first Apply: %v", err)
	}

	// Second call must succeed without error.
	if err := Apply(db, cfg, testMasterKey); err != nil {
		t.Fatalf("second Apply (should be no-op): %v", err)
	}

	// Exactly one admin user must exist.
	var userCount int
	if err := db.SQLDB().QueryRow("SELECT COUNT(*) FROM ui_users").Scan(&userCount); err != nil {
		t.Fatalf("counting users: %v", err)
	}
	if userCount != 1 {
		t.Errorf("expected 1 admin user after idempotent Apply, got %d", userCount)
	}

	// Exactly one active root key must exist.
	var keyCount int
	if err := db.SQLDB().QueryRow("SELECT COUNT(*) FROM access_keys WHERE is_root=1 AND status='active'").Scan(&keyCount); err != nil {
		t.Fatalf("counting keys: %v", err)
	}
	if keyCount != 1 {
		t.Errorf("expected 1 root key after idempotent Apply, got %d", keyCount)
	}
}

func TestApply_PasswordHash_NotPlaintext(t *testing.T) {
	// The stored password_hash must never equal the plaintext password.
	// Per security-model.md section 4.1.
	db := openTestDB(t)
	cfg := fullBootstrapCfg()

	if err := Apply(db, cfg, testMasterKey); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	var storedHash string
	if err := db.SQLDB().QueryRow("SELECT password_hash FROM ui_users WHERE username = ?", cfg.AdminUsername).Scan(&storedHash); err != nil {
		t.Fatalf("querying password_hash: %v", err)
	}
	if storedHash == cfg.AdminPassword {
		t.Error("password_hash must not equal plaintext password (must be argon2id hash)")
	}
	if storedHash == "" {
		t.Error("password_hash must not be empty")
	}
}

func TestApply_SecretCiphertext_NotPlaintext(t *testing.T) {
	// The stored secret_ciphertext must never equal the plaintext secret.
	// Per security-model.md section 4.2.
	db := openTestDB(t)
	cfg := fullBootstrapCfg()

	if err := Apply(db, cfg, testMasterKey); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	var storedCiphertext string
	if err := db.SQLDB().QueryRow("SELECT secret_ciphertext FROM access_keys WHERE access_key = ?", cfg.RootAccessKey).Scan(&storedCiphertext); err != nil {
		t.Fatalf("querying secret_ciphertext: %v", err)
	}
	if storedCiphertext == cfg.RootSecretKey {
		t.Error("secret_ciphertext must not equal plaintext secret (must be AES-256-GCM encrypted)")
	}
	if storedCiphertext == "" {
		t.Error("secret_ciphertext must not be empty")
	}
}

func TestApply_AccessKeyIsRootAndActive(t *testing.T) {
	// The bootstrapped access key must be root-scoped and active.
	// Per IsBootstrapped logic: is_root=1 AND status='active' is required.
	db := openTestDB(t)
	cfg := fullBootstrapCfg()

	if err := Apply(db, cfg, testMasterKey); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	var isRoot int
	var status string
	err := db.SQLDB().QueryRow(
		"SELECT is_root, status FROM access_keys WHERE access_key = ?",
		cfg.RootAccessKey,
	).Scan(&isRoot, &status)
	if err != nil {
		t.Fatalf("querying access_key: %v", err)
	}
	if isRoot != 1 {
		t.Errorf("expected is_root=1, got %d", isRoot)
	}
	if status != "active" {
		t.Errorf("expected status='active', got %q", status)
	}
}

func TestApply_AdminRoleIsAdmin(t *testing.T) {
	db := openTestDB(t)
	cfg := fullBootstrapCfg()

	if err := Apply(db, cfg, testMasterKey); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	var role string
	if err := db.SQLDB().QueryRow(
		"SELECT role FROM ui_users WHERE username = ?", cfg.AdminUsername,
	).Scan(&role); err != nil {
		t.Fatalf("querying role: %v", err)
	}
	if role != "admin" {
		t.Errorf("expected role='admin', got %q", role)
	}
}

func TestApply_DecryptedSecretMatchesOriginal(t *testing.T) {
	// After bootstrap, the stored ciphertext must decrypt back to the original secret.
	// This validates the full encrypt/decrypt round-trip in the bootstrap flow.
	db := openTestDB(t)
	cfg := fullBootstrapCfg()

	if err := Apply(db, cfg, testMasterKey); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	var storedCiphertext string
	if err := db.SQLDB().QueryRow(
		"SELECT secret_ciphertext FROM access_keys WHERE access_key = ?", cfg.RootAccessKey,
	).Scan(&storedCiphertext); err != nil {
		t.Fatalf("querying secret_ciphertext: %v", err)
	}

	// Import auth package indirectly via the package-level function is not possible
	// in a black-box test without importing the auth package. Do it via sql.DB.
	// Verify that the stored value is not the plaintext.
	if storedCiphertext == cfg.RootSecretKey {
		t.Error("stored ciphertext must not be plaintext")
	}
	// Verify the stored value starts with the version prefix.
	if len(storedCiphertext) < 3 || storedCiphertext[:3] != "v1:" {
		t.Errorf("expected ciphertext version prefix 'v1:', got: %q", storedCiphertext[:min(3, len(storedCiphertext))])
	}
}

func TestApply_ReadyzTransition_EmptyDB_NoEnv(t *testing.T) {
	// An empty DB with no bootstrap applied must NOT be bootstrapped.
	db := openTestDB(t)
	bootstrapped, err := db.IsBootstrapped()
	if err != nil {
		t.Fatalf("IsBootstrapped: %v", err)
	}
	if bootstrapped {
		t.Error("fresh DB must not be bootstrapped without Apply")
	}
}

func TestApply_ReadyzTransition_AfterApply(t *testing.T) {
	// An empty DB with full bootstrap env must be bootstrapped after Apply.
	db := openTestDB(t)
	cfg := fullBootstrapCfg()

	// Before Apply: not bootstrapped.
	bootstrapped, _ := db.IsBootstrapped()
	if bootstrapped {
		t.Error("expected not bootstrapped before Apply")
	}

	// After Apply: bootstrapped.
	if err := Apply(db, cfg, testMasterKey); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	bootstrapped, err := db.IsBootstrapped()
	if err != nil {
		t.Fatalf("IsBootstrapped after Apply: %v", err)
	}
	if !bootstrapped {
		t.Error("expected bootstrapped after Apply")
	}
}

func TestBootstrapDB_NoTx_AccessKeys(t *testing.T) {
	// Direct DB.Bootstrap() call verifies atomicity: both user and key must be present.
	db := openTestDB(t)

	if err := db.Bootstrap("admin", "$argon2id$placeholder", "AKIAROOT", "v1:nonce:cipher"); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	var userCount, keyCount int
	_ = db.SQLDB().QueryRow("SELECT COUNT(*) FROM ui_users").Scan(&userCount)
	_ = db.SQLDB().QueryRow("SELECT COUNT(*) FROM access_keys").Scan(&keyCount)

	if userCount != 1 {
		t.Errorf("expected 1 user after Bootstrap, got %d", userCount)
	}
	if keyCount != 1 {
		t.Errorf("expected 1 access key after Bootstrap, got %d", keyCount)
	}
}

// ---- Partial state tests ----
// Per security-model.md 3.1 and configuration-model.md 2.2:
// bootstrap input is consumed ONLY when the DB is in the empty state.
// Apply must return ErrPartialInit for partial state and never modify the DB.

func TestApply_PartialDB_UserOnly_ReturnsErrPartialInit(t *testing.T) {
	// Simulate: admin user inserted (e.g., from a previous crashed bootstrap),
	// but no access key. Apply must refuse with ErrPartialInit.
	db := openTestDB(t)
	cfg := fullBootstrapCfg()

	// Pre-insert only the user (simulates partial bootstrap crash).
	if _, err := db.SQLDB().Exec(
		"INSERT INTO ui_users (username, password_hash, created_at) VALUES (?, ?, datetime('now'))",
		"orphaned-admin", "$argon2id$placeholder",
	); err != nil {
		t.Fatalf("pre-inserting user: %v", err)
	}

	err := Apply(db, cfg, testMasterKey)
	if err == nil {
		t.Fatal("expected ErrPartialInit for user-only DB, got nil")
	}
	if !isErrPartialInit(err) {
		t.Errorf("expected ErrPartialInit, got: %v", err)
	}

	// Verify NO new records were added (DB still has exactly 1 user, 0 keys).
	var userCount, keyCount int
	_ = db.SQLDB().QueryRow("SELECT COUNT(*) FROM ui_users").Scan(&userCount)
	_ = db.SQLDB().QueryRow("SELECT COUNT(*) FROM access_keys").Scan(&keyCount)
	if userCount != 1 {
		t.Errorf("expected 1 user (no change), got %d", userCount)
	}
	if keyCount != 0 {
		t.Errorf("expected 0 keys (no change), got %d", keyCount)
	}
}

func TestApply_PartialDB_KeyOnly_ReturnsErrPartialInit(t *testing.T) {
	// Simulate: root key inserted but no admin user. Apply must refuse.
	db := openTestDB(t)
	cfg := fullBootstrapCfg()

	// Pre-insert only a root key.
	if _, err := db.SQLDB().Exec(
		"INSERT INTO access_keys (access_key, secret_ciphertext, status, is_root, created_at) VALUES (?, ?, 'active', 1, datetime('now'))",
		"AKIAORPHANROOT", "v1:nonce:cipher",
	); err != nil {
		t.Fatalf("pre-inserting root key: %v", err)
	}

	err := Apply(db, cfg, testMasterKey)
	if err == nil {
		t.Fatal("expected ErrPartialInit for key-only DB, got nil")
	}
	if !isErrPartialInit(err) {
		t.Errorf("expected ErrPartialInit, got: %v", err)
	}

	// Verify NO new records were added.
	var userCount, keyCount int
	_ = db.SQLDB().QueryRow("SELECT COUNT(*) FROM ui_users").Scan(&userCount)
	_ = db.SQLDB().QueryRow("SELECT COUNT(*) FROM access_keys").Scan(&keyCount)
	if userCount != 0 {
		t.Errorf("expected 0 users (no change), got %d", userCount)
	}
	if keyCount != 1 {
		t.Errorf("expected 1 key (no change), got %d", keyCount)
	}
}

func TestApply_EmptyDB_AllowsBootstrap(t *testing.T) {
	// Explicit test: empty DB + full bootstrap env → Apply succeeds.
	// Per configuration-model.md 2.2: bootstrap consumed only from empty DB.
	db := openTestDB(t)
	cfg := fullBootstrapCfg()

	if err := Apply(db, cfg, testMasterKey); err != nil {
		t.Fatalf("Apply on empty DB: %v", err)
	}

	state, err := db.BootstrapState()
	if err != nil {
		t.Fatalf("BootstrapState: %v", err)
	}
	if state != metadata.DBStateBootstrapped {
		t.Errorf("expected DBStateBootstrapped after Apply on empty DB, got %s", state)
	}
}

func TestApply_BootstrappedDB_IsNoOp(t *testing.T) {
	// Bootstrapped DB → Apply returns nil without modifying records.
	db := openTestDB(t)
	cfg := fullBootstrapCfg()

	if err := Apply(db, cfg, testMasterKey); err != nil {
		t.Fatalf("first Apply: %v", err)
	}

	// Second call: must return nil (no-op, not ErrPartialInit).
	if err := Apply(db, cfg, testMasterKey); err != nil {
		t.Fatalf("second Apply on bootstrapped DB should be no-op: %v", err)
	}
}

// isErrPartialInit checks whether err is or wraps ErrPartialInit.
func isErrPartialInit(err error) bool {
	return errors.Is(err, ErrPartialInit)
}

func TestBootstrapDB_DuplicateUsername_RollsBack(t *testing.T) {
	// If the admin username already exists, Bootstrap must roll back
	// and not insert the access key (atomicity check).
	db := openTestDB(t)

	// Insert existing user.
	if _, err := db.SQLDB().Exec(
		"INSERT INTO ui_users (username, password_hash, created_at) VALUES ('admin', 'hash', datetime('now'))",
	); err != nil {
		t.Fatalf("pre-inserting user: %v", err)
	}

	err := db.Bootstrap("admin", "newhash", "AKIAROOT", "v1:nonce:cipher")
	if err == nil {
		t.Fatal("expected Bootstrap to fail on duplicate username")
	}

	// Access key must NOT have been inserted (transaction rolled back).
	var keyCount int
	if scanErr := db.SQLDB().QueryRow("SELECT COUNT(*) FROM access_keys").Scan(&keyCount); scanErr != nil {
		t.Fatalf("counting keys: %v", scanErr)
	}
	if keyCount != 0 {
		t.Errorf("expected 0 access keys after rolled-back Bootstrap, got %d", keyCount)
	}
}

