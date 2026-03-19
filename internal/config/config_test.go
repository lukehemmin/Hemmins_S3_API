package config

import (
	"os"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := defaultConfig()
	if cfg.Server.Listen != ":9000" {
		t.Errorf("default listen: got %q, want :9000", cfg.Server.Listen)
	}
	if cfg.S3.Region != "us-east-1" {
		t.Errorf("default region: got %q, want us-east-1", cfg.S3.Region)
	}
	if cfg.UI.SessionTTL.Duration != 12*time.Hour {
		t.Errorf("default session_ttl: got %s, want 12h", cfg.UI.SessionTTL)
	}
	if cfg.UI.SessionIdleTTL.Duration != 30*time.Minute {
		t.Errorf("default session_idle_ttl: got %s, want 30m", cfg.UI.SessionIdleTTL)
	}
	if !cfg.Server.EnableUI {
		t.Error("default enable_ui should be true")
	}
	if cfg.Server.TrustProxyHeaders {
		t.Error("default trust_proxy_headers should be false")
	}
}

func TestValidate_MissingRequiredPaths(t *testing.T) {
	cfg := defaultConfig()
	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected validation error for missing required paths, got nil")
	}
}

func TestValidate_Valid(t *testing.T) {
	cfg := validTestConfig()
	if err := Validate(cfg); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestValidate_RelativePath(t *testing.T) {
	cfg := validTestConfig()
	cfg.Paths.MetaDB = "relative/path/metadata.db"
	if err := Validate(cfg); err == nil {
		t.Fatal("expected error for relative paths.meta_db, got nil")
	}
}

func TestValidate_InvalidRegion(t *testing.T) {
	cfg := validTestConfig()
	cfg.S3.Region = "INVALID_REGION_WITH_CAPS"
	if err := Validate(cfg); err == nil {
		t.Fatal("expected error for invalid s3.region, got nil")
	}
}

func TestValidate_InvalidPublicEndpoint(t *testing.T) {
	cfg := validTestConfig()
	cfg.Server.PublicEndpoint = "not-a-url"
	if err := Validate(cfg); err == nil {
		t.Fatal("expected error for invalid server.public_endpoint, got nil")
	}
}

func TestValidate_SessionIdleTTLExceedsSessionTTL(t *testing.T) {
	cfg := validTestConfig()
	cfg.UI.SessionTTL = Duration{1 * time.Hour}
	cfg.UI.SessionIdleTTL = Duration{2 * time.Hour}
	if err := Validate(cfg); err == nil {
		t.Fatal("expected error when session_idle_ttl > session_ttl, got nil")
	}
}

func TestValidate_ShortMasterKey(t *testing.T) {
	cfg := validTestConfig()
	cfg.Auth.MasterKey = "tooshort"
	if err := Validate(cfg); err == nil {
		t.Fatal("expected error for master_key < 32 bytes, got nil")
	}
}

func TestValidate_SameObjectAndMultipartRoot(t *testing.T) {
	cfg := validTestConfig()
	cfg.Paths.MultipartRoot = cfg.Paths.ObjectRoot
	if err := Validate(cfg); err == nil {
		t.Fatal("expected error when object_root == multipart_root, got nil")
	}
}

func TestValidate_SameObjectAndTempRoot(t *testing.T) {
	cfg := validTestConfig()
	cfg.Paths.TempRoot = cfg.Paths.ObjectRoot
	if err := Validate(cfg); err == nil {
		t.Fatal("expected error when object_root == temp_root, got nil")
	}
}

func TestValidate_InvalidLoggingLevel(t *testing.T) {
	cfg := validTestConfig()
	cfg.Logging.Level = "verbose"
	if err := Validate(cfg); err == nil {
		t.Fatal("expected error for invalid logging.level, got nil")
	}
}

func TestValidate_UnsupportedSchemaVersion(t *testing.T) {
	cfg := validTestConfig()
	cfg.Version = 99
	if err := Validate(cfg); err == nil {
		t.Fatal("expected error for unsupported schema version, got nil")
	}
}

func TestExpandEnvVars_Set(t *testing.T) {
	t.Setenv("TEST_EXPAND_VAR_XYZ", "hello")
	input := []byte(`key: "${TEST_EXPAND_VAR_XYZ}"`)
	got := string(expandEnvVars(input))
	want := `key: "hello"`
	if got != want {
		t.Errorf("expandEnvVars: got %q, want %q", got, want)
	}
}

func TestExpandEnvVars_Unset(t *testing.T) {
	os.Unsetenv("DEFINITELY_NOT_SET_VAR_HEMMINS")
	input := []byte(`key: "${DEFINITELY_NOT_SET_VAR_HEMMINS}"`)
	got := string(expandEnvVars(input))
	want := `key: ""`
	if got != want {
		t.Errorf("expandEnvVars unset: got %q, want %q", got, want)
	}
}

func TestApplyEnvOverrides_Region(t *testing.T) {
	t.Setenv("HEMMINS_S3_REGION", "eu-west-1")
	cfg := defaultConfig()
	if err := applyEnvOverrides(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.S3.Region != "eu-west-1" {
		t.Errorf("expected eu-west-1, got %q", cfg.S3.Region)
	}
	if !cfg.EnvLocked.S3Region {
		t.Error("expected S3Region to be env-locked")
	}
}

func TestApplyEnvOverrides_Listen(t *testing.T) {
	t.Setenv("HEMMINS_SERVER_LISTEN", ":8080")
	cfg := defaultConfig()
	if err := applyEnvOverrides(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.Listen != ":8080" {
		t.Errorf("expected :8080, got %q", cfg.Server.Listen)
	}
	if !cfg.EnvLocked.ServerListen {
		t.Error("expected ServerListen to be env-locked")
	}
}

func TestApplyEnvOverrides_MasterKey(t *testing.T) {
	t.Setenv("HEMMINS_AUTH_MASTER_KEY", "env-provided-master-key-value-long-enough-32bytes")
	cfg := defaultConfig()
	if err := applyEnvOverrides(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Auth.MasterKey != "env-provided-master-key-value-long-enough-32bytes" {
		t.Errorf("unexpected master key value")
	}
	if !cfg.EnvLocked.AuthMasterKey {
		t.Error("expected AuthMasterKey to be env-locked")
	}
}

func TestApplyEnvOverrides_InvalidBool(t *testing.T) {
	t.Setenv("HEMMINS_SERVER_ENABLE_UI", "notabool")
	cfg := defaultConfig()
	err := applyEnvOverrides(cfg)
	if err == nil {
		t.Fatal("expected error for invalid bool env var, got nil")
	}
}

func TestApplyEnvOverrides_InvalidDuration(t *testing.T) {
	t.Setenv("HEMMINS_S3_MAX_PRESIGN_TTL", "notaduration")
	cfg := defaultConfig()
	err := applyEnvOverrides(cfg)
	if err == nil {
		t.Fatal("expected error for invalid duration env var, got nil")
	}
}

func TestApplyEnvOverrides_EmptyStringOverride(t *testing.T) {
	t.Setenv("HEMMINS_S3_REGION", "")
	cfg := defaultConfig()
	if err := applyEnvOverrides(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.S3.Region != "" {
		t.Errorf("expected empty region from explicit empty env var, got %q", cfg.S3.Region)
	}
	if !cfg.EnvLocked.S3Region {
		t.Error("expected S3Region to be env-locked even when set to empty string")
	}
}

func TestApplyEnvOverrides_EmptyBoolError(t *testing.T) {
	t.Setenv("HEMMINS_SERVER_ENABLE_UI", "")
	cfg := defaultConfig()
	err := applyEnvOverrides(cfg)
	if err == nil {
		t.Fatal("expected error for empty bool env var (not a valid bool), got nil")
	}
}

func TestParseBootstrapEnv_WithValues(t *testing.T) {
	t.Setenv("HEMMINS_BOOTSTRAP_ADMIN_USERNAME", "testadmin")
	t.Setenv("HEMMINS_BOOTSTRAP_ADMIN_PASSWORD", "testpassword")
	t.Setenv("HEMMINS_BOOTSTRAP_ROOT_ACCESS_KEY", "AKIATEST")
	t.Setenv("HEMMINS_BOOTSTRAP_ROOT_SECRET_KEY", "secrettest")

	b, err := parseBootstrapEnv()
	if err != nil {
		t.Fatalf("unexpected error for complete bootstrap env: %v", err)
	}
	if !b.HasValues {
		t.Error("expected HasValues=true")
	}
	if b.AdminUsername != "testadmin" {
		t.Errorf("AdminUsername: got %q, want testadmin", b.AdminUsername)
	}
}

func TestParseBootstrapEnv_Empty(t *testing.T) {
	os.Unsetenv("HEMMINS_BOOTSTRAP_ADMIN_USERNAME")
	os.Unsetenv("HEMMINS_BOOTSTRAP_ADMIN_PASSWORD")
	os.Unsetenv("HEMMINS_BOOTSTRAP_ROOT_ACCESS_KEY")
	os.Unsetenv("HEMMINS_BOOTSTRAP_ROOT_SECRET_KEY")

	b, err := parseBootstrapEnv()
	if err != nil {
		t.Fatalf("unexpected error for empty bootstrap env: %v", err)
	}
	if b.HasValues {
		t.Error("expected HasValues=false when no bootstrap env vars are set")
	}
}

func TestParseBootstrapEnv_Partial_OnlyUsername(t *testing.T) {
	// Per security-model.md 3.2: all 4 bootstrap vars must be provided together.
	t.Setenv("HEMMINS_BOOTSTRAP_ADMIN_USERNAME", "admin")
	os.Unsetenv("HEMMINS_BOOTSTRAP_ADMIN_PASSWORD")
	os.Unsetenv("HEMMINS_BOOTSTRAP_ROOT_ACCESS_KEY")
	os.Unsetenv("HEMMINS_BOOTSTRAP_ROOT_SECRET_KEY")

	_, err := parseBootstrapEnv()
	if err == nil {
		t.Fatal("expected fail-fast error for partial bootstrap env (only username set)")
	}
}

func TestParseBootstrapEnv_Partial_ThreeOfFour(t *testing.T) {
	t.Setenv("HEMMINS_BOOTSTRAP_ADMIN_USERNAME", "admin")
	t.Setenv("HEMMINS_BOOTSTRAP_ADMIN_PASSWORD", "password")
	t.Setenv("HEMMINS_BOOTSTRAP_ROOT_ACCESS_KEY", "AKIAROOT")
	os.Unsetenv("HEMMINS_BOOTSTRAP_ROOT_SECRET_KEY")

	_, err := parseBootstrapEnv()
	if err == nil {
		t.Fatal("expected fail-fast error for partial bootstrap env (3 of 4 set)")
	}
}

func TestLoad_PartialBootstrapEnvFails(t *testing.T) {
	// Verify that partial bootstrap vars cause Load() to fail-fast.
	t.Setenv("HEMMINS_BOOTSTRAP_ADMIN_USERNAME", "admin")
	os.Unsetenv("HEMMINS_BOOTSTRAP_ADMIN_PASSWORD")
	os.Unsetenv("HEMMINS_BOOTSTRAP_ROOT_ACCESS_KEY")
	os.Unsetenv("HEMMINS_BOOTSTRAP_ROOT_SECRET_KEY")

	_, _, err := Load("")
	if err == nil {
		t.Fatal("expected Load() to fail with partial bootstrap env vars")
	}
}

// validTestConfig returns a Config with all required fields filled in for testing.
func validTestConfig() *Config {
	cfg := defaultConfig()
	cfg.Paths.MetaDB = "/data/meta/metadata.db"
	cfg.Paths.ObjectRoot = "/data/objects"
	cfg.Paths.MultipartRoot = "/data/multipart"
	cfg.Paths.TempRoot = "/data/tmp"
	cfg.Auth.MasterKey = "this-is-a-valid-32-byte-master-key!"
	return cfg
}
