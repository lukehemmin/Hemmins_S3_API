package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestSave_Success(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	cfg := &Config{
		Version: 1,
		Server: ServerConfig{
			Listen:         ":9000",
			PublicEndpoint: "http://localhost:9000",
			EnableUI:       true,
		},
		S3: S3Config{
			Region:        "us-east-1",
			MaxPresignTTL: Duration{Duration: 24 * time.Hour},
		},
		Paths: PathsConfig{
			MetaDB:        "/data/meta/metadata.db",
			ObjectRoot:    "/data/objects",
			MultipartRoot: "/data/multipart",
			TempRoot:      "/data/tmp",
			LogRoot:       "/data/logs",
		},
		Auth: AuthConfig{
			MasterKey: "test-master-key-32-bytes-minimum!",
		},
		UI: UIConfig{
			SessionTTL:     Duration{Duration: 12 * time.Hour},
			SessionIdleTTL: Duration{Duration: 30 * time.Minute},
		},
		Logging: LoggingConfig{
			Level:     "info",
			AccessLog: true,
		},
		GC: GCConfig{
			OrphanScanInterval: Duration{Duration: 24 * time.Hour},
			OrphanGracePeriod:  Duration{Duration: 1 * time.Hour},
			MultipartExpiry:    Duration{Duration: 24 * time.Hour},
		},
		ConfigFilePath: configPath,
	}

	// Write initial file
	if err := os.WriteFile(configPath, []byte("version: 1\n"), 0644); err != nil {
		t.Fatalf("writing initial file: %v", err)
	}

	if err := Save(cfg, configPath); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Read back and verify
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("reading saved file: %v", err)
	}

	var loaded Config
	if err := yaml.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("parsing saved file: %v", err)
	}

	if loaded.Server.Listen != ":9000" {
		t.Errorf("server.listen: got %q, want :9000", loaded.Server.Listen)
	}
	if loaded.Logging.Level != "info" {
		t.Errorf("logging.level: got %q, want info", loaded.Logging.Level)
	}
}

func TestSave_CreatesBackup(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	// Create initial file
	initialContent := []byte("version: 1\noriginal: true\n")
	if err := os.WriteFile(configPath, initialContent, 0644); err != nil {
		t.Fatalf("writing initial file: %v", err)
	}

	cfg := &Config{
		Version: 1,
		Server:  ServerConfig{Listen: ":9000"},
		Auth:    AuthConfig{MasterKey: "test-master-key-32-bytes-minimum!"},
		Paths: PathsConfig{
			MetaDB:        "/data/meta/metadata.db",
			ObjectRoot:    "/data/objects",
			MultipartRoot: "/data/multipart",
			TempRoot:      "/data/tmp",
		},
		Logging: LoggingConfig{Level: "debug"},
	}

	if err := Save(cfg, configPath); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Check backup exists
	backupPath := configPath + ".bak"
	backupData, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("reading backup file: %v", err)
	}

	if string(backupData) != string(initialContent) {
		t.Errorf("backup content mismatch: got %q, want %q", backupData, initialContent)
	}
}

func TestSave_NoPath_Error(t *testing.T) {
	cfg := &Config{}
	if err := Save(cfg, ""); err == nil {
		t.Error("expected error for empty path, got nil")
	}
}

func TestCanSaveConfig_Writable(t *testing.T) {
	tempDir := t.TempDir()
	realPath := filepath.Join(tempDir, "config.yaml")
	if err := os.WriteFile(realPath, []byte("version: 1\n"), 0644); err != nil {
		t.Fatalf("creating temp config file: %v", err)
	}
	cfg := &Config{
		ConfigFilePath:     realPath,
		ConfigFileReadOnly: false,
	}
	if err := CanSaveConfig(cfg); err != nil {
		t.Errorf("expected writable config, got error: %v", err)
	}
}

func TestCanSaveConfig_ReadOnly(t *testing.T) {
	cfg := &Config{
		ConfigFilePath:     "/some/path/config.yaml",
		ConfigFileReadOnly: true,
	}
	if err := CanSaveConfig(cfg); err == nil {
		t.Error("expected error for read-only config, got nil")
	}
}

func TestCanSaveConfig_NoPath(t *testing.T) {
	cfg := &Config{
		ConfigFilePath: "",
	}
	if err := CanSaveConfig(cfg); err == nil {
		t.Error("expected error for missing path, got nil")
	}
}

func TestDuration_MarshalYAML(t *testing.T) {
	d := Duration{Duration: 2*time.Hour + 30*time.Minute}
	got, err := d.MarshalYAML()
	if err != nil {
		t.Fatalf("MarshalYAML failed: %v", err)
	}
	if got != "2h30m0s" {
		t.Errorf("got %q, want 2h30m0s", got)
	}
}

func TestBuildPatchedBytes_FileNotExist(t *testing.T) {
	tempDir := t.TempDir()
	nonExistentPath := filepath.Join(tempDir, "nonexistent.yaml")

	patch := &ConfigPatch{}
	_, err := BuildPatchedBytes(nonExistentPath, patch)
	if err == nil {
		t.Fatal("expected error for non-existent file, got nil")
	}
}

func TestBuildPatchedBytes_AppliesPatch(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	initial := "version: 1\nlogging:\n  level: info\n"
	if err := os.WriteFile(configPath, []byte(initial), 0644); err != nil {
		t.Fatalf("writing initial file: %v", err)
	}

	level := "debug"
	patch := &ConfigPatch{LoggingLevel: &level}
	data, err := BuildPatchedBytes(configPath, patch)
	if err != nil {
		t.Fatalf("BuildPatchedBytes: %v", err)
	}

	content := string(data)
	if !containsStr(content, "debug") {
		t.Errorf("expected patched bytes to contain 'debug', got:\n%s", content)
	}
	// Original unpached field must be preserved.
	if !containsStr(content, "version") {
		t.Errorf("expected patched bytes to contain 'version':\n%s", content)
	}
}

func TestParseCandidateConfig_InvalidDuration(t *testing.T) {
	// A candidate YAML with an invalid duration string must cause ParseCandidateConfig
	// to return an error, preventing the invalid bytes from being saved.
	yamlBytes := []byte("version: 1\ns3:\n  max_presign_ttl: not-a-duration\n")
	_, err := ParseCandidateConfig(yamlBytes)
	if err == nil {
		t.Fatal("expected error for invalid duration in candidate, got nil")
	}
}

func TestParseCandidateConfig_ValidBytes(t *testing.T) {
	yamlBytes := []byte("version: 1\nlogging:\n  level: debug\n")
	cfg, err := ParseCandidateConfig(yamlBytes)
	if err != nil {
		t.Fatalf("ParseCandidateConfig: %v", err)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("expected logging.level=debug, got %q", cfg.Logging.Level)
	}
}

func TestCanSaveConfig_FileNotExist(t *testing.T) {
	cfg := &Config{
		ConfigFilePath:     "/nonexistent/path/config.yaml",
		ConfigFileReadOnly: false,
	}
	if err := CanSaveConfig(cfg); err == nil {
		t.Error("expected error for non-existent file, got nil")
	}
}

func TestSaveRawBytes_NoPath(t *testing.T) {
	if err := SaveRawBytes("", []byte("data")); err == nil {
		t.Error("expected error for empty path, got nil")
	}
}

// TestParseCandidateConfig_ExpandsEnvVars verifies that ParseCandidateConfig
// applies ${VAR} expansion before parsing, matching loadFile semantics.
// This is the core fix for the settings-save / runtime-loader validation parity bug.
func TestParseCandidateConfig_ExpandsEnvVars(t *testing.T) {
	t.Setenv("TEST_PARSE_LOG_LEVEL", "debug")
	yamlBytes := []byte("version: 1\nlogging:\n  level: \"${TEST_PARSE_LOG_LEVEL}\"\n")
	cfg, err := ParseCandidateConfig(yamlBytes)
	if err != nil {
		t.Fatalf("ParseCandidateConfig: %v", err)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("expected logging.level=debug after env expansion, got %q", cfg.Logging.Level)
	}
}

// TestParseCandidateConfig_UnsetEnvExpandsToEmpty verifies that unset env vars
// expand to empty string, consistent with expandEnvVars / loadFile behavior.
func TestParseCandidateConfig_UnsetEnvExpandsToEmpty(t *testing.T) {
	yamlBytes := []byte("version: 1\nlogging:\n  level: \"${TEST_UNSET_VAR_XYZZY_NOEXIST}\"\n")
	cfg, err := ParseCandidateConfig(yamlBytes)
	if err != nil {
		t.Fatalf("ParseCandidateConfig: %v", err)
	}
	if cfg.Logging.Level != "" {
		t.Errorf("expected empty logging.level for unset env var, got %q", cfg.Logging.Level)
	}
}

// TestParseCandidateConfig_PlaceholderDuration verifies that a ${VAR} placeholder
// for a duration field is expanded and correctly parsed.
func TestParseCandidateConfig_PlaceholderDuration(t *testing.T) {
	t.Setenv("TEST_PRESIGN_TTL", "48h")
	yamlBytes := []byte("version: 1\ns3:\n  max_presign_ttl: \"${TEST_PRESIGN_TTL}\"\n")
	cfg, err := ParseCandidateConfig(yamlBytes)
	if err != nil {
		t.Fatalf("ParseCandidateConfig: %v", err)
	}
	if cfg.S3.MaxPresignTTL.Duration != 48*time.Hour {
		t.Errorf("expected max_presign_ttl=48h, got %v", cfg.S3.MaxPresignTTL.Duration)
	}
}

// TestSavePatch_RejectsInvalidCandidate verifies that SavePatch now validates
// candidate bytes before writing, preventing structurally invalid configs from
// being persisted.
func TestSavePatch_RejectsInvalidCandidate(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	// Write initial file with an invalid duration placeholder that expands to garbage.
	t.Setenv("TEST_BAD_DURATION", "not-a-duration")
	initial := "version: 1\ns3:\n  max_presign_ttl: \"${TEST_BAD_DURATION}\"\n"
	if err := os.WriteFile(configPath, []byte(initial), 0644); err != nil {
		t.Fatalf("writing initial file: %v", err)
	}

	level := "debug"
	patch := &ConfigPatch{LoggingLevel: &level}
	err := SavePatch(configPath, patch)
	if err == nil {
		t.Fatal("expected SavePatch to reject invalid candidate, got nil")
	}
}

// containsStr is a local helper for this test file.
func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (sub == "" || func() bool {
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}())
}
