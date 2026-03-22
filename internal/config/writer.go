package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ConfigPatch contains only the safe-subset UI-editable fields.
// Nil pointers mean "leave the existing file value unchanged".
// Per configuration-model.md section 10.2.
type ConfigPatch struct {
	ServerPublicEndpoint *string // server.public_endpoint
	S3MaxPresignTTL      *string // s3.max_presign_ttl (duration string)
	LoggingLevel         *string // logging.level
	LoggingAccessLog     *bool   // logging.access_log
	UISessionTTL         *string // ui.session_ttl (duration string)
	UISessionIdleTTL     *string // ui.session_idle_ttl (duration string)
}

// SaveError indicates the config file cannot be saved.
var SaveError = errors.New("config file cannot be saved")

// SaveableConfig is the subset of Config that can be persisted to YAML.
// It excludes runtime-only fields like EnvLocked, ConfigFilePath, ConfigFileReadOnly.
// Per configuration-model.md: only config file values are persisted; env overrides are runtime-only.
type SaveableConfig struct {
	Version int           `yaml:"version"`
	Server  ServerConfig  `yaml:"server"`
	S3      S3Config      `yaml:"s3"`
	Paths   PathsConfig   `yaml:"paths"`
	Auth    AuthConfig    `yaml:"auth"`
	UI      UIConfig      `yaml:"ui"`
	Logging LoggingConfig `yaml:"logging"`
	GC      GCConfig      `yaml:"gc"`
}

// ToSaveable converts a Config to the saveable subset for YAML serialization.
func (c *Config) ToSaveable() *SaveableConfig {
	return &SaveableConfig{
		Version: c.Version,
		Server:  c.Server,
		S3:      c.S3,
		Paths:   c.Paths,
		Auth:    c.Auth,
		UI:      c.UI,
		Logging: c.Logging,
		GC:      c.GC,
	}
}

// Save writes the saveable portion of a Config to the given path.
// Per configuration-model.md section 9.2:
//  1. Write to a temp file in the same directory
//  2. Validate the written content
//  3. Create a backup of the existing config (config.yaml.bak)
//  4. Atomic rename temp file to final path
//
// The caller must ensure the path is writable before calling Save.
// Returns SaveError wrapping the underlying cause on failure.
func Save(cfg *Config, path string) error {
	if path == "" {
		return fmt.Errorf("%w: no config file path specified", SaveError)
	}

	saveable := cfg.ToSaveable()
	data, err := yaml.Marshal(saveable)
	if err != nil {
		return fmt.Errorf("%w: marshaling config: %v", SaveError, err)
	}

	return atomicWriteFile(path, data)
}

// SavePatch reads the existing config file and applies only the safe-subset
// ConfigPatch fields. All other file content (including auth.master_key,
// paths.*, and any fields not present in the patch) is preserved unchanged.
//
// This ensures:
//   - env-override values are never persisted to the file
//   - auth.master_key is never written or modified by this function
//   - paths.* are never written or modified by this function
//   - only the explicitly requested fields change in the file
//
// Note: SavePatch performs structural parse validation (including ${VAR}
// expansion) but does NOT run full Validate with runtime env-locked merging.
// For the complete validation flow used by the settings save HTTP handler,
// use: BuildPatchedBytes + ParseCandidateConfig + MergeRuntimeEnvLocked +
// Validate + SaveRawBytes.
//
// Per configuration-model.md sections 2.1, 9.2, 10.2.
func SavePatch(path string, patch *ConfigPatch) error {
	data, err := BuildPatchedBytes(path, patch)
	if err != nil {
		return err
	}
	// Structural validation: ensure the candidate bytes are parseable
	// (including ${VAR} expansion, matching loadFile semantics).
	if _, err := ParseCandidateConfig(data); err != nil {
		return fmt.Errorf("%w: %v", SaveError, err)
	}
	return atomicWriteFile(path, data)
}

// BuildPatchedBytes reads the existing config file, applies only the safe-subset
// ConfigPatch fields, and returns the resulting YAML bytes without writing to disk.
// Returns an error (wrapping SaveError) if the file does not exist.
// This allows callers to validate the candidate bytes before committing.
func BuildPatchedBytes(path string, patch *ConfigPatch) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: no config file path specified", SaveError)
	}

	// Read the existing file. We intentionally error if it does not exist:
	// creating a new file from scratch via patch would produce an incomplete
	// config (missing paths.*, auth.master_key, etc.).
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: config file does not exist at %q", SaveError, path)
		}
		return nil, fmt.Errorf("%w: reading existing config: %v", SaveError, err)
	}

	var fileMap map[string]interface{}
	if err := yaml.Unmarshal(data, &fileMap); err != nil {
		return nil, fmt.Errorf("%w: parsing existing config: %v", SaveError, err)
	}
	if fileMap == nil {
		fileMap = make(map[string]interface{})
	}

	// Apply only safe-subset fields. auth and paths sections are never touched.
	applyPatchToFileMap(fileMap, patch)

	// Marshal back to YAML.
	newData, err := yaml.Marshal(fileMap)
	if err != nil {
		return nil, fmt.Errorf("%w: marshaling patched config: %v", SaveError, err)
	}

	return newData, nil
}

// ParseCandidateConfig parses YAML bytes into a Config (defaults + file values).
// It applies ${VAR} environment variable expansion before parsing, matching the
// same semantics as loadFile (configuration-model.md section 4.1). This ensures
// validation parity: a config accepted at startup is also accepted during save.
//
// It does NOT apply HEMMINS_* environment variable overrides; call MergeRuntimeEnvLocked
// afterward to overlay the currently-active env-locked values from the runtime config.
// This separation allows tests to work without setting real HEMMINS_* env vars.
func ParseCandidateConfig(data []byte) (*Config, error) {
	cfg := defaultConfig()
	expanded := expandEnvVars(data)
	if err := yaml.Unmarshal(expanded, cfg); err != nil {
		return nil, fmt.Errorf("parsing candidate config: %w", err)
	}
	return cfg, nil
}

// MergeRuntimeEnvLocked copies all env-locked field values from the runtime config
// into the candidate config and sets the corresponding EnvLocked flags.
// This simulates what the next startup would produce when the same env vars are present.
// It must be called after ParseCandidateConfig so that env-provided required fields
// (e.g. auth.master_key, paths.*) are present before Validate runs.
func MergeRuntimeEnvLocked(candidate *Config, runtime *Config) {
	if runtime.EnvLocked.ServerListen {
		candidate.Server.Listen = runtime.Server.Listen
		candidate.EnvLocked.ServerListen = true
	}
	if runtime.EnvLocked.ServerPublicEndpoint {
		candidate.Server.PublicEndpoint = runtime.Server.PublicEndpoint
		candidate.EnvLocked.ServerPublicEndpoint = true
	}
	if runtime.EnvLocked.ServerEnableUI {
		candidate.Server.EnableUI = runtime.Server.EnableUI
		candidate.EnvLocked.ServerEnableUI = true
	}
	if runtime.EnvLocked.ServerTrustProxyHeaders {
		candidate.Server.TrustProxyHeaders = runtime.Server.TrustProxyHeaders
		candidate.EnvLocked.ServerTrustProxyHeaders = true
	}
	if runtime.EnvLocked.S3Region {
		candidate.S3.Region = runtime.S3.Region
		candidate.EnvLocked.S3Region = true
	}
	if runtime.EnvLocked.S3VirtualHostSuffix {
		candidate.S3.VirtualHostSuffix = runtime.S3.VirtualHostSuffix
		candidate.EnvLocked.S3VirtualHostSuffix = true
	}
	if runtime.EnvLocked.S3MaxPresignTTL {
		candidate.S3.MaxPresignTTL = runtime.S3.MaxPresignTTL
		candidate.EnvLocked.S3MaxPresignTTL = true
	}
	if runtime.EnvLocked.PathsMetaDB {
		candidate.Paths.MetaDB = runtime.Paths.MetaDB
		candidate.EnvLocked.PathsMetaDB = true
	}
	if runtime.EnvLocked.PathsObjectRoot {
		candidate.Paths.ObjectRoot = runtime.Paths.ObjectRoot
		candidate.EnvLocked.PathsObjectRoot = true
	}
	if runtime.EnvLocked.PathsMultipartRoot {
		candidate.Paths.MultipartRoot = runtime.Paths.MultipartRoot
		candidate.EnvLocked.PathsMultipartRoot = true
	}
	if runtime.EnvLocked.PathsTempRoot {
		candidate.Paths.TempRoot = runtime.Paths.TempRoot
		candidate.EnvLocked.PathsTempRoot = true
	}
	if runtime.EnvLocked.PathsLogRoot {
		candidate.Paths.LogRoot = runtime.Paths.LogRoot
		candidate.EnvLocked.PathsLogRoot = true
	}
	if runtime.EnvLocked.AuthMasterKey {
		candidate.Auth.MasterKey = runtime.Auth.MasterKey
		candidate.EnvLocked.AuthMasterKey = true
	}
	if runtime.EnvLocked.UISessionTTL {
		candidate.UI.SessionTTL = runtime.UI.SessionTTL
		candidate.EnvLocked.UISessionTTL = true
	}
	if runtime.EnvLocked.UISessionIdleTTL {
		candidate.UI.SessionIdleTTL = runtime.UI.SessionIdleTTL
		candidate.EnvLocked.UISessionIdleTTL = true
	}
	if runtime.EnvLocked.LoggingLevel {
		candidate.Logging.Level = runtime.Logging.Level
		candidate.EnvLocked.LoggingLevel = true
	}
	if runtime.EnvLocked.LoggingAccessLog {
		candidate.Logging.AccessLog = runtime.Logging.AccessLog
		candidate.EnvLocked.LoggingAccessLog = true
	}
	if runtime.EnvLocked.GCOrphanScanInterval {
		candidate.GC.OrphanScanInterval = runtime.GC.OrphanScanInterval
		candidate.EnvLocked.GCOrphanScanInterval = true
	}
	if runtime.EnvLocked.GCOrphanGracePeriod {
		candidate.GC.OrphanGracePeriod = runtime.GC.OrphanGracePeriod
		candidate.EnvLocked.GCOrphanGracePeriod = true
	}
	if runtime.EnvLocked.GCMultipartExpiry {
		candidate.GC.MultipartExpiry = runtime.GC.MultipartExpiry
		candidate.EnvLocked.GCMultipartExpiry = true
	}
}

// SaveRawBytes atomically writes pre-computed YAML bytes to path.
// Use after BuildPatchedBytes + ParseCandidateConfig + Validate to avoid
// recomputing the bytes.
func SaveRawBytes(path string, data []byte) error {
	if path == "" {
		return fmt.Errorf("%w: no config file path specified", SaveError)
	}
	return atomicWriteFile(path, data)
}

// readYAMLFileMap reads a YAML file into a map[string]interface{}.
// Returns an error if the file does not exist.
func readYAMLFileMap(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if m == nil {
		m = make(map[string]interface{})
	}
	return m, nil
}

// applyPatchToFileMap applies patch fields to the file map.
// ONLY safe-subset fields are modified; auth and paths sections are never touched.
func applyPatchToFileMap(m map[string]interface{}, patch *ConfigPatch) {
	if patch.ServerPublicEndpoint != nil {
		setNestedField(m, "server", "public_endpoint", *patch.ServerPublicEndpoint)
	}
	if patch.S3MaxPresignTTL != nil {
		setNestedField(m, "s3", "max_presign_ttl", *patch.S3MaxPresignTTL)
	}
	if patch.LoggingLevel != nil {
		setNestedField(m, "logging", "level", *patch.LoggingLevel)
	}
	if patch.LoggingAccessLog != nil {
		setNestedField(m, "logging", "access_log", *patch.LoggingAccessLog)
	}
	if patch.UISessionTTL != nil {
		setNestedField(m, "ui", "session_ttl", *patch.UISessionTTL)
	}
	if patch.UISessionIdleTTL != nil {
		setNestedField(m, "ui", "session_idle_ttl", *patch.UISessionIdleTTL)
	}
}

// setNestedField sets m[section][field] = value, creating the section map if needed.
// Only call this for safe-subset sections (server, s3, logging, ui).
func setNestedField(m map[string]interface{}, section, field string, value interface{}) {
	if _, exists := m[section]; !exists {
		m[section] = make(map[string]interface{})
	}
	sectionMap, ok := m[section].(map[string]interface{})
	if !ok {
		// Section exists but is not a map — overwrite with a fresh map.
		sectionMap = make(map[string]interface{})
		m[section] = sectionMap
	}
	sectionMap[field] = value
}

// atomicWriteFile writes data to path using temp-file + sync + backup + atomic rename.
// Per configuration-model.md section 9.2.
func atomicWriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	// Step 1: Write to a temp file in the same directory.
	tmpFile, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return fmt.Errorf("%w: creating temp file: %v", SaveError, err)
	}
	tmpPath := tmpFile.Name()

	// Clean up temp file on any failure.
	defer func() {
		if tmpPath != "" {
			os.Remove(tmpPath)
		}
	}()

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		return fmt.Errorf("%w: writing temp file: %v", SaveError, err)
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return fmt.Errorf("%w: syncing temp file: %v", SaveError, err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("%w: closing temp file: %v", SaveError, err)
	}

	// Step 2: Validate the written content by re-parsing it.
	testData, err := os.ReadFile(tmpPath)
	if err != nil {
		return fmt.Errorf("%w: reading temp file for validation: %v", SaveError, err)
	}
	var testMap map[string]interface{}
	if err := yaml.Unmarshal(testData, &testMap); err != nil {
		return fmt.Errorf("%w: validation failed - invalid YAML: %v", SaveError, err)
	}

	// Step 3: Create backup of existing config if it exists.
	backupPath := path + ".bak"
	if _, err := os.Stat(path); err == nil {
		if err := copyFile(path, backupPath); err != nil {
			return fmt.Errorf("%w: creating backup: %v", SaveError, err)
		}
	}

	// Step 4: Atomic rename temp file to final path.
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("%w: atomic rename failed: %v", SaveError, err)
	}
	tmpPath = "" // Prevent deferred cleanup from removing the final file.

	return nil
}

// copyFile copies src to dst, preserving the content but not necessarily permissions.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0640)
}

// CanSaveConfig checks whether the config file can be written.
// Returns nil if writable, error otherwise.
// Per configuration-model.md section 9.2: file must exist before patching;
// we never create a new config file via the UI save path.
func CanSaveConfig(cfg *Config) error {
	if cfg.ConfigFilePath == "" {
		return fmt.Errorf("no config file path")
	}
	if cfg.ConfigFileReadOnly {
		return fmt.Errorf("config file is read-only")
	}
	if _, err := os.Stat(cfg.ConfigFilePath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("config file does not exist at %q", cfg.ConfigFilePath)
		}
		return fmt.Errorf("config file not accessible: %v", err)
	}
	return nil
}
