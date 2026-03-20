package config

import (
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var regionPattern = regexp.MustCompile(`^[a-z0-9-]+$`)

// Validate performs a full validation of the effective configuration.
// Returns a combined error listing all detected problems.
// Per configuration-model.md section 7 and section 9.1: fail-fast on invalid config.
func Validate(cfg *Config) error {
	var errs []error

	if cfg.Version != 0 && cfg.Version != 1 {
		errs = append(errs, fmt.Errorf("unsupported config schema version %d (expected 1)", cfg.Version))
	}

	// Required fields per configuration-model.md section 5.4 and 5.5
	if cfg.Paths.MetaDB == "" {
		errs = append(errs, errors.New("paths.meta_db is required"))
	}
	if cfg.Paths.ObjectRoot == "" {
		errs = append(errs, errors.New("paths.object_root is required"))
	}
	if cfg.Paths.MultipartRoot == "" {
		errs = append(errs, errors.New("paths.multipart_root is required"))
	}
	if cfg.Paths.TempRoot == "" {
		errs = append(errs, errors.New("paths.temp_root is required"))
	}
	if cfg.Auth.MasterKey == "" {
		errs = append(errs, errors.New("auth.master_key is required"))
	}

	// auth.master_key minimum entropy: 32 bytes recommended
	if cfg.Auth.MasterKey != "" && len(cfg.Auth.MasterKey) < 32 {
		errs = append(errs, fmt.Errorf("auth.master_key must be at least 32 bytes (got %d)", len(cfg.Auth.MasterKey)))
	}

	// All paths must be absolute
	pathFields := map[string]string{
		"paths.meta_db":        cfg.Paths.MetaDB,
		"paths.object_root":    cfg.Paths.ObjectRoot,
		"paths.multipart_root": cfg.Paths.MultipartRoot,
		"paths.temp_root":      cfg.Paths.TempRoot,
	}
	if cfg.Paths.LogRoot != "" {
		pathFields["paths.log_root"] = cfg.Paths.LogRoot
	}
	for name, p := range pathFields {
		if p != "" && !filepath.IsAbs(p) {
			errs = append(errs, fmt.Errorf("%s must be an absolute path (got %q)", name, p))
		}
	}

	// paths.object_root, multipart_root, temp_root must be distinct directories
	if cfg.Paths.ObjectRoot != "" && cfg.Paths.MultipartRoot != "" &&
		cfg.Paths.ObjectRoot == cfg.Paths.MultipartRoot {
		errs = append(errs, errors.New("paths.object_root and paths.multipart_root must be different directories"))
	}
	if cfg.Paths.ObjectRoot != "" && cfg.Paths.TempRoot != "" &&
		cfg.Paths.ObjectRoot == cfg.Paths.TempRoot {
		errs = append(errs, errors.New("paths.object_root and paths.temp_root must be different directories"))
	}
	if cfg.Paths.MultipartRoot != "" && cfg.Paths.TempRoot != "" &&
		cfg.Paths.MultipartRoot == cfg.Paths.TempRoot {
		errs = append(errs, errors.New("paths.multipart_root and paths.temp_root must be different directories"))
	}

	// server.public_endpoint must be an absolute http:// or https:// URL if set
	if cfg.Server.PublicEndpoint != "" {
		u, err := url.Parse(cfg.Server.PublicEndpoint)
		if err != nil || !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") {
			errs = append(errs, fmt.Errorf(
				"server.public_endpoint must be an absolute http:// or https:// URL (got %q)",
				cfg.Server.PublicEndpoint,
			))
		}
	}

	// s3.region: lowercase letters, digits, hyphens only
	if cfg.S3.Region != "" && !regionPattern.MatchString(cfg.S3.Region) {
		errs = append(errs, fmt.Errorf(
			"s3.region must contain only lowercase letters, digits, and hyphens (got %q)",
			cfg.S3.Region,
		))
	}

	// ui.session_idle_ttl must not exceed ui.session_ttl
	if cfg.UI.SessionIdleTTL.Duration > 0 && cfg.UI.SessionTTL.Duration > 0 {
		if cfg.UI.SessionIdleTTL.Duration > cfg.UI.SessionTTL.Duration {
			errs = append(errs, fmt.Errorf(
				"ui.session_idle_ttl (%s) must not exceed ui.session_ttl (%s)",
				cfg.UI.SessionIdleTTL, cfg.UI.SessionTTL,
			))
		}
	}

	// logging.level must be a valid level
	if cfg.Logging.Level != "" {
		switch cfg.Logging.Level {
		case "debug", "info", "warn", "error":
		default:
			errs = append(errs, fmt.Errorf(
				"logging.level must be one of: debug, info, warn, error (got %q)",
				cfg.Logging.Level,
			))
		}
	}

	if len(errs) > 0 {
		return joinErrors(errs)
	}
	return nil
}

// InitializePaths creates required data directories, validates permissions,
// and enforces the filesystem constraint that temp_root and object_root must
// reside on the same filesystem (required for atomic rename).
// Per operations-runbook.md section 3.1 and configuration-model.md section 7.2.
func InitializePaths(cfg *Config) error {
	// Required data directories (fatal if creation fails)
	requiredDirs := []string{
		filepath.Dir(cfg.Paths.MetaDB),
		cfg.Paths.ObjectRoot,
		cfg.Paths.MultipartRoot,
		cfg.Paths.TempRoot,
	}
	for _, dir := range requiredDirs {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("creating directory %q: %w", dir, err)
		}
	}

	// log_root is optional; creation failure is a warning only
	if cfg.Paths.LogRoot != "" {
		if err := os.MkdirAll(cfg.Paths.LogRoot, 0750); err != nil {
			log.Printf("warning: cannot create paths.log_root %q: %v (file logging disabled)", cfg.Paths.LogRoot, err)
		}
	}

	// Validate read/write access for data directories
	writableDirs := []string{
		cfg.Paths.ObjectRoot,
		cfg.Paths.MultipartRoot,
		cfg.Paths.TempRoot,
	}
	for _, dir := range writableDirs {
		if err := checkWritable(dir); err != nil {
			return fmt.Errorf("directory %q is not writable: %w", dir, err)
		}
	}

	// temp_root and object_root must be on the same filesystem.
	// This is required so that rename(2) across temp→final path is atomic.
	// Per operations-runbook.md section 3.1 and system-architecture.md section 6.1.
	same, err := sameFilesystem(cfg.Paths.TempRoot, cfg.Paths.ObjectRoot)
	if err != nil {
		return fmt.Errorf("checking filesystem for paths.temp_root and paths.object_root: %w", err)
	}
	if !same {
		return fmt.Errorf(
			"paths.temp_root (%q) and paths.object_root (%q) must be on the same filesystem (required for atomic rename)",
			cfg.Paths.TempRoot, cfg.Paths.ObjectRoot,
		)
	}

	// temp_root and multipart_root must be on the same filesystem.
	// AtomicWrite creates a temp file in temp_root and renames it into
	// multipart_root/<upload_id>/ for each UploadPart request.
	// That rename is only atomic when both paths share the same device.
	// Per system-architecture.md section 6.1 and 5.3.
	same, err = sameFilesystem(cfg.Paths.TempRoot, cfg.Paths.MultipartRoot)
	if err != nil {
		return fmt.Errorf("checking filesystem for paths.temp_root and paths.multipart_root: %w", err)
	}
	if !same {
		return fmt.Errorf(
			"paths.temp_root (%q) and paths.multipart_root (%q) must be on the same filesystem (required for atomic rename)",
			cfg.Paths.TempRoot, cfg.Paths.MultipartRoot,
		)
	}

	return nil
}

// checkWritable verifies that a directory exists and is writable by attempting
// to create and remove a temporary file inside it.
func checkWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".hemmins-writecheck-*")
	if err != nil {
		return err
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return nil
}

// joinErrors combines multiple errors into a single descriptive error message.
func joinErrors(errs []error) error {
	if len(errs) == 1 {
		return errs[0]
	}
	msgs := make([]string, len(errs))
	for i, e := range errs {
		msgs[i] = "  - " + e.Error()
	}
	return fmt.Errorf("configuration errors:\n%s", strings.Join(msgs, "\n"))
}
