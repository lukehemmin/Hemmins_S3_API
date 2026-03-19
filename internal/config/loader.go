package config

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

// configEnvKey is the environment variable that specifies the config file path.
const configEnvKey = "HEMMINS_CONFIG_FILE"

var envVarPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// Load finds, reads, and merges configuration from the config file and environment variables.
// configPath is the path specified via CLI flag; pass "" to rely on auto-detection.
// Returns the effective Config, the one-time BootstrapConfig, and any error.
func Load(configPath string) (*Config, *BootstrapConfig, error) {
	cfg := defaultConfig()

	path, err := resolveConfigFile(configPath)
	if err != nil {
		return nil, nil, err
	}

	if path != "" {
		cfg.ConfigFilePath = path
		if err := loadFile(cfg, path); err != nil {
			return nil, nil, fmt.Errorf("loading config file %q: %w", path, err)
		}
		if err := checkConfigWritable(path); err != nil {
			cfg.ConfigFileReadOnly = true
		}
	}

	if err := applyEnvOverrides(cfg); err != nil {
		return nil, nil, fmt.Errorf("environment variable override: %w", err)
	}

	bootstrap, err := parseBootstrapEnv()
	if err != nil {
		return nil, nil, fmt.Errorf("bootstrap environment variables: %w", err)
	}

	return cfg, bootstrap, nil
}

// defaultConfig returns a Config populated with documented default values
// per configuration-model.md section 5.
func defaultConfig() *Config {
	return &Config{
		Version: 1,
		Server: ServerConfig{
			Listen:            ":9000",
			PublicEndpoint:    "",
			EnableUI:          true,
			TrustProxyHeaders: false,
		},
		S3: S3Config{
			Region:            "us-east-1",
			VirtualHostSuffix: "",
			MaxPresignTTL:     Duration{24 * time.Hour},
		},
		Paths: PathsConfig{
			LogRoot: "/data/logs",
		},
		UI: UIConfig{
			SessionTTL:     Duration{12 * time.Hour},
			SessionIdleTTL: Duration{30 * time.Minute},
		},
		Logging: LoggingConfig{
			Level:     "info",
			AccessLog: true,
		},
		GC: GCConfig{
			OrphanScanInterval: Duration{24 * time.Hour},
			OrphanGracePeriod:  Duration{1 * time.Hour},
			MultipartExpiry:    Duration{24 * time.Hour},
		},
	}
}

// resolveConfigFile returns the config file path using the following priority order:
// 1. CLI-specified path
// 2. HEMMINS_CONFIG_FILE environment variable
// 3. ./config.yaml in current working directory
// Returns "" (not an error) if no config file is found.
func resolveConfigFile(cliPath string) (string, error) {
	if cliPath != "" {
		if _, err := os.Stat(cliPath); err != nil {
			return "", fmt.Errorf("config file %q specified but not accessible: %w", cliPath, err)
		}
		return cliPath, nil
	}

	if envPath := os.Getenv(configEnvKey); envPath != "" {
		if _, err := os.Stat(envPath); err != nil {
			return "", fmt.Errorf("config file from %s=%q not accessible: %w", configEnvKey, envPath, err)
		}
		return envPath, nil
	}

	const defaultPath = "config.yaml"
	if _, err := os.Stat(defaultPath); err == nil {
		return defaultPath, nil
	}

	return "", nil
}

// expandEnvVars replaces ${VAR} references in raw YAML text with os.Getenv values.
// Unset variables are expanded to an empty string. This is done before YAML parsing
// so that env var references can appear inside quoted YAML string values.
func expandEnvVars(raw []byte) []byte {
	return envVarPattern.ReplaceAllFunc(raw, func(match []byte) []byte {
		name := envVarPattern.FindSubmatch(match)[1]
		return []byte(os.Getenv(string(name)))
	})
}

// loadFile reads the config file, expands ${VAR} references, and merges into cfg.
// Fields present in the YAML override the defaults already set in cfg.
func loadFile(cfg *Config, path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	expanded := expandEnvVars(raw)

	if err := yaml.Unmarshal(expanded, cfg); err != nil {
		return fmt.Errorf("parsing YAML: %w", err)
	}

	return nil
}

// checkConfigWritable reports whether the config file can be opened for writing.
func checkConfigWritable(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	f.Close()
	return nil
}

// applyEnvOverrides applies HEMMINS_* environment variable overrides to cfg.
// Each override marks the corresponding field as env-locked (read-only in UI).
// Per configuration-model.md section 4: env vars take precedence over config file values.
// Per configuration-model.md section 4.1: empty string is a valid value and passes to validation.
// Per configuration-model.md section 9.1: invalid bool/duration values are fatal errors.
func applyEnvOverrides(cfg *Config) error {
	// envStr applies a string env var override. Empty string is a valid override.
	envStr := func(key string, field *string, locked *bool) {
		if v, ok := os.LookupEnv(key); ok {
			*field = v
			*locked = true
		}
	}
	// envBool applies a bool env var override. Returns error on invalid value.
	envBool := func(key string, field *bool, locked *bool) error {
		v, ok := os.LookupEnv(key)
		if !ok {
			return nil
		}
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("invalid value for %s=%q: must be a boolean (true/false/1/0): %w", key, v, err)
		}
		*field = b
		*locked = true
		return nil
	}
	// envDur applies a duration env var override. Returns error on invalid value.
	envDur := func(key string, field *Duration, locked *bool) error {
		v, ok := os.LookupEnv(key)
		if !ok {
			return nil
		}
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("invalid value for %s=%q: must be a duration (e.g. 24h, 30m): %w", key, v, err)
		}
		*field = Duration{d}
		*locked = true
		return nil
	}

	envStr("HEMMINS_SERVER_LISTEN", &cfg.Server.Listen, &cfg.EnvLocked.ServerListen)
	envStr("HEMMINS_SERVER_PUBLIC_ENDPOINT", &cfg.Server.PublicEndpoint, &cfg.EnvLocked.ServerPublicEndpoint)
	envStr("HEMMINS_S3_REGION", &cfg.S3.Region, &cfg.EnvLocked.S3Region)
	envStr("HEMMINS_S3_VIRTUAL_HOST_SUFFIX", &cfg.S3.VirtualHostSuffix, &cfg.EnvLocked.S3VirtualHostSuffix)
	envStr("HEMMINS_PATHS_META_DB", &cfg.Paths.MetaDB, &cfg.EnvLocked.PathsMetaDB)
	envStr("HEMMINS_PATHS_OBJECT_ROOT", &cfg.Paths.ObjectRoot, &cfg.EnvLocked.PathsObjectRoot)
	envStr("HEMMINS_PATHS_MULTIPART_ROOT", &cfg.Paths.MultipartRoot, &cfg.EnvLocked.PathsMultipartRoot)
	envStr("HEMMINS_PATHS_TEMP_ROOT", &cfg.Paths.TempRoot, &cfg.EnvLocked.PathsTempRoot)
	envStr("HEMMINS_PATHS_LOG_ROOT", &cfg.Paths.LogRoot, &cfg.EnvLocked.PathsLogRoot)
	envStr("HEMMINS_AUTH_MASTER_KEY", &cfg.Auth.MasterKey, &cfg.EnvLocked.AuthMasterKey)
	envStr("HEMMINS_LOGGING_LEVEL", &cfg.Logging.Level, &cfg.EnvLocked.LoggingLevel)

	if err := envBool("HEMMINS_SERVER_ENABLE_UI", &cfg.Server.EnableUI, &cfg.EnvLocked.ServerEnableUI); err != nil {
		return err
	}
	if err := envBool("HEMMINS_SERVER_TRUST_PROXY_HEADERS", &cfg.Server.TrustProxyHeaders, &cfg.EnvLocked.ServerTrustProxyHeaders); err != nil {
		return err
	}
	if err := envBool("HEMMINS_LOGGING_ACCESS_LOG", &cfg.Logging.AccessLog, &cfg.EnvLocked.LoggingAccessLog); err != nil {
		return err
	}
	if err := envDur("HEMMINS_S3_MAX_PRESIGN_TTL", &cfg.S3.MaxPresignTTL, &cfg.EnvLocked.S3MaxPresignTTL); err != nil {
		return err
	}
	if err := envDur("HEMMINS_UI_SESSION_TTL", &cfg.UI.SessionTTL, &cfg.EnvLocked.UISessionTTL); err != nil {
		return err
	}
	if err := envDur("HEMMINS_UI_SESSION_IDLE_TTL", &cfg.UI.SessionIdleTTL, &cfg.EnvLocked.UISessionIdleTTL); err != nil {
		return err
	}
	if err := envDur("HEMMINS_GC_ORPHAN_SCAN_INTERVAL", &cfg.GC.OrphanScanInterval, &cfg.EnvLocked.GCOrphanScanInterval); err != nil {
		return err
	}
	if err := envDur("HEMMINS_GC_ORPHAN_GRACE_PERIOD", &cfg.GC.OrphanGracePeriod, &cfg.EnvLocked.GCOrphanGracePeriod); err != nil {
		return err
	}
	if err := envDur("HEMMINS_GC_MULTIPART_EXPIRY", &cfg.GC.MultipartExpiry, &cfg.EnvLocked.GCMultipartExpiry); err != nil {
		return err
	}
	return nil
}

// parseBootstrapEnv reads one-time bootstrap credentials from environment variables.
// Per configuration-model.md section 6: these are NEVER stored in config.yaml.
// They are consumed only when the metadata DB is empty.
//
// All four variables must be set together as a complete set.
// Providing only some of them is a misconfiguration and returns an error (fail-fast).
// Per security-model.md section 3.2: Headless bootstrap requires all four variables.
func parseBootstrapEnv() (*BootstrapConfig, error) {
	b := &BootstrapConfig{
		AdminUsername: os.Getenv("HEMMINS_BOOTSTRAP_ADMIN_USERNAME"),
		AdminPassword: os.Getenv("HEMMINS_BOOTSTRAP_ADMIN_PASSWORD"),
		RootAccessKey: os.Getenv("HEMMINS_BOOTSTRAP_ROOT_ACCESS_KEY"),
		RootSecretKey: os.Getenv("HEMMINS_BOOTSTRAP_ROOT_SECRET_KEY"),
	}

	var setCount int
	for _, v := range []string{b.AdminUsername, b.AdminPassword, b.RootAccessKey, b.RootSecretKey} {
		if v != "" {
			setCount++
		}
	}

	switch setCount {
	case 0:
		b.HasValues = false
	case 4:
		b.HasValues = true
	default:
		return nil, fmt.Errorf(
			"partial bootstrap credentials: %d of 4 required variables are set; "+
				"all of HEMMINS_BOOTSTRAP_ADMIN_USERNAME, HEMMINS_BOOTSTRAP_ADMIN_PASSWORD, "+
				"HEMMINS_BOOTSTRAP_ROOT_ACCESS_KEY, HEMMINS_BOOTSTRAP_ROOT_SECRET_KEY "+
				"must be provided together or not at all",
			setCount,
		)
	}

	return b, nil
}
