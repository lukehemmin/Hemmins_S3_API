package config

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level runtime configuration.
// Schema version 1 per configuration-model.md.
type Config struct {
	Version int           `yaml:"version"`
	Server  ServerConfig  `yaml:"server"`
	S3      S3Config      `yaml:"s3"`
	Paths   PathsConfig   `yaml:"paths"`
	Auth    AuthConfig    `yaml:"auth"`
	UI      UIConfig      `yaml:"ui"`
	Logging LoggingConfig `yaml:"logging"`
	GC      GCConfig      `yaml:"gc"`

	// EnvLocked tracks which leaf fields are overridden by HEMMINS_* environment variables.
	// The web UI must not allow editing locked fields.
	EnvLocked EnvLocked `yaml:"-"`

	// ConfigFilePath is the resolved config file path (empty if none found).
	ConfigFilePath string `yaml:"-"`

	// ConfigFileReadOnly indicates the config file cannot be written by the server.
	ConfigFileReadOnly bool `yaml:"-"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Listen            string `yaml:"listen"`
	PublicEndpoint    string `yaml:"public_endpoint"`
	EnableUI          bool   `yaml:"enable_ui"`
	TrustProxyHeaders bool   `yaml:"trust_proxy_headers"`
}

// S3Config holds S3 protocol settings.
type S3Config struct {
	Region            string   `yaml:"region"`
	VirtualHostSuffix string   `yaml:"virtual_host_suffix"`
	MaxPresignTTL     Duration `yaml:"max_presign_ttl"`
}

// PathsConfig holds filesystem path settings.
type PathsConfig struct {
	MetaDB        string `yaml:"meta_db"`
	ObjectRoot    string `yaml:"object_root"`
	MultipartRoot string `yaml:"multipart_root"`
	TempRoot      string `yaml:"temp_root"`
	LogRoot       string `yaml:"log_root"`
}

// AuthConfig holds authentication settings.
type AuthConfig struct {
	MasterKey string `yaml:"master_key"`
}

// UIConfig holds web UI settings.
type UIConfig struct {
	SessionTTL     Duration `yaml:"session_ttl"`
	SessionIdleTTL Duration `yaml:"session_idle_ttl"`
}

// LoggingConfig holds logging settings.
type LoggingConfig struct {
	Level     string `yaml:"level"`
	AccessLog bool   `yaml:"access_log"`
}

// GCConfig holds garbage collection settings.
type GCConfig struct {
	OrphanScanInterval Duration `yaml:"orphan_scan_interval"`
	OrphanGracePeriod  Duration `yaml:"orphan_grace_period"`
	MultipartExpiry    Duration `yaml:"multipart_expiry"`
}

// BootstrapConfig holds one-time initialization credentials.
// These are consumed only when the metadata DB is empty and are NEVER stored in config.yaml.
type BootstrapConfig struct {
	AdminUsername string
	AdminPassword string
	RootAccessKey string
	RootSecretKey string
	HasValues     bool
}

// EnvLocked tracks which config fields are locked by HEMMINS_* environment variables.
// The web UI must treat locked fields as read-only.
type EnvLocked struct {
	ServerListen            bool
	ServerPublicEndpoint    bool
	ServerEnableUI          bool
	ServerTrustProxyHeaders bool
	S3Region                bool
	S3VirtualHostSuffix     bool
	S3MaxPresignTTL         bool
	PathsMetaDB             bool
	PathsObjectRoot         bool
	PathsMultipartRoot      bool
	PathsTempRoot           bool
	PathsLogRoot            bool
	AuthMasterKey           bool
	UISessionTTL            bool
	UISessionIdleTTL        bool
	LoggingLevel            bool
	LoggingAccessLog        bool
	GCOrphanScanInterval    bool
	GCOrphanGracePeriod     bool
	GCMultipartExpiry       bool
}

// Duration is a time.Duration that unmarshals from YAML duration strings (e.g. "12h", "30m").
type Duration struct {
	time.Duration
}

// UnmarshalYAML implements yaml.Unmarshaler for Duration.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	dur, err := time.ParseDuration(value.Value)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", value.Value, err)
	}
	d.Duration = dur
	return nil
}

// String implements fmt.Stringer for Duration.
func (d Duration) String() string {
	return d.Duration.String()
}
