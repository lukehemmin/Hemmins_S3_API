// Package ui implements the management UI session API.
// Per system-architecture.md section 8 and security-model.md section 6.
package ui

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/lukehemmin/hemmins-s3-api/internal/config"
)

// SettingsView is a read-only projection of Config for the UI settings API.
// It excludes sensitive fields (auth.master_key) and includes metadata about
// environment variable locks and config file state.
//
// Per configuration-model.md section 10.1:
//   - Current effective settings
//   - Environment-locked field indicators
//   - Config file path and read-only state
//   - Path status (exists, writable, kind)
//
// Per security-model.md section 4.3: secret values are NEVER exposed.
type SettingsView struct {
	cfg *config.Config
}

// NewSettingsView creates a read-only settings view from the runtime config.
func NewSettingsView(cfg *config.Config) *SettingsView {
	return &SettingsView{cfg: cfg}
}

// settingsResponse is the JSON structure returned by GET /ui/api/settings.
type settingsResponse struct {
	Server  serverSettingsResponse  `json:"server"`
	S3      s3SettingsResponse      `json:"s3"`
	Paths   pathsSettingsResponse   `json:"paths"`
	UI      uiSettingsResponse      `json:"ui"`
	Logging loggingSettingsResponse `json:"logging"`
	GC      gcSettingsResponse      `json:"gc"`

	// Metadata about the configuration source.
	ConfigFile configFileInfo `json:"configFile"`

	// EnvLocked indicates which fields are overridden by HEMMINS_* environment variables.
	// Per configuration-model.md section 2.1: env-locked fields are read-only in UI.
	EnvLocked envLockedResponse `json:"envLocked"`

	// PathStatus contains filesystem status for each configured path.
	// Per system-architecture.md section 8.1 and product-spec.md section 7.4.
	PathStatus pathStatusResponse `json:"pathStatus"`
}

type serverSettingsResponse struct {
	Listen            string `json:"listen"`
	PublicEndpoint    string `json:"publicEndpoint"`
	EnableUI          bool   `json:"enableUI"`
	TrustProxyHeaders bool   `json:"trustProxyHeaders"`
}

type s3SettingsResponse struct {
	Region            string `json:"region"`
	VirtualHostSuffix string `json:"virtualHostSuffix"`
	MaxPresignTTL     string `json:"maxPresignTTL"` // duration string e.g. "24h0m0s"
}

type pathsSettingsResponse struct {
	MetaDB        string `json:"metaDB"`
	ObjectRoot    string `json:"objectRoot"`
	MultipartRoot string `json:"multipartRoot"`
	TempRoot      string `json:"tempRoot"`
	LogRoot       string `json:"logRoot"`
}

type uiSettingsResponse struct {
	SessionTTL     string `json:"sessionTTL"`     // duration string
	SessionIdleTTL string `json:"sessionIdleTTL"` // duration string
}

type loggingSettingsResponse struct {
	Level     string `json:"level"`
	AccessLog bool   `json:"accessLog"`
}

type gcSettingsResponse struct {
	OrphanScanInterval string `json:"orphanScanInterval"` // duration string
	OrphanGracePeriod  string `json:"orphanGracePeriod"`  // duration string
	MultipartExpiry    string `json:"multipartExpiry"`    // duration string
}

type configFileInfo struct {
	Path     string `json:"path"`     // empty if no config file was loaded
	ReadOnly bool   `json:"readOnly"` // true if config file cannot be written
}

// envLockedResponse mirrors config.EnvLocked for JSON serialization.
// Per configuration-model.md section 2.1: UI must not allow editing locked fields.
type envLockedResponse struct {
	ServerListen            bool `json:"serverListen"`
	ServerPublicEndpoint    bool `json:"serverPublicEndpoint"`
	ServerEnableUI          bool `json:"serverEnableUI"`
	ServerTrustProxyHeaders bool `json:"serverTrustProxyHeaders"`
	S3Region                bool `json:"s3Region"`
	S3VirtualHostSuffix     bool `json:"s3VirtualHostSuffix"`
	S3MaxPresignTTL         bool `json:"s3MaxPresignTTL"`
	PathsMetaDB             bool `json:"pathsMetaDB"`
	PathsObjectRoot         bool `json:"pathsObjectRoot"`
	PathsMultipartRoot      bool `json:"pathsMultipartRoot"`
	PathsTempRoot           bool `json:"pathsTempRoot"`
	PathsLogRoot            bool `json:"pathsLogRoot"`
	UISessionTTL            bool `json:"uiSessionTTL"`
	UISessionIdleTTL        bool `json:"uiSessionIdleTTL"`
	LoggingLevel            bool `json:"loggingLevel"`
	LoggingAccessLog        bool `json:"loggingAccessLog"`
	GCOrphanScanInterval    bool `json:"gcOrphanScanInterval"`
	GCOrphanGracePeriod     bool `json:"gcOrphanGracePeriod"`
	GCMultipartExpiry       bool `json:"gcMultipartExpiry"`
}

// pathStatusResponse contains status for each configured path.
// Per system-architecture.md section 8.1: show exists, writable, kind for each path.
type pathStatusResponse struct {
	MetaDB        pathInfo `json:"metaDB"`
	ObjectRoot    pathInfo `json:"objectRoot"`
	MultipartRoot pathInfo `json:"multipartRoot"`
	TempRoot      pathInfo `json:"tempRoot"`
	LogRoot       pathInfo `json:"logRoot"`
}

// pathInfo describes the filesystem status of a configured path.
// Per product-spec.md section 7.4 and configuration-model.md section 10.1:
// includes disk usage and free space information.
type pathInfo struct {
	Path     string `json:"path"`
	Exists   bool   `json:"exists"`
	Writable bool   `json:"writable"`
	Kind     string `json:"kind"` // "file", "dir", or "unknown"

	// DiskStats contains filesystem capacity information.
	// For directories, stats are for the filesystem containing the directory.
	// For files (e.g., meta_db), stats are for the filesystem containing the parent directory.
	// If the path does not exist, all values are 0.
	DiskStats diskStats `json:"diskStats"`
}

// diskStats contains filesystem capacity information.
// Per product-spec.md section 7.4: disk usage and free space.
type diskStats struct {
	TotalBytes uint64 `json:"totalBytes"` // total filesystem capacity
	FreeBytes  uint64 `json:"freeBytes"`  // available space for unprivileged users
	UsedBytes  uint64 `json:"usedBytes"`  // total - free (approximate)
}

// ToResponse builds the full settings response from the config.
func (sv *SettingsView) ToResponse() *settingsResponse {
	cfg := sv.cfg

	return &settingsResponse{
		Server: serverSettingsResponse{
			Listen:            cfg.Server.Listen,
			PublicEndpoint:    cfg.Server.PublicEndpoint,
			EnableUI:          cfg.Server.EnableUI,
			TrustProxyHeaders: cfg.Server.TrustProxyHeaders,
		},
		S3: s3SettingsResponse{
			Region:            cfg.S3.Region,
			VirtualHostSuffix: cfg.S3.VirtualHostSuffix,
			MaxPresignTTL:     cfg.S3.MaxPresignTTL.String(),
		},
		Paths: pathsSettingsResponse{
			MetaDB:        cfg.Paths.MetaDB,
			ObjectRoot:    cfg.Paths.ObjectRoot,
			MultipartRoot: cfg.Paths.MultipartRoot,
			TempRoot:      cfg.Paths.TempRoot,
			LogRoot:       cfg.Paths.LogRoot,
		},
		UI: uiSettingsResponse{
			SessionTTL:     cfg.UI.SessionTTL.String(),
			SessionIdleTTL: cfg.UI.SessionIdleTTL.String(),
		},
		Logging: loggingSettingsResponse{
			Level:     cfg.Logging.Level,
			AccessLog: cfg.Logging.AccessLog,
		},
		GC: gcSettingsResponse{
			OrphanScanInterval: cfg.GC.OrphanScanInterval.String(),
			OrphanGracePeriod:  cfg.GC.OrphanGracePeriod.String(),
			MultipartExpiry:    cfg.GC.MultipartExpiry.String(),
		},
		ConfigFile: configFileInfo{
			Path:     cfg.ConfigFilePath,
			ReadOnly: cfg.ConfigFileReadOnly,
		},
		EnvLocked: envLockedResponse{
			ServerListen:            cfg.EnvLocked.ServerListen,
			ServerPublicEndpoint:    cfg.EnvLocked.ServerPublicEndpoint,
			ServerEnableUI:          cfg.EnvLocked.ServerEnableUI,
			ServerTrustProxyHeaders: cfg.EnvLocked.ServerTrustProxyHeaders,
			S3Region:                cfg.EnvLocked.S3Region,
			S3VirtualHostSuffix:     cfg.EnvLocked.S3VirtualHostSuffix,
			S3MaxPresignTTL:         cfg.EnvLocked.S3MaxPresignTTL,
			PathsMetaDB:             cfg.EnvLocked.PathsMetaDB,
			PathsObjectRoot:         cfg.EnvLocked.PathsObjectRoot,
			PathsMultipartRoot:      cfg.EnvLocked.PathsMultipartRoot,
			PathsTempRoot:           cfg.EnvLocked.PathsTempRoot,
			PathsLogRoot:            cfg.EnvLocked.PathsLogRoot,
			UISessionTTL:            cfg.EnvLocked.UISessionTTL,
			UISessionIdleTTL:        cfg.EnvLocked.UISessionIdleTTL,
			LoggingLevel:            cfg.EnvLocked.LoggingLevel,
			LoggingAccessLog:        cfg.EnvLocked.LoggingAccessLog,
			GCOrphanScanInterval:    cfg.EnvLocked.GCOrphanScanInterval,
			GCOrphanGracePeriod:     cfg.EnvLocked.GCOrphanGracePeriod,
			GCMultipartExpiry:       cfg.EnvLocked.GCMultipartExpiry,
		},
		PathStatus: pathStatusResponse{
			MetaDB:        checkPath(cfg.Paths.MetaDB),
			ObjectRoot:    checkPath(cfg.Paths.ObjectRoot),
			MultipartRoot: checkPath(cfg.Paths.MultipartRoot),
			TempRoot:      checkPath(cfg.Paths.TempRoot),
			LogRoot:       checkPath(cfg.Paths.LogRoot),
		},
	}
}

// checkPath inspects the filesystem and returns pathInfo for the given path.
// For meta_db, the path is a file; for others, it is a directory.
// Per product-spec.md section 7.4: includes disk stats for each path.
func checkPath(path string) pathInfo {
	info := pathInfo{Path: path}

	if path == "" {
		info.Kind = "unknown"
		// DiskStats stays zero-valued for empty path.
		return info
	}

	fi, err := os.Stat(path)
	if err != nil {
		// Path does not exist or is not accessible.
		// DiskStats stays zero-valued per policy: non-existent path → 0.
		info.Exists = false
		info.Writable = false
		info.Kind = "unknown"
		return info
	}

	info.Exists = true
	if fi.IsDir() {
		info.Kind = "dir"
		info.Writable = isDirWritable(path)
		// Get disk stats for the directory itself.
		info.DiskStats = getDiskStats(path)
	} else {
		info.Kind = "file"
		info.Writable = isFileWritable(path)
		// For files (e.g., meta_db), get disk stats for the parent directory.
		info.DiskStats = getDiskStats(filepath.Dir(path))
	}

	return info
}

// isDirWritable checks if we can write to the directory by creating a temp file.
func isDirWritable(dir string) bool {
	f, err := os.CreateTemp(dir, ".hemmins-writecheck-*")
	if err != nil {
		return false
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return true
}

// isFileWritable checks if we can open the file for writing.
func isFileWritable(path string) bool {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// handleSettings implements GET /ui/api/settings.
// Returns the current effective configuration (excluding secrets) and path status.
// Session required; 401 if not authenticated.
// Per product-spec.md section 7.4 and configuration-model.md section 10.1.
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if _, ok := s.requireSession(w, r); !ok {
		return
	}

	if s.settingsView == nil {
		// Settings view not configured — programming error, not user error.
		writeJSONError(w, http.StatusInternalServerError, "settings not available")
		return
	}

	resp := s.settingsView.ToResponse()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// durationString converts a time.Duration to a human-readable string.
// This is used for JSON serialization of duration fields.
func durationString(d time.Duration) string {
	return d.String()
}
