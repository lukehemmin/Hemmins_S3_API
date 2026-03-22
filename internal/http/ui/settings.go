// Package ui implements the management UI session API.
// Per system-architecture.md section 8 and security-model.md section 6.
package ui

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/lukehemmin/hemmins-s3-api/internal/config"
)

// SettingsView is a projection of Config for the UI settings API.
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
//
// The stored config pointer is replaced atomically on hot-reload, so concurrent
// GET /ui/api/settings requests always see a consistent snapshot.
type SettingsView struct {
	cfgVal atomic.Value // always stores *config.Config; never nil after NewSettingsView
}

// NewSettingsView creates a settings view from the runtime config.
func NewSettingsView(cfg *config.Config) *SettingsView {
	sv := &SettingsView{}
	sv.cfgVal.Store(cfg)
	return sv
}

// Cfg returns the current runtime config pointer. Safe for concurrent use.
func (sv *SettingsView) Cfg() *config.Config {
	return sv.cfgVal.Load().(*config.Config)
}

// UpdateCfg atomically replaces the stored config pointer.
// The caller must pass a complete Config that preserves all non-safe-subset
// fields (ConfigFilePath, EnvLocked, etc.) from the previous config.
func (sv *SettingsView) UpdateCfg(cfg *config.Config) {
	sv.cfgVal.Store(cfg)
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
	cfg := sv.Cfg() // atomic load; safe for concurrent use

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

// handleSettings implements GET and POST /ui/api/settings.
// GET: Returns the current effective configuration (excluding secrets) and path status.
// POST: Saves the safe subset of configuration to the config file.
// Session required; 401 if not authenticated.
// Per product-spec.md section 7.4 and configuration-model.md sections 9.2, 10.1, 10.2.
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleSettingsGet(w, r)
	case http.MethodPost:
		s.handleSettingsSave(w, r)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleSettingsGet implements GET /ui/api/settings.
func (s *Server) handleSettingsGet(w http.ResponseWriter, r *http.Request) {
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

// SettingsSavePayload defines the JSON structure for POST /ui/api/settings.
// Per configuration-model.md section 10.2: only a safe subset is UI-editable.
// Unsupported fields are rejected with 400.
//
// Safe subset (all "즉시 반영 가능" per docs):
//   - server.public_endpoint
//   - s3.max_presign_ttl
//   - logging.level
//   - logging.access_log
//   - ui.session_ttl
//   - ui.session_idle_ttl
type SettingsSavePayload struct {
	Server  *serverSavePayload  `json:"server,omitempty"`
	S3      *s3SavePayload      `json:"s3,omitempty"`
	Logging *loggingSavePayload `json:"logging,omitempty"`
	UI      *uiSavePayload      `json:"ui,omitempty"`
}

type serverSavePayload struct {
	PublicEndpoint *string `json:"publicEndpoint,omitempty"`
}

type s3SavePayload struct {
	MaxPresignTTL *string `json:"maxPresignTTL,omitempty"`
}

type loggingSavePayload struct {
	Level     *string `json:"level,omitempty"`
	AccessLog *bool   `json:"accessLog,omitempty"`
}

type uiSavePayload struct {
	SessionTTL     *string `json:"sessionTTL,omitempty"`
	SessionIdleTTL *string `json:"sessionIdleTTL,omitempty"`
}

// settingsSaveResponse is the JSON response for POST /ui/api/settings.
type settingsSaveResponse struct {
	Saved           bool `json:"saved"`
	RequiresRestart bool `json:"requiresRestart"`
}

// handleSettingsSave implements POST /ui/api/settings.
// Saves the safe subset of configuration to the config file.
// Per configuration-model.md sections 9.2 and 10.2.
//
// Requirements:
//   - Valid session (401 otherwise)
//   - Valid CSRF token (403 otherwise)
//   - Config file exists and is writable (409 otherwise)
//   - Payload contains only safe subset fields (400 otherwise)
//   - Fields not locked by env vars (400 otherwise)
//   - Payload passes validation (400 otherwise)
//
// Response:
//   - 200: {"saved": true, "requiresRestart": <bool>}
//   - 400: validation error or unsupported field
//   - 401: no session
//   - 403: CSRF validation failed
//   - 409: config file not writable
func (s *Server) handleSettingsSave(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}

	if s.settingsView == nil || s.settingsView.Cfg() == nil {
		writeJSONError(w, http.StatusInternalServerError, "settings not available")
		return
	}
	cfg := s.settingsView.Cfg()

	// Check config file is writable.
	if err := config.CanSaveConfig(cfg); err != nil {
		log.Printf("AUDIT settings_save_rejected user=%q reason=config_not_writable path=%q", sess.Username, cfg.ConfigFilePath)
		writeJSONError(w, http.StatusConflict, "config file is not writable")
		return
	}

	// Read body once for both validation and parsing.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	// Reject any unsupported fields via strict check.
	if err := checkUnsupportedFields(body); err != nil {
		log.Printf("AUDIT settings_save_rejected user=%q reason=unsupported_field err=%q", sess.Username, err.Error())
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Parse payload.
	var payload SettingsSavePayload
	if err := json.Unmarshal(body, &payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Check env-locked fields.
	if err := s.checkEnvLocked(cfg, &payload); err != nil {
		log.Printf("AUDIT settings_save_rejected user=%q reason=env_locked err=%q", sess.Username, err.Error())
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Build a patch containing only the safe-subset fields from the payload.
	patch := s.buildPatch(&payload)

	// Build candidate YAML bytes: existing file content + patch applied.
	// This errors if the file does not exist, ensuring we never create a new
	// file from scratch (which would produce an incomplete config).
	candidateBytes, err := config.BuildPatchedBytes(cfg.ConfigFilePath, patch)
	if err != nil {
		log.Printf("ERROR settings_save_build_candidate user=%q err=%v", sess.Username, err)
		writeJSONError(w, http.StatusInternalServerError, "failed to build config candidate")
		return
	}

	// Parse the candidate bytes (defaults + file values; no env overlay yet).
	// This catches structurally invalid values such as unparseable duration strings
	// before anything is written to disk.
	candidateCfg, err := config.ParseCandidateConfig(candidateBytes)
	if err != nil {
		log.Printf("AUDIT settings_save_rejected user=%q reason=candidate_parse_error err=%q", sess.Username, err.Error())
		writeJSONError(w, http.StatusBadRequest, "candidate config is invalid: "+err.Error())
		return
	}

	// Overlay the currently-active env-locked values from the runtime config.
	// This mirrors what the next startup would produce (file + same env vars),
	// ensuring required fields provided by env (e.g. auth.master_key, paths.*)
	// are present before Validate runs.
	config.MergeRuntimeEnvLocked(candidateCfg, cfg)

	// Validate the candidate config.
	if err := config.Validate(candidateCfg); err != nil {
		log.Printf("AUDIT settings_save_rejected user=%q reason=validation_failed err=%q", sess.Username, err.Error())
		writeJSONError(w, http.StatusBadRequest, "validation failed: "+err.Error())
		return
	}

	// Write the pre-validated bytes atomically.
	if err := config.SaveRawBytes(cfg.ConfigFilePath, candidateBytes); err != nil {
		log.Printf("ERROR settings_save_failed user=%q err=%v", sess.Username, err)
		writeJSONError(w, http.StatusInternalServerError, "failed to save config file")
		return
	}

	log.Printf("AUDIT settings_save_success user=%q path=%q", sess.Username, cfg.ConfigFilePath)

	// Apply the safe subset to the runtime in-memory state immediately.
	// Per configuration-model.md section 8.3: safe subset is "즉시 반영 가능".
	s.applyRuntimeReload(&payload)

	resp := settingsSaveResponse{
		Saved:           true,
		RequiresRestart: computeRequiresRestart(&payload),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// buildPatch creates a ConfigPatch from the validated payload.
// Only safe-subset fields from the payload are included.
// This ensures only explicitly requested fields are written to the config file.
func (s *Server) buildPatch(payload *SettingsSavePayload) *config.ConfigPatch {
	patch := &config.ConfigPatch{}
	if payload.Server != nil && payload.Server.PublicEndpoint != nil {
		patch.ServerPublicEndpoint = payload.Server.PublicEndpoint
	}
	if payload.S3 != nil && payload.S3.MaxPresignTTL != nil {
		patch.S3MaxPresignTTL = payload.S3.MaxPresignTTL
	}
	if payload.Logging != nil {
		if payload.Logging.Level != nil {
			patch.LoggingLevel = payload.Logging.Level
		}
		if payload.Logging.AccessLog != nil {
			patch.LoggingAccessLog = payload.Logging.AccessLog
		}
	}
	if payload.UI != nil {
		if payload.UI.SessionTTL != nil {
			patch.UISessionTTL = payload.UI.SessionTTL
		}
		if payload.UI.SessionIdleTTL != nil {
			patch.UISessionIdleTTL = payload.UI.SessionIdleTTL
		}
	}
	return patch
}

// checkEnvLocked ensures no env-locked field is being modified.
func (s *Server) checkEnvLocked(cfg *config.Config, payload *SettingsSavePayload) error {
	if payload.Server != nil && payload.Server.PublicEndpoint != nil && cfg.EnvLocked.ServerPublicEndpoint {
		return fmt.Errorf("server.publicEndpoint is locked by environment variable")
	}
	if payload.S3 != nil && payload.S3.MaxPresignTTL != nil && cfg.EnvLocked.S3MaxPresignTTL {
		return fmt.Errorf("s3.maxPresignTTL is locked by environment variable")
	}
	if payload.Logging != nil {
		if payload.Logging.Level != nil && cfg.EnvLocked.LoggingLevel {
			return fmt.Errorf("logging.level is locked by environment variable")
		}
		if payload.Logging.AccessLog != nil && cfg.EnvLocked.LoggingAccessLog {
			return fmt.Errorf("logging.accessLog is locked by environment variable")
		}
	}
	if payload.UI != nil {
		if payload.UI.SessionTTL != nil && cfg.EnvLocked.UISessionTTL {
			return fmt.Errorf("ui.sessionTTL is locked by environment variable")
		}
		if payload.UI.SessionIdleTTL != nil && cfg.EnvLocked.UISessionIdleTTL {
			return fmt.Errorf("ui.sessionIdleTTL is locked by environment variable")
		}
	}
	return nil
}

// applyPayload applies the payload changes to a copy of the config.
func (s *Server) applyPayload(cfg *config.Config, payload *SettingsSavePayload) *config.Config {
	// Create a shallow copy of the config.
	updated := *cfg

	if payload.Server != nil && payload.Server.PublicEndpoint != nil {
		updated.Server.PublicEndpoint = *payload.Server.PublicEndpoint
	}
	if payload.S3 != nil && payload.S3.MaxPresignTTL != nil {
		if d, err := time.ParseDuration(*payload.S3.MaxPresignTTL); err == nil {
			updated.S3.MaxPresignTTL = config.Duration{Duration: d}
		}
	}
	if payload.Logging != nil {
		if payload.Logging.Level != nil {
			updated.Logging.Level = *payload.Logging.Level
		}
		if payload.Logging.AccessLog != nil {
			updated.Logging.AccessLog = *payload.Logging.AccessLog
		}
	}
	if payload.UI != nil {
		if payload.UI.SessionTTL != nil {
			if d, err := time.ParseDuration(*payload.UI.SessionTTL); err == nil {
				updated.UI.SessionTTL = config.Duration{Duration: d}
			}
		}
		if payload.UI.SessionIdleTTL != nil {
			if d, err := time.ParseDuration(*payload.UI.SessionIdleTTL); err == nil {
				updated.UI.SessionIdleTTL = config.Duration{Duration: d}
			}
		}
	}

	return &updated
}

// computeRequiresRestart returns true only if the payload contains a field that
// requires a server restart to take effect.
// All fields in SettingsSavePayload belong to the safe subset that supports
// runtime hot-reload via applyRuntimeReload, so this always returns false.
// Per configuration-model.md section 8.3: safe subset is "즉시 반영 가능".
func computeRequiresRestart(payload *SettingsSavePayload) bool {
	_ = payload // all fields in SettingsSavePayload are hot-reloadable safe-subset fields
	return false
}

// applyRuntimeReload applies the safe subset from payload to the runtime in-memory state.
// Called after a successful config file write. Thread-safe.
//
// Session TTL policy:
//   - New sessions created after this call use the new TTL values.
//   - Existing sessions retain the TTL captured at their creation time (see Session.TTL).
//
// Rationale: conservative approach for a single-admin tool. Retroactive session
// shortening (security tightening) is deferred to keep active admin sessions
// stable during settings changes. Retroactive extension is unnecessary.
// Per configuration-model.md section 8.3.
func (s *Server) applyRuntimeReload(payload *SettingsSavePayload) {
	if s.settingsView == nil {
		return
	}

	// Build an updated copy of the current runtime config.
	// applyPayload copies all fields and updates only the payload fields,
	// preserving ConfigFilePath, EnvLocked, and other non-payload metadata.
	currentCfg := s.settingsView.Cfg()
	updated := s.applyPayload(currentCfg, payload)

	// Atomically publish the updated config for GET /ui/api/settings.
	s.settingsView.UpdateCfg(updated)

	// Update Server's presign hot-reload fields under write lock.
	s.reloadMu.Lock()
	s.publicEndpoint = updated.Server.PublicEndpoint
	s.maxPresignTTL = updated.S3.MaxPresignTTL.Duration
	s.reloadMu.Unlock()

	// Update session store TTLs for newly created sessions.
	// Only update if UI TTL fields were present in the payload.
	if payload.UI != nil && (payload.UI.SessionTTL != nil || payload.UI.SessionIdleTTL != nil) {
		s.store.UpdateTTLs(updated.UI.SessionTTL.Duration, updated.UI.SessionIdleTTL.Duration)
	}

	log.Printf("INFO settings_hot_reload publicEndpoint=%q maxPresignTTL=%s loggingLevel=%q loggingAccessLog=%v sessionTTL=%s sessionIdleTTL=%s",
		updated.Server.PublicEndpoint,
		updated.S3.MaxPresignTTL,
		updated.Logging.Level,
		updated.Logging.AccessLog,
		updated.UI.SessionTTL,
		updated.UI.SessionIdleTTL,
	)
}

// checkUnsupportedFields validates the raw JSON body for any forbidden keys.
// This is used to strictly reject payloads that attempt to modify sensitive fields
// like auth.master_key, paths.*, or other restart-required settings.
func checkUnsupportedFields(body []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return fmt.Errorf("invalid JSON")
	}

	// Allowed top-level keys.
	allowedTopLevel := map[string]bool{
		"server":  true,
		"s3":      true,
		"logging": true,
		"ui":      true,
	}
	for key := range raw {
		if !allowedTopLevel[key] {
			return fmt.Errorf("unsupported field: %s", key)
		}
	}

	// Check nested server fields.
	if serverRaw, ok := raw["server"]; ok {
		var server map[string]json.RawMessage
		if err := json.Unmarshal(serverRaw, &server); err != nil {
			return fmt.Errorf("invalid server object")
		}
		allowedServer := map[string]bool{"publicEndpoint": true}
		for key := range server {
			if !allowedServer[key] {
				return fmt.Errorf("unsupported field: server.%s", key)
			}
		}
	}

	// Check nested s3 fields.
	if s3Raw, ok := raw["s3"]; ok {
		var s3 map[string]json.RawMessage
		if err := json.Unmarshal(s3Raw, &s3); err != nil {
			return fmt.Errorf("invalid s3 object")
		}
		allowedS3 := map[string]bool{"maxPresignTTL": true}
		for key := range s3 {
			if !allowedS3[key] {
				return fmt.Errorf("unsupported field: s3.%s", key)
			}
		}
	}

	// Check nested logging fields.
	if loggingRaw, ok := raw["logging"]; ok {
		var logging map[string]json.RawMessage
		if err := json.Unmarshal(loggingRaw, &logging); err != nil {
			return fmt.Errorf("invalid logging object")
		}
		allowedLogging := map[string]bool{"level": true, "accessLog": true}
		for key := range logging {
			if !allowedLogging[key] {
				return fmt.Errorf("unsupported field: logging.%s", key)
			}
		}
	}

	// Check nested ui fields.
	if uiRaw, ok := raw["ui"]; ok {
		var ui map[string]json.RawMessage
		if err := json.Unmarshal(uiRaw, &ui); err != nil {
			return fmt.Errorf("invalid ui object")
		}
		allowedUI := map[string]bool{"sessionTTL": true, "sessionIdleTTL": true}
		for key := range ui {
			if !allowedUI[key] {
				return fmt.Errorf("unsupported field: ui.%s", key)
			}
		}
	}

	return nil
}
