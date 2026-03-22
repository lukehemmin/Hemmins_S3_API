package ui_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lukehemmin/hemmins-s3-api/internal/auth"
	"github.com/lukehemmin/hemmins-s3-api/internal/config"
	ui "github.com/lukehemmin/hemmins-s3-api/internal/http/ui"
	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
	"gopkg.in/yaml.v3"
)

// setupWritableConfig creates a temp config file and returns a config with writable path.
func setupWritableConfig(t *testing.T) (*config.Config, string) {
	t.Helper()
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	cfg := &config.Config{
		Version: 1,
		Server: config.ServerConfig{
			Listen:            ":9000",
			PublicEndpoint:    "http://localhost:9000",
			EnableUI:          true,
			TrustProxyHeaders: false,
		},
		S3: config.S3Config{
			Region:            "us-east-1",
			VirtualHostSuffix: "",
			MaxPresignTTL:     config.Duration{Duration: 24 * time.Hour},
		},
		Paths: config.PathsConfig{
			MetaDB:        filepath.Join(tempDir, "meta", "metadata.db"),
			ObjectRoot:    filepath.Join(tempDir, "objects"),
			MultipartRoot: filepath.Join(tempDir, "multipart"),
			TempRoot:      filepath.Join(tempDir, "tmp"),
			LogRoot:       filepath.Join(tempDir, "logs"),
		},
		Auth: config.AuthConfig{
			MasterKey: "test-master-key-32-bytes-minimum!",
		},
		UI: config.UIConfig{
			SessionTTL:     config.Duration{Duration: 12 * time.Hour},
			SessionIdleTTL: config.Duration{Duration: 30 * time.Minute},
		},
		Logging: config.LoggingConfig{
			Level:     "info",
			AccessLog: true,
		},
		GC: config.GCConfig{
			OrphanScanInterval: config.Duration{Duration: 24 * time.Hour},
			OrphanGracePeriod:  config.Duration{Duration: 1 * time.Hour},
			MultipartExpiry:    config.Duration{Duration: 24 * time.Hour},
		},
		ConfigFilePath:     configPath,
		ConfigFileReadOnly: false,
	}

	// Write initial config file.
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	return cfg, configPath
}

// setupTestUIServerForSave creates a test server with writable config.
func setupTestUIServerForSave(t *testing.T, cfg *config.Config) (http.Handler, *metadata.DB) {
	t.Helper()
	db, err := metadata.Open(":memory:")
	if err != nil {
		t.Fatalf("metadata.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	pwHash, err := auth.HashPassword(testAdminPassword)
	if err != nil {
		t.Fatalf("auth.HashPassword: %v", err)
	}
	ciphertext, err := auth.EncryptSecret(testMasterKey, "testsecret123")
	if err != nil {
		t.Fatalf("auth.EncryptSecret: %v", err)
	}
	if err := db.Bootstrap(testAdminUsername, pwHash, testAccessKey, ciphertext); err != nil {
		t.Fatalf("db.Bootstrap: %v", err)
	}

	store := ui.NewSessionStore(12*time.Hour, 30*time.Minute)
	srv := ui.NewServer(db, store, false)
	srv.SetConfig(cfg)
	return srv.Handler(), db
}

// doSettingsSave issues POST /ui/api/settings with the given payload.
func doSettingsSave(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encoding body: %v", err)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/api/settings", &buf)
	req.Header.Set("Content-Type", "application/json")
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// Test 1: POST /ui/api/settings with valid session + CSRF + writable config → success.
func TestSettingsSave_Success(t *testing.T) {
	cfg, configPath := setupWritableConfig(t)
	handler, _ := setupTestUIServerForSave(t, cfg)

	// Login
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Get CSRF token
	csrfRR := doGetCSRF(t, handler, cookies)
	if csrfRR.Code != http.StatusOK {
		t.Fatalf("csrf failed: %d", csrfRR.Code)
	}
	var csrfResp map[string]string
	if err := json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp); err != nil {
		t.Fatalf("parsing csrf: %v", err)
	}
	csrf := csrfResp["token"]
	cookies = append(cookies, csrfRR.Result().Cookies()...)

	// Save settings
	payload := map[string]interface{}{
		"logging": map[string]interface{}{
			"level": "debug",
		},
	}
	rr := doSettingsSave(t, handler, cookies, csrf, payload)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if resp["saved"] != true {
		t.Errorf("expected saved=true, got %v", resp["saved"])
	}
	if _, ok := resp["requiresRestart"]; !ok {
		t.Error("missing requiresRestart in response")
	}

	// Verify file was written
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("reading config file: %v", err)
	}
	if !bytes.Contains(data, []byte("debug")) {
		t.Error("config file does not contain updated logging level")
	}
}

// Test 2: POST /ui/api/settings without session → 401.
func TestSettingsSave_NoSession(t *testing.T) {
	cfg, _ := setupWritableConfig(t)
	handler, _ := setupTestUIServerForSave(t, cfg)

	payload := map[string]interface{}{
		"logging": map[string]interface{}{
			"level": "debug",
		},
	}
	rr := doSettingsSave(t, handler, nil, "sometoken", payload)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// Test 3: POST /ui/api/settings without CSRF → 403.
func TestSettingsSave_MissingCSRF(t *testing.T) {
	cfg, _ := setupWritableConfig(t)
	handler, _ := setupTestUIServerForSave(t, cfg)

	// Login
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	payload := map[string]interface{}{
		"logging": map[string]interface{}{
			"level": "debug",
		},
	}
	rr := doSettingsSave(t, handler, cookies, "", payload)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 4: POST /ui/api/settings with read-only config file → 409.
func TestSettingsSave_ReadOnlyConfig(t *testing.T) {
	cfg, _ := setupWritableConfig(t)
	cfg.ConfigFileReadOnly = true // Mark as read-only
	handler, _ := setupTestUIServerForSave(t, cfg)

	// Login
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Get CSRF
	csrfRR := doGetCSRF(t, handler, cookies)
	var csrfResp map[string]string
	json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp)
	csrf := csrfResp["token"]
	cookies = append(cookies, csrfRR.Result().Cookies()...)

	payload := map[string]interface{}{
		"logging": map[string]interface{}{
			"level": "debug",
		},
	}
	rr := doSettingsSave(t, handler, cookies, csrf, payload)

	if rr.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 5: POST /ui/api/settings with env-locked field → 400.
func TestSettingsSave_EnvLockedField(t *testing.T) {
	cfg, _ := setupWritableConfig(t)
	cfg.EnvLocked.LoggingLevel = true // Mark logging.level as env-locked
	handler, _ := setupTestUIServerForSave(t, cfg)

	// Login
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Get CSRF
	csrfRR := doGetCSRF(t, handler, cookies)
	var csrfResp map[string]string
	json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp)
	csrf := csrfResp["token"]
	cookies = append(cookies, csrfRR.Result().Cookies()...)

	payload := map[string]interface{}{
		"logging": map[string]interface{}{
			"level": "debug",
		},
	}
	rr := doSettingsSave(t, handler, cookies, csrf, payload)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	errMsg, _ := resp["error"].(string)
	if errMsg == "" || !contains(errMsg, "locked") {
		t.Errorf("expected error about locked field, got %q", errMsg)
	}
}

// Test 6: POST /ui/api/settings with invalid logging.level → 400.
func TestSettingsSave_InvalidLoggingLevel(t *testing.T) {
	cfg, _ := setupWritableConfig(t)
	handler, _ := setupTestUIServerForSave(t, cfg)

	// Login
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Get CSRF
	csrfRR := doGetCSRF(t, handler, cookies)
	var csrfResp map[string]string
	json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp)
	csrf := csrfResp["token"]
	cookies = append(cookies, csrfRR.Result().Cookies()...)

	payload := map[string]interface{}{
		"logging": map[string]interface{}{
			"level": "invalid_level",
		},
	}
	rr := doSettingsSave(t, handler, cookies, csrf, payload)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	errMsg, _ := resp["error"].(string)
	if errMsg == "" || !contains(errMsg, "logging.level") {
		t.Errorf("expected error about logging.level, got %q", errMsg)
	}
}

// Test 7: POST /ui/api/settings with ui.session_idle_ttl > ui.session_ttl → 400.
func TestSettingsSave_IdleTTLExceedsSessionTTL(t *testing.T) {
	cfg, _ := setupWritableConfig(t)
	handler, _ := setupTestUIServerForSave(t, cfg)

	// Login
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Get CSRF
	csrfRR := doGetCSRF(t, handler, cookies)
	var csrfResp map[string]string
	json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp)
	csrf := csrfResp["token"]
	cookies = append(cookies, csrfRR.Result().Cookies()...)

	// session_ttl = 12h (default), trying to set idle_ttl = 24h
	payload := map[string]interface{}{
		"ui": map[string]interface{}{
			"sessionIdleTTL": "24h",
		},
	}
	rr := doSettingsSave(t, handler, cookies, csrf, payload)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	errMsg, _ := resp["error"].(string)
	if errMsg == "" || !contains(errMsg, "session_idle_ttl") {
		t.Errorf("expected error about session_idle_ttl, got %q", errMsg)
	}
}

// Test 8: POST /ui/api/settings with unsupported field (paths) → 400.
func TestSettingsSave_UnsupportedFieldPaths(t *testing.T) {
	cfg, _ := setupWritableConfig(t)
	handler, _ := setupTestUIServerForSave(t, cfg)

	// Login
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Get CSRF
	csrfRR := doGetCSRF(t, handler, cookies)
	var csrfResp map[string]string
	json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp)
	csrf := csrfResp["token"]
	cookies = append(cookies, csrfRR.Result().Cookies()...)

	payload := map[string]interface{}{
		"paths": map[string]interface{}{
			"objectRoot": "/new/path",
		},
	}
	rr := doSettingsSave(t, handler, cookies, csrf, payload)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	errMsg, _ := resp["error"].(string)
	if errMsg == "" || !contains(errMsg, "unsupported") {
		t.Errorf("expected error about unsupported field, got %q", errMsg)
	}
}

// Test 9: POST /ui/api/settings with auth.master_key → 400.
func TestSettingsSave_MasterKeyAttempt(t *testing.T) {
	cfg, _ := setupWritableConfig(t)
	handler, _ := setupTestUIServerForSave(t, cfg)

	// Login
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Get CSRF
	csrfRR := doGetCSRF(t, handler, cookies)
	var csrfResp map[string]string
	json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp)
	csrf := csrfResp["token"]
	cookies = append(cookies, csrfRR.Result().Cookies()...)

	payload := map[string]interface{}{
		"auth": map[string]interface{}{
			"masterKey": "new-master-key-attempt",
		},
	}
	rr := doSettingsSave(t, handler, cookies, csrf, payload)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	errMsg, _ := resp["error"].(string)
	if errMsg == "" || !contains(errMsg, "unsupported") {
		t.Errorf("expected error about unsupported field, got %q", errMsg)
	}
}

// Test 10: POST /ui/api/settings with server.listen (restart-required) → 400.
func TestSettingsSave_ServerListenReject(t *testing.T) {
	cfg, _ := setupWritableConfig(t)
	handler, _ := setupTestUIServerForSave(t, cfg)

	// Login
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Get CSRF
	csrfRR := doGetCSRF(t, handler, cookies)
	var csrfResp map[string]string
	json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp)
	csrf := csrfResp["token"]
	cookies = append(cookies, csrfRR.Result().Cookies()...)

	payload := map[string]interface{}{
		"server": map[string]interface{}{
			"listen": ":8080",
		},
	}
	rr := doSettingsSave(t, handler, cookies, csrf, payload)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	errMsg, _ := resp["error"].(string)
	if errMsg == "" || !contains(errMsg, "unsupported") {
		t.Errorf("expected error about unsupported field, got %q", errMsg)
	}
}

// Test 11: Save creates backup file.
func TestSettingsSave_CreatesBackup(t *testing.T) {
	cfg, configPath := setupWritableConfig(t)
	handler, _ := setupTestUIServerForSave(t, cfg)

	// Login
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Get CSRF
	csrfRR := doGetCSRF(t, handler, cookies)
	var csrfResp map[string]string
	json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp)
	csrf := csrfResp["token"]
	cookies = append(cookies, csrfRR.Result().Cookies()...)

	payload := map[string]interface{}{
		"logging": map[string]interface{}{
			"level": "warn",
		},
	}
	rr := doSettingsSave(t, handler, cookies, csrf, payload)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Check backup was created
	backupPath := configPath + ".bak"
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		t.Error("backup file was not created")
	}
}

// Test 12: Save all safe subset fields at once.
func TestSettingsSave_AllSafeFields(t *testing.T) {
	cfg, configPath := setupWritableConfig(t)
	handler, _ := setupTestUIServerForSave(t, cfg)

	// Login
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Get CSRF
	csrfRR := doGetCSRF(t, handler, cookies)
	var csrfResp map[string]string
	json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp)
	csrf := csrfResp["token"]
	cookies = append(cookies, csrfRR.Result().Cookies()...)

	payload := map[string]interface{}{
		"server": map[string]interface{}{
			"publicEndpoint": "https://example.com",
		},
		"s3": map[string]interface{}{
			"maxPresignTTL": "48h",
		},
		"logging": map[string]interface{}{
			"level":     "debug",
			"accessLog": false,
		},
		"ui": map[string]interface{}{
			"sessionTTL":     "6h",
			"sessionIdleTTL": "15m",
		},
	}
	rr := doSettingsSave(t, handler, cookies, csrf, payload)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify all fields were written
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("reading config file: %v", err)
	}
	content := string(data)

	checks := []string{
		"https://example.com",
		"48h",
		"debug",
		"6h",
		"15m",
	}
	for _, check := range checks {
		if !contains(content, check) {
			t.Errorf("config file does not contain %q", check)
		}
	}
}

// Test 13: No config file path → 409.
func TestSettingsSave_NoConfigFilePath(t *testing.T) {
	cfg, _ := setupWritableConfig(t)
	cfg.ConfigFilePath = "" // No config file
	handler, _ := setupTestUIServerForSave(t, cfg)

	// Login
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Get CSRF
	csrfRR := doGetCSRF(t, handler, cookies)
	var csrfResp map[string]string
	json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp)
	csrf := csrfResp["token"]
	cookies = append(cookies, csrfRR.Result().Cookies()...)

	payload := map[string]interface{}{
		"logging": map[string]interface{}{
			"level": "debug",
		},
	}
	rr := doSettingsSave(t, handler, cookies, csrf, payload)

	if rr.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 14: publicEndpoint validation (must be http/https URL).
func TestSettingsSave_InvalidPublicEndpoint(t *testing.T) {
	cfg, _ := setupWritableConfig(t)
	handler, _ := setupTestUIServerForSave(t, cfg)

	// Login
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Get CSRF
	csrfRR := doGetCSRF(t, handler, cookies)
	var csrfResp map[string]string
	json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp)
	csrf := csrfResp["token"]
	cookies = append(cookies, csrfRR.Result().Cookies()...)

	payload := map[string]interface{}{
		"server": map[string]interface{}{
			"publicEndpoint": "ftp://invalid.com",
		},
	}
	rr := doSettingsSave(t, handler, cookies, csrf, payload)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

// setupConfigFileNoAuth creates a config file that deliberately omits the auth
// section, while the runtime Config still has auth.master_key set (e.g., from an
// env var). This is the common Docker deployment pattern where
// HEMMINS_AUTH_MASTER_KEY is injected at runtime and never stored in the file.
func setupConfigFileNoAuth(t *testing.T) (*config.Config, string) {
	t.Helper()
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	// File deliberately has NO auth section.
	fileContent := "version: 1\n" +
		"server:\n" +
		"  listen: \":9000\"\n" +
		"  public_endpoint: \"http://localhost:9000\"\n" +
		"  enable_ui: true\n" +
		"  trust_proxy_headers: false\n" +
		"s3:\n" +
		"  region: \"us-east-1\"\n" +
		"  virtual_host_suffix: \"\"\n" +
		"  max_presign_ttl: \"24h\"\n" +
		"logging:\n" +
		"  level: \"info\"\n" +
		"  access_log: true\n" +
		"ui:\n" +
		"  session_ttl: \"12h\"\n" +
		"  session_idle_ttl: \"30m\"\n"
	if err := os.WriteFile(configPath, []byte(fileContent), 0644); err != nil {
		t.Fatalf("writing config file: %v", err)
	}

	// Runtime config has auth.master_key (as if injected via env var, not from file).
	cfg := &config.Config{
		Version: 1,
		Server: config.ServerConfig{
			Listen:            ":9000",
			PublicEndpoint:    "http://localhost:9000",
			EnableUI:          true,
			TrustProxyHeaders: false,
		},
		S3: config.S3Config{
			Region:        "us-east-1",
			MaxPresignTTL: config.Duration{Duration: 24 * time.Hour},
		},
		Paths: config.PathsConfig{
			MetaDB:        filepath.Join(tempDir, "meta", "metadata.db"),
			ObjectRoot:    filepath.Join(tempDir, "objects"),
			MultipartRoot: filepath.Join(tempDir, "multipart"),
			TempRoot:      filepath.Join(tempDir, "tmp"),
			LogRoot:       filepath.Join(tempDir, "logs"),
		},
		Auth: config.AuthConfig{
			MasterKey: "test-master-key-32-bytes-minimum!",
		},
		UI: config.UIConfig{
			SessionTTL:     config.Duration{Duration: 12 * time.Hour},
			SessionIdleTTL: config.Duration{Duration: 30 * time.Minute},
		},
		Logging: config.LoggingConfig{
			Level:     "info",
			AccessLog: true,
		},
		GC: config.GCConfig{
			OrphanScanInterval: config.Duration{Duration: 24 * time.Hour},
			OrphanGracePeriod:  config.Duration{Duration: 1 * time.Hour},
			MultipartExpiry:    config.Duration{Duration: 24 * time.Hour},
		},
		ConfigFilePath:     configPath,
		ConfigFileReadOnly: false,
		EnvLocked: config.EnvLocked{
			AuthMasterKey:      true, // master_key comes from env, not the file
			PathsMetaDB:        true, // paths come from env in this Docker pattern
			PathsObjectRoot:    true,
			PathsMultipartRoot: true,
			PathsTempRoot:      true,
			PathsLogRoot:       true,
		},
	}
	return cfg, configPath
}

// Test 15: SavePatch never adds auth.master_key when auth section was absent from file.
// Per security-model.md section 4.3 and configuration-model.md section 2.1.
func TestSettingsSave_AuthMasterKeyNotWritten(t *testing.T) {
	cfg, configPath := setupConfigFileNoAuth(t)
	handler, _ := setupTestUIServerForSave(t, cfg)

	// Login
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Get CSRF
	csrfRR := doGetCSRF(t, handler, cookies)
	var csrfResp map[string]string
	json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp)
	csrf := csrfResp["token"]
	cookies = append(cookies, csrfRR.Result().Cookies()...)

	// Save a safe field that has nothing to do with auth.
	payload := map[string]interface{}{
		"logging": map[string]interface{}{
			"level": "debug",
		},
	}
	rr := doSettingsSave(t, handler, cookies, csrf, payload)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Read the resulting config file.
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("reading config file: %v", err)
	}
	content := string(data)

	// auth.master_key must NOT appear — it was not in the original file.
	if contains(content, "master_key") {
		t.Errorf("config file must not contain master_key after save (was not in original file):\n%s", content)
	}
	// auth section must NOT appear — it was not in the original file.
	if contains(content, "auth:") {
		t.Errorf("config file must not contain auth section after save (was not in original file):\n%s", content)
	}
	// The intended change must be present.
	if !contains(content, "debug") {
		t.Errorf("config file should contain updated logging.level=debug:\n%s", content)
	}
}

// Test 16: Saving an unrelated safe field must not persist env-override values.
// Scenario: file has logging.level=info; runtime has logging.level=debug (env override).
// Saving server.publicEndpoint must leave logging.level=info in the file.
// Per configuration-model.md section 2.1: env overrides are runtime-only.
func TestSettingsSave_EnvOverrideNotPersisted(t *testing.T) {
	cfg, configPath := setupWritableConfig(t)

	// Simulate env override: runtime value differs from file value.
	// The file was written with logging.level=info (via setupWritableConfig).
	// Override the runtime value to "debug" as if HEMMINS_LOGGING_LEVEL=debug was set.
	cfg.Logging.Level = "debug"
	cfg.EnvLocked.LoggingLevel = true // field is locked by env

	handler, _ := setupTestUIServerForSave(t, cfg)

	// Login
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Get CSRF
	csrfRR := doGetCSRF(t, handler, cookies)
	var csrfResp map[string]string
	json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp)
	csrf := csrfResp["token"]
	cookies = append(cookies, csrfRR.Result().Cookies()...)

	// Save only server.publicEndpoint — do NOT include logging in the payload.
	payload := map[string]interface{}{
		"server": map[string]interface{}{
			"publicEndpoint": "https://new-endpoint.example.com",
		},
	}
	rr := doSettingsSave(t, handler, cookies, csrf, payload)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Read the resulting config file.
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("reading config file: %v", err)
	}
	content := string(data)

	// The env-override value "debug" must NOT have been written to the file.
	// The original file value "info" must still be present.
	if !contains(content, "info") {
		t.Errorf("file should still contain logging.level=info (not the env-override value):\n%s", content)
	}
	// Verify the intended change is present.
	if !contains(content, "https://new-endpoint.example.com") {
		t.Errorf("file should contain new publicEndpoint:\n%s", content)
	}
}

// Test 17: Only the explicitly patched field changes; all others are preserved.
// Per configuration-model.md section 2.1: save only modifies requested fields.
func TestSettingsSave_OnlyIntendedFieldsChanged(t *testing.T) {
	cfg, configPath := setupWritableConfig(t)
	handler, _ := setupTestUIServerForSave(t, cfg)

	// Capture the original file content.
	originalData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("reading original config file: %v", err)
	}
	originalContent := string(originalData)

	// Login
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Get CSRF
	csrfRR := doGetCSRF(t, handler, cookies)
	var csrfResp map[string]string
	json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp)
	csrf := csrfResp["token"]
	cookies = append(cookies, csrfRR.Result().Cookies()...)

	// Save ONLY logging.level.
	payload := map[string]interface{}{
		"logging": map[string]interface{}{
			"level": "warn",
		},
	}
	rr := doSettingsSave(t, handler, cookies, csrf, payload)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Read the resulting file.
	newData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("reading new config file: %v", err)
	}
	newContent := string(newData)

	// Intended change: logging.level should be "warn".
	if !contains(newContent, "warn") {
		t.Errorf("file should contain updated logging.level=warn:\n%s", newContent)
	}

	// The server.public_endpoint field value should still be present (unchanged).
	if !contains(newContent, "http://localhost:9000") {
		t.Errorf("file should still contain original publicEndpoint:\n%s", newContent)
	}

	// The s3.region should still be present (unchanged).
	if !contains(newContent, "us-east-1") {
		t.Errorf("file should still contain original s3.region:\n%s", newContent)
	}

	// The original file had "info" for logging.level; after save it should be "warn".
	// Sanity: original content had "info".
	if !contains(originalContent, "info") {
		t.Skip("original config did not contain 'info' — skipping field-change verification")
	}
}

// Test 18: ConfigFilePath is set but the actual file does not exist → 409.
// Per configuration-model.md section 9.2: we never create a new file from scratch.
// CanSaveConfig must reject before any patch logic runs.
func TestSettingsSave_MissingConfigFile(t *testing.T) {
	cfg, _ := setupWritableConfig(t)
	// Point to a path that does not exist on disk.
	cfg.ConfigFilePath = filepath.Join(t.TempDir(), "does-not-exist.yaml")
	handler, _ := setupTestUIServerForSave(t, cfg)

	// Login
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Get CSRF
	csrfRR := doGetCSRF(t, handler, cookies)
	var csrfResp map[string]string
	json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp)
	csrf := csrfResp["token"]
	cookies = append(cookies, csrfRR.Result().Cookies()...)

	payload := map[string]interface{}{
		"logging": map[string]interface{}{
			"level": "debug",
		},
	}
	rr := doSettingsSave(t, handler, cookies, csrf, payload)

	if rr.Code != http.StatusConflict {
		t.Errorf("expected 409 for missing config file, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 19: Validation must run against the actual saved candidate, not the runtime config clone.
//
// Concretely: applyPayload() silently ignores time.ParseDuration failures, so under the
// old approach an invalid duration (e.g. "not-a-duration") would pass Validate() (which
// sees the unchanged old value) and then get written verbatim to the file — corrupting it.
//
// Under the new approach BuildPatchedBytes writes the raw string into the candidate YAML,
// then ParseCandidateConfig tries to unmarshal it into a Duration field and fails → 400.
func TestSettingsSave_ValidationAgainstCandidate(t *testing.T) {
	cfg, configPath := setupWritableConfig(t)
	handler, _ := setupTestUIServerForSave(t, cfg)

	// Login
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Get CSRF
	csrfRR := doGetCSRF(t, handler, cookies)
	var csrfResp map[string]string
	json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp)
	csrf := csrfResp["token"]
	cookies = append(cookies, csrfRR.Result().Cookies()...)

	// Send an invalid duration string for maxPresignTTL.
	// The old code would: applyPayload silently ignores parse error → Validate passes
	// → file gets "not-a-duration" written → server fails to restart.
	// The new code: BuildPatchedBytes writes the raw string → ParseCandidateConfig
	// fails to unmarshal Duration → 400.
	payload := map[string]interface{}{
		"s3": map[string]interface{}{
			"maxPresignTTL": "not-a-duration",
		},
	}
	rr := doSettingsSave(t, handler, cookies, csrf, payload)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid duration in candidate, got %d: %s", rr.Code, rr.Body.String())
	}

	// The config file must NOT have been modified.
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("reading config file: %v", err)
	}
	if contains(string(data), "not-a-duration") {
		t.Error("config file must not contain invalid duration string after rejected save")
	}
}

// setupConfigFileWithPlaceholders creates a config file that uses ${VAR}
// placeholders for some string fields, mimicking the common deployment pattern
// shown in configuration-model.md section 13 (e.g. auth.master_key: "${HEMMINS_MASTER_KEY}").
// The runtime Config reflects the expanded values.
func setupConfigFileWithPlaceholders(t *testing.T) (*config.Config, string) {
	t.Helper()
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	// Set env vars that the ${VAR} placeholders in the file reference.
	t.Setenv("TEST_SAVE_PUBLIC_ENDPOINT", "http://placeholder-expanded.example.com")
	t.Setenv("TEST_SAVE_MASTER_KEY", "test-master-key-32-bytes-minimum!")

	// File uses ${VAR} syntax (file-level expansion, NOT HEMMINS_* override).
	fileContent := "version: 1\n" +
		"server:\n" +
		"  listen: \":9000\"\n" +
		"  public_endpoint: \"${TEST_SAVE_PUBLIC_ENDPOINT}\"\n" +
		"  enable_ui: true\n" +
		"  trust_proxy_headers: false\n" +
		"s3:\n" +
		"  region: \"us-east-1\"\n" +
		"  virtual_host_suffix: \"\"\n" +
		"  max_presign_ttl: \"24h\"\n" +
		"paths:\n" +
		"  meta_db: \"" + filepath.Join(tempDir, "meta", "metadata.db") + "\"\n" +
		"  object_root: \"" + filepath.Join(tempDir, "objects") + "\"\n" +
		"  multipart_root: \"" + filepath.Join(tempDir, "multipart") + "\"\n" +
		"  temp_root: \"" + filepath.Join(tempDir, "tmp") + "\"\n" +
		"  log_root: \"" + filepath.Join(tempDir, "logs") + "\"\n" +
		"auth:\n" +
		"  master_key: \"${TEST_SAVE_MASTER_KEY}\"\n" +
		"logging:\n" +
		"  level: \"info\"\n" +
		"  access_log: true\n" +
		"ui:\n" +
		"  session_ttl: \"12h\"\n" +
		"  session_idle_ttl: \"30m\"\n" +
		"gc:\n" +
		"  orphan_scan_interval: \"24h\"\n" +
		"  orphan_grace_period: \"1h\"\n" +
		"  multipart_expiry: \"24h\"\n"
	if err := os.WriteFile(configPath, []byte(fileContent), 0644); err != nil {
		t.Fatalf("writing config file: %v", err)
	}

	// Runtime config has the expanded values (as loadFile would produce).
	// EnvLocked flags are NOT set because these values came from ${VAR}
	// file-level expansion, not from HEMMINS_* env overrides.
	cfg := &config.Config{
		Version: 1,
		Server: config.ServerConfig{
			Listen:            ":9000",
			PublicEndpoint:    "http://placeholder-expanded.example.com",
			EnableUI:          true,
			TrustProxyHeaders: false,
		},
		S3: config.S3Config{
			Region:        "us-east-1",
			MaxPresignTTL: config.Duration{Duration: 24 * time.Hour},
		},
		Paths: config.PathsConfig{
			MetaDB:        filepath.Join(tempDir, "meta", "metadata.db"),
			ObjectRoot:    filepath.Join(tempDir, "objects"),
			MultipartRoot: filepath.Join(tempDir, "multipart"),
			TempRoot:      filepath.Join(tempDir, "tmp"),
			LogRoot:       filepath.Join(tempDir, "logs"),
		},
		Auth: config.AuthConfig{
			MasterKey: "test-master-key-32-bytes-minimum!",
		},
		UI: config.UIConfig{
			SessionTTL:     config.Duration{Duration: 12 * time.Hour},
			SessionIdleTTL: config.Duration{Duration: 30 * time.Minute},
		},
		Logging: config.LoggingConfig{
			Level:     "info",
			AccessLog: true,
		},
		GC: config.GCConfig{
			OrphanScanInterval: config.Duration{Duration: 24 * time.Hour},
			OrphanGracePeriod:  config.Duration{Duration: 1 * time.Hour},
			MultipartExpiry:    config.Duration{Duration: 24 * time.Hour},
		},
		ConfigFilePath:     configPath,
		ConfigFileReadOnly: false,
	}
	return cfg, configPath
}

// Test 20: Config file with ${VAR} placeholders — unrelated safe field save must succeed.
// This is the core regression test for the env-placeholder validation parity bug.
// Per configuration-model.md section 4.1: config file strings support ${ENV_VAR} expansion.
// The save validation path must apply the same expansion as the runtime loader (loadFile).
func TestSettingsSave_PlaceholderConfigSaveSucceeds(t *testing.T) {
	cfg, configPath := setupConfigFileWithPlaceholders(t)
	handler, _ := setupTestUIServerForSave(t, cfg)

	// Login
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Get CSRF
	csrfRR := doGetCSRF(t, handler, cookies)
	var csrfResp map[string]string
	json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp)
	csrf := csrfResp["token"]
	cookies = append(cookies, csrfRR.Result().Cookies()...)

	// Save an unrelated safe field — this must not fail due to ${VAR} in other fields.
	payload := map[string]interface{}{
		"logging": map[string]interface{}{
			"level": "debug",
		},
	}
	rr := doSettingsSave(t, handler, cookies, csrf, payload)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Read the resulting file.
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("reading config file: %v", err)
	}
	content := string(data)

	// The ${VAR} placeholders must be preserved in the file (not expanded).
	if !contains(content, "${TEST_SAVE_PUBLIC_ENDPOINT}") {
		t.Errorf("file should still contain ${TEST_SAVE_PUBLIC_ENDPOINT} placeholder:\n%s", content)
	}
	if !contains(content, "${TEST_SAVE_MASTER_KEY}") {
		t.Errorf("file should still contain ${TEST_SAVE_MASTER_KEY} placeholder:\n%s", content)
	}

	// The intended change must be present.
	if !contains(content, "debug") {
		t.Errorf("file should contain updated logging.level=debug:\n%s", content)
	}

	// auth section must still exist (was in original file).
	if !contains(content, "master_key") {
		t.Errorf("file should still contain auth.master_key field:\n%s", content)
	}
}

// Test 21: Config file with ${VAR} placeholder for a duration field — save succeeds
// when the env var provides a valid duration.
func TestSettingsSave_PlaceholderDurationSaveSucceeds(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	t.Setenv("TEST_SAVE_PRESIGN_TTL", "48h")
	t.Setenv("TEST_SAVE_MASTER_KEY2", "test-master-key-32-bytes-minimum!")

	fileContent := "version: 1\n" +
		"server:\n" +
		"  listen: \":9000\"\n" +
		"  public_endpoint: \"http://localhost:9000\"\n" +
		"  enable_ui: true\n" +
		"s3:\n" +
		"  region: \"us-east-1\"\n" +
		"  max_presign_ttl: \"${TEST_SAVE_PRESIGN_TTL}\"\n" +
		"paths:\n" +
		"  meta_db: \"" + filepath.Join(tempDir, "meta", "metadata.db") + "\"\n" +
		"  object_root: \"" + filepath.Join(tempDir, "objects") + "\"\n" +
		"  multipart_root: \"" + filepath.Join(tempDir, "multipart") + "\"\n" +
		"  temp_root: \"" + filepath.Join(tempDir, "tmp") + "\"\n" +
		"  log_root: \"" + filepath.Join(tempDir, "logs") + "\"\n" +
		"auth:\n" +
		"  master_key: \"${TEST_SAVE_MASTER_KEY2}\"\n" +
		"logging:\n" +
		"  level: \"info\"\n" +
		"  access_log: true\n" +
		"ui:\n" +
		"  session_ttl: \"12h\"\n" +
		"  session_idle_ttl: \"30m\"\n" +
		"gc:\n" +
		"  orphan_scan_interval: \"24h\"\n" +
		"  orphan_grace_period: \"1h\"\n" +
		"  multipart_expiry: \"24h\"\n"
	if err := os.WriteFile(configPath, []byte(fileContent), 0644); err != nil {
		t.Fatalf("writing config file: %v", err)
	}

	cfg := &config.Config{
		Version: 1,
		Server: config.ServerConfig{
			Listen:         ":9000",
			PublicEndpoint: "http://localhost:9000",
			EnableUI:       true,
		},
		S3: config.S3Config{
			Region:        "us-east-1",
			MaxPresignTTL: config.Duration{Duration: 48 * time.Hour},
		},
		Paths: config.PathsConfig{
			MetaDB:        filepath.Join(tempDir, "meta", "metadata.db"),
			ObjectRoot:    filepath.Join(tempDir, "objects"),
			MultipartRoot: filepath.Join(tempDir, "multipart"),
			TempRoot:      filepath.Join(tempDir, "tmp"),
			LogRoot:       filepath.Join(tempDir, "logs"),
		},
		Auth: config.AuthConfig{
			MasterKey: "test-master-key-32-bytes-minimum!",
		},
		UI: config.UIConfig{
			SessionTTL:     config.Duration{Duration: 12 * time.Hour},
			SessionIdleTTL: config.Duration{Duration: 30 * time.Minute},
		},
		Logging: config.LoggingConfig{
			Level:     "info",
			AccessLog: true,
		},
		GC: config.GCConfig{
			OrphanScanInterval: config.Duration{Duration: 24 * time.Hour},
			OrphanGracePeriod:  config.Duration{Duration: 1 * time.Hour},
			MultipartExpiry:    config.Duration{Duration: 24 * time.Hour},
		},
		ConfigFilePath:     configPath,
		ConfigFileReadOnly: false,
	}

	handler, _ := setupTestUIServerForSave(t, cfg)

	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	csrfRR := doGetCSRF(t, handler, cookies)
	var csrfResp map[string]string
	json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp)
	csrf := csrfResp["token"]
	cookies = append(cookies, csrfRR.Result().Cookies()...)

	// Save logging.level — unrelated to the ${VAR} duration field.
	payload := map[string]interface{}{
		"logging": map[string]interface{}{
			"level": "warn",
		},
	}
	rr := doSettingsSave(t, handler, cookies, csrf, payload)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// The placeholder must be preserved.
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("reading config file: %v", err)
	}
	content := string(data)
	if !contains(content, "${TEST_SAVE_PRESIGN_TTL}") {
		t.Errorf("file should still contain ${TEST_SAVE_PRESIGN_TTL} placeholder:\n%s", content)
	}
	if !contains(content, "warn") {
		t.Errorf("file should contain updated logging.level=warn:\n%s", content)
	}
}

// setupTestUIServerForPresignReload creates a server suitable for testing both
// config save and presigned URL generation. Uses testMasterKey consistently for both
// bootstrap encryption and cfg.Auth.MasterKey so getRootAccessKey() succeeds.
func setupTestUIServerForPresignReload(t *testing.T) (http.Handler, string) {
	t.Helper()
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	cfg := &config.Config{
		Version: 1,
		Server: config.ServerConfig{
			Listen:         ":9000",
			PublicEndpoint: testPublicEndpoint,
			EnableUI:       true,
		},
		S3: config.S3Config{
			Region:        testRegion,
			MaxPresignTTL: config.Duration{Duration: 24 * time.Hour},
		},
		Paths: config.PathsConfig{
			MetaDB:        filepath.Join(tempDir, "meta", "metadata.db"),
			ObjectRoot:    filepath.Join(tempDir, "objects"),
			MultipartRoot: filepath.Join(tempDir, "multipart"),
			TempRoot:      filepath.Join(tempDir, "tmp"),
			LogRoot:       filepath.Join(tempDir, "logs"),
		},
		Auth: config.AuthConfig{
			MasterKey: testMasterKey, // must match the key used to encrypt the root secret
		},
		UI: config.UIConfig{
			SessionTTL:     config.Duration{Duration: 12 * time.Hour},
			SessionIdleTTL: config.Duration{Duration: 30 * time.Minute},
		},
		Logging: config.LoggingConfig{
			Level:     "info",
			AccessLog: true,
		},
		GC: config.GCConfig{
			OrphanScanInterval: config.Duration{Duration: 24 * time.Hour},
			OrphanGracePeriod:  config.Duration{Duration: 1 * time.Hour},
			MultipartExpiry:    config.Duration{Duration: 24 * time.Hour},
		},
		ConfigFilePath:     configPath,
		ConfigFileReadOnly: false,
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	db, err := metadata.Open(":memory:")
	if err != nil {
		t.Fatalf("metadata.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	pwHash, err := auth.HashPassword(testAdminPassword)
	if err != nil {
		t.Fatalf("auth.HashPassword: %v", err)
	}
	ciphertext, err := auth.EncryptSecret(testMasterKey, testRootSecretKey)
	if err != nil {
		t.Fatalf("auth.EncryptSecret: %v", err)
	}
	if err := db.Bootstrap(testAdminUsername, pwHash, testAccessKey, ciphertext); err != nil {
		t.Fatalf("db.Bootstrap: %v", err)
	}

	store := ui.NewSessionStore(12*time.Hour, 30*time.Minute)
	srv := ui.NewServer(db, store, false)
	srv.SetConfig(cfg)
	return srv.Handler(), configPath
}

// TestSettingsSave_RequiresRestart_False verifies that saving any safe-subset field
// returns requiresRestart=false because all safe-subset fields support runtime hot-reload.
// Per configuration-model.md section 8.3: safe subset is "즉시 반영 가능".
func TestSettingsSave_RequiresRestart_False(t *testing.T) {
	cfg, _ := setupWritableConfig(t)
	handler, _ := setupTestUIServerForSave(t, cfg)

	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	csrfRR := doGetCSRF(t, handler, cookies)
	var csrfResp map[string]string
	json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp)
	csrf := csrfResp["token"]
	cookies = append(cookies, csrfRR.Result().Cookies()...)

	tests := []struct {
		name    string
		payload interface{}
	}{
		{
			"logging.level",
			map[string]interface{}{"logging": map[string]interface{}{"level": "debug"}},
		},
		{
			"logging.accessLog",
			map[string]interface{}{"logging": map[string]interface{}{"accessLog": false}},
		},
		{
			"server.publicEndpoint",
			map[string]interface{}{"server": map[string]interface{}{"publicEndpoint": "http://example.com:9000"}},
		},
		{
			"s3.maxPresignTTL",
			map[string]interface{}{"s3": map[string]interface{}{"maxPresignTTL": "48h"}},
		},
		{
			"ui.sessionTTL",
			map[string]interface{}{"ui": map[string]interface{}{"sessionTTL": "8h"}},
		},
		{
			"ui.sessionIdleTTL",
			map[string]interface{}{"ui": map[string]interface{}{"sessionIdleTTL": "20m"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr := doSettingsSave(t, handler, cookies, csrf, tc.payload)
			if rr.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
			}
			var resp map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("parsing response: %v", err)
			}
			if resp["requiresRestart"] != false {
				t.Errorf("expected requiresRestart=false for %s, got %v", tc.name, resp["requiresRestart"])
			}
		})
	}
}

// TestSettingsSave_RuntimeReload_GETReflectsNewValues verifies that after a successful
// save, GET /ui/api/settings immediately returns the updated values without restart.
// Per configuration-model.md section 8.3: "즉시 반영 가능" (immediately effective).
func TestSettingsSave_RuntimeReload_GETReflectsNewValues(t *testing.T) {
	cfg, _ := setupWritableConfig(t)
	handler, _ := setupTestUIServerForSave(t, cfg)

	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	csrfRR := doGetCSRF(t, handler, cookies)
	var csrfResp map[string]string
	json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp)
	csrf := csrfResp["token"]
	cookies = append(cookies, csrfRR.Result().Cookies()...)

	savePayload := map[string]interface{}{
		"logging": map[string]interface{}{
			"level":     "warn",
			"accessLog": false,
		},
		"s3": map[string]interface{}{
			"maxPresignTTL": "48h",
		},
		"server": map[string]interface{}{
			"publicEndpoint": "http://reload.example.com:9000",
		},
		"ui": map[string]interface{}{
			"sessionTTL":     "6h",
			"sessionIdleTTL": "15m",
		},
	}
	saveRR := doSettingsSave(t, handler, cookies, csrf, savePayload)
	if saveRR.Code != http.StatusOK {
		t.Fatalf("save failed: %d: %s", saveRR.Code, saveRR.Body.String())
	}

	// GET /ui/api/settings must reflect the new values immediately without restart.
	getResp := doSettings(t, handler, cookies)
	if getResp.Code != http.StatusOK {
		t.Fatalf("GET settings failed: %d", getResp.Code)
	}
	var settings map[string]interface{}
	if err := json.Unmarshal(getResp.Body.Bytes(), &settings); err != nil {
		t.Fatalf("parsing GET response: %v", err)
	}

	logging, _ := settings["logging"].(map[string]interface{})
	if logging["level"] != "warn" {
		t.Errorf("runtime reload: expected logging.level=warn, got %v", logging["level"])
	}
	if logging["accessLog"] != false {
		t.Errorf("runtime reload: expected logging.accessLog=false, got %v", logging["accessLog"])
	}

	s3obj, _ := settings["s3"].(map[string]interface{})
	if s3obj["maxPresignTTL"] != "48h0m0s" {
		t.Errorf("runtime reload: expected s3.maxPresignTTL=48h0m0s, got %v", s3obj["maxPresignTTL"])
	}

	server, _ := settings["server"].(map[string]interface{})
	if server["publicEndpoint"] != "http://reload.example.com:9000" {
		t.Errorf("runtime reload: expected server.publicEndpoint=http://reload.example.com:9000, got %v", server["publicEndpoint"])
	}

	uiFields, _ := settings["ui"].(map[string]interface{})
	if uiFields["sessionTTL"] != "6h0m0s" {
		t.Errorf("runtime reload: expected ui.sessionTTL=6h0m0s, got %v", uiFields["sessionTTL"])
	}
	if uiFields["sessionIdleTTL"] != "15m0s" {
		t.Errorf("runtime reload: expected ui.sessionIdleTTL=15m0s, got %v", uiFields["sessionIdleTTL"])
	}
}

// TestSettingsSave_RuntimeReload_MaxPresignTTL verifies that saving s3.maxPresignTTL
// immediately affects presigned URL TTL enforcement without restart.
//
// Before save: presigning with expiresSeconds > 24h must fail (400).
// After saving maxPresignTTL=48h: the same expiresSeconds must succeed (200).
//
// This validates that s.maxPresignTTL is updated by applyRuntimeReload.
func TestSettingsSave_RuntimeReload_MaxPresignTTL(t *testing.T) {
	handler, _ := setupTestUIServerForPresignReload(t)

	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket for presign tests.
	createRR := doCreateBucket(t, handler, cookies, "ttl-reload-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d: %s", createRR.Code, createRR.Body.String())
	}

	// Before save: 90000s (25h) > maxPresignTTL=24h — must fail with 400.
	beforeRR := doPresign(t, handler, cookies, "ttl-reload-bucket", presignRequest{
		Key:            "test.txt",
		Method:         "GET",
		ExpiresSeconds: 90000, // 25h, exceeds 24h max
	})
	if beforeRR.Code != http.StatusBadRequest {
		t.Errorf("before save: expected 400 for 25h presign (24h max), got %d: %s",
			beforeRR.Code, beforeRR.Body.String())
	}

	// Save new maxPresignTTL = 48h.
	csrfRR := doGetCSRF(t, handler, cookies)
	var csrfResp map[string]string
	json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp)
	csrf := csrfResp["token"]
	cookies = append(cookies, csrfRR.Result().Cookies()...)

	saveRR := doSettingsSave(t, handler, cookies, csrf, map[string]interface{}{
		"s3": map[string]interface{}{"maxPresignTTL": "48h"},
	})
	if saveRR.Code != http.StatusOK {
		t.Fatalf("save failed: %d: %s", saveRR.Code, saveRR.Body.String())
	}

	// After save: 90000s (25h) must now succeed (maxPresignTTL=48h).
	afterRR := doPresign(t, handler, cookies, "ttl-reload-bucket", presignRequest{
		Key:            "test.txt",
		Method:         "GET",
		ExpiresSeconds: 90000, // 25h — now within 48h max
	})
	if afterRR.Code != http.StatusOK {
		t.Errorf("after save: expected 200 for 25h presign (48h max), got %d: %s",
			afterRR.Code, afterRR.Body.String())
	}
}

// TestSessionStore_UpdateTTLs_PerSessionTTL verifies the per-session TTL policy:
// UpdateTTLs only affects newly created sessions; existing sessions retain the
// TTL captured at their creation time (Session.TTL / Session.IdleTTL).
//
// Policy: conservative — existing admin sessions are not disrupted by a TTL change;
// new TTL applies to subsequent logins only.
// Per configuration-model.md section 8.3 and session_store.go Session.TTL comment.
func TestSessionStore_UpdateTTLs_PerSessionTTL(t *testing.T) {
	// Store with a short absolute TTL (50ms) to exercise expiry quickly.
	store := ui.NewSessionStore(50*time.Millisecond, 1*time.Second)

	// Create S1 before the TTL update — S1 captures TTL=50ms.
	id1, err := store.Create("admin", "admin")
	if err != nil {
		t.Fatalf("Create S1: %v", err)
	}
	if _, ok := store.Get(id1); !ok {
		t.Fatal("S1 should be valid immediately after creation")
	}

	// Update store TTLs to a longer value — future sessions get TTL=500ms.
	store.UpdateTTLs(500*time.Millisecond, 1*time.Second)

	// Create S2 after the update — S2 captures TTL=500ms.
	id2, err := store.Create("admin", "admin")
	if err != nil {
		t.Fatalf("Create S2: %v", err)
	}
	if _, ok := store.Get(id2); !ok {
		t.Fatal("S2 should be valid immediately after creation")
	}

	// Sleep 100ms: past S1's TTL (50ms) but within S2's TTL (500ms).
	time.Sleep(100 * time.Millisecond)

	// S1 must be expired: it was created with TTL=50ms; 100ms have elapsed.
	if _, ok := store.Get(id1); ok {
		t.Error("S1 should have expired: created with TTL=50ms, 100ms elapsed")
	}

	// S2 must still be valid: it was created with TTL=500ms; only 100ms elapsed.
	if _, ok := store.Get(id2); !ok {
		t.Error("S2 should still be valid: created with TTL=500ms, 100ms elapsed")
	}
}

// doGetCSRF issues GET /ui/api/session/csrf.
func doGetCSRF(t *testing.T, handler http.Handler, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/ui/api/session/csrf", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// contains is a simple substring check.
func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && bytes.Contains([]byte(s), []byte(substr))
}

// setupTestUIServerForCookieReload creates a test server with a writable config file
// using the given initial public endpoint. secureCookie is derived from the endpoint scheme,
// matching the logic in cmd/server/main.go.
func setupTestUIServerForCookieReload(t *testing.T, initialEndpoint string) (http.Handler, string) {
	t.Helper()
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	cfg := &config.Config{
		Version: 1,
		Server: config.ServerConfig{
			Listen:         ":9000",
			PublicEndpoint: initialEndpoint,
			EnableUI:       true,
		},
		S3: config.S3Config{
			Region:        "us-east-1",
			MaxPresignTTL: config.Duration{Duration: 24 * time.Hour},
		},
		Paths: config.PathsConfig{
			MetaDB:        filepath.Join(tempDir, "meta", "metadata.db"),
			ObjectRoot:    filepath.Join(tempDir, "objects"),
			MultipartRoot: filepath.Join(tempDir, "multipart"),
			TempRoot:      filepath.Join(tempDir, "tmp"),
			LogRoot:       filepath.Join(tempDir, "logs"),
		},
		Auth: config.AuthConfig{
			MasterKey: "test-master-key-32-bytes-minimum!",
		},
		UI: config.UIConfig{
			SessionTTL:     config.Duration{Duration: 12 * time.Hour},
			SessionIdleTTL: config.Duration{Duration: 30 * time.Minute},
		},
		Logging: config.LoggingConfig{
			Level:     "info",
			AccessLog: true,
		},
		GC: config.GCConfig{
			OrphanScanInterval: config.Duration{Duration: 24 * time.Hour},
			OrphanGracePeriod:  config.Duration{Duration: 1 * time.Hour},
			MultipartExpiry:    config.Duration{Duration: 24 * time.Hour},
		},
		ConfigFilePath:     configPath,
		ConfigFileReadOnly: false,
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	db, err := metadata.Open(":memory:")
	if err != nil {
		t.Fatalf("metadata.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	pwHash, err := auth.HashPassword(testAdminPassword)
	if err != nil {
		t.Fatalf("auth.HashPassword: %v", err)
	}
	ciphertext, err := auth.EncryptSecret(testMasterKey, "testsecret123")
	if err != nil {
		t.Fatalf("auth.EncryptSecret: %v", err)
	}
	if err := db.Bootstrap(testAdminUsername, pwHash, testAccessKey, ciphertext); err != nil {
		t.Fatalf("db.Bootstrap: %v", err)
	}

	// Derive secureCookie from endpoint scheme, matching cmd/server/main.go.
	secureCookie := strings.HasPrefix(initialEndpoint, "https://")
	store := ui.NewSessionStore(12*time.Hour, 30*time.Minute)
	srv := ui.NewServer(db, store, secureCookie)
	srv.SetConfig(cfg)
	return srv.Handler(), configPath
}

// TestSecureCookieParity_HttpToHttps verifies that changing server.publicEndpoint from
// http:// to https:// via settings save immediately updates the Secure attribute on
// all subsequent CSRF, session, and logout cookies without restarting.
// Per security-model.md section 7: Secure cookie required when public endpoint is https://.
func TestSecureCookieParity_HttpToHttps(t *testing.T) {
	handler, _ := setupTestUIServerForCookieReload(t, "http://localhost:9000")

	// --- Pre-save: cookies must NOT have Secure flag ---
	csrfRR := doCSRF(t, handler)
	if c := findCSRFCookie(csrfRR); c == nil {
		t.Fatal("pre-save: no CSRF cookie")
	} else if c.Secure {
		t.Error("pre-save: CSRF cookie must not have Secure flag for http endpoint")
	}

	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("pre-save login failed: %d", loginRR.Code)
	}
	if c := findSessionCookie(loginRR); c == nil {
		t.Fatal("pre-save: no session cookie")
	} else if c.Secure {
		t.Error("pre-save: session cookie must not have Secure flag for http endpoint")
	}

	// --- Save: change publicEndpoint to https:// ---
	loginCookies := loginRR.Result().Cookies()
	csrfGetRR := doGetCSRF(t, handler, loginCookies)
	if csrfGetRR.Code != http.StatusOK {
		t.Fatalf("get CSRF failed: %d", csrfGetRR.Code)
	}
	var csrfResp map[string]string
	if err := json.Unmarshal(csrfGetRR.Body.Bytes(), &csrfResp); err != nil {
		t.Fatalf("parsing CSRF response: %v", err)
	}
	saveCookies := append(loginCookies, csrfGetRR.Result().Cookies()...)
	saveRR := doSettingsSave(t, handler, saveCookies, csrfResp["token"], map[string]interface{}{
		"server": map[string]interface{}{"publicEndpoint": "https://example.com"},
	})
	if saveRR.Code != http.StatusOK {
		t.Fatalf("save failed: %d: %s", saveRR.Code, saveRR.Body.String())
	}

	// --- Post-save: cookies must have Secure=true ---

	// CSRF cookie after reload.
	csrfRR2 := doCSRF(t, handler)
	if c := findCSRFCookie(csrfRR2); c == nil {
		t.Fatal("post-save: no CSRF cookie")
	} else if !c.Secure {
		t.Error("post-save: CSRF cookie must have Secure=true after http→https reload")
	}

	// Session cookie after reload.
	loginRR2 := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR2.Code != http.StatusOK {
		t.Fatalf("post-save login failed: %d", loginRR2.Code)
	}
	if c := findSessionCookie(loginRR2); c == nil {
		t.Fatal("post-save: no session cookie")
	} else if !c.Secure {
		t.Error("post-save: session cookie must have Secure=true after http→https reload")
	}

	// Logout clear cookies after reload.
	logoutRR := doLogout(t, handler, loginRR2.Result().Cookies())
	if logoutRR.Code != http.StatusNoContent {
		t.Fatalf("post-save logout failed: %d", logoutRR.Code)
	}
	if c := findSessionCookie(logoutRR); c != nil && !c.Secure {
		t.Error("post-save: logout session clear cookie must have Secure=true after http→https reload")
	}
	if c := findCSRFCookie(logoutRR); c != nil && !c.Secure {
		t.Error("post-save: logout CSRF clear cookie must have Secure=true after http→https reload")
	}
}

// TestSecureCookieParity_HttpsToHttp verifies that changing server.publicEndpoint from
// https:// to http:// via settings save immediately removes the Secure attribute from
// all subsequent CSRF, session, and logout cookies without restarting.
// Per security-model.md section 7: Secure cookie must not be set for plain http endpoints.
func TestSecureCookieParity_HttpsToHttp(t *testing.T) {
	handler, _ := setupTestUIServerForCookieReload(t, "https://example.com")

	// --- Pre-save: cookies must have Secure=true ---
	csrfRR := doCSRF(t, handler)
	if c := findCSRFCookie(csrfRR); c == nil {
		t.Fatal("pre-save: no CSRF cookie")
	} else if !c.Secure {
		t.Error("pre-save: CSRF cookie must have Secure=true for https endpoint")
	}

	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("pre-save login failed: %d", loginRR.Code)
	}
	if c := findSessionCookie(loginRR); c == nil {
		t.Fatal("pre-save: no session cookie")
	} else if !c.Secure {
		t.Error("pre-save: session cookie must have Secure=true for https endpoint")
	}

	// --- Save: change publicEndpoint to http:// ---
	loginCookies := loginRR.Result().Cookies()
	csrfGetRR := doGetCSRF(t, handler, loginCookies)
	if csrfGetRR.Code != http.StatusOK {
		t.Fatalf("get CSRF failed: %d", csrfGetRR.Code)
	}
	var csrfResp map[string]string
	if err := json.Unmarshal(csrfGetRR.Body.Bytes(), &csrfResp); err != nil {
		t.Fatalf("parsing CSRF response: %v", err)
	}
	saveCookies := append(loginCookies, csrfGetRR.Result().Cookies()...)
	saveRR := doSettingsSave(t, handler, saveCookies, csrfResp["token"], map[string]interface{}{
		"server": map[string]interface{}{"publicEndpoint": "http://localhost:9000"},
	})
	if saveRR.Code != http.StatusOK {
		t.Fatalf("save failed: %d: %s", saveRR.Code, saveRR.Body.String())
	}

	// --- Post-save: cookies must NOT have Secure flag ---

	// CSRF cookie after reload.
	csrfRR2 := doCSRF(t, handler)
	if c := findCSRFCookie(csrfRR2); c == nil {
		t.Fatal("post-save: no CSRF cookie")
	} else if c.Secure {
		t.Error("post-save: CSRF cookie must not have Secure flag after https→http reload")
	}

	// Session cookie after reload.
	loginRR2 := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR2.Code != http.StatusOK {
		t.Fatalf("post-save login failed: %d", loginRR2.Code)
	}
	if c := findSessionCookie(loginRR2); c == nil {
		t.Fatal("post-save: no session cookie")
	} else if c.Secure {
		t.Error("post-save: session cookie must not have Secure flag after https→http reload")
	}

	// Logout clear cookies after reload.
	logoutRR := doLogout(t, handler, loginRR2.Result().Cookies())
	if logoutRR.Code != http.StatusNoContent {
		t.Fatalf("post-save logout failed: %d", logoutRR.Code)
	}
	if c := findSessionCookie(logoutRR); c != nil && c.Secure {
		t.Error("post-save: logout session clear cookie must not have Secure flag after https→http reload")
	}
	if c := findCSRFCookie(logoutRR); c != nil && c.Secure {
		t.Error("post-save: logout CSRF clear cookie must not have Secure flag after https→http reload")
	}
}

// TestSettingsSave_ConcurrentSave_FileParity verifies that after concurrent saves,
// GET /ui/api/settings always reflects the same state as the config file.
//
// This is the primary regression test for the save transaction serialization bug:
//   - Before fix: two concurrent saves could each read the original file, write
//     different candidates, and then apply independent runtime reloads — leaving
//     the file and runtime in divergent states.
//   - After fix: saveMu serializes the entire transaction so that file content and
//     runtime state always point to the same logical snapshot.
//
// The test uses a barrier channel to maximize goroutine overlap, then asserts the
// parity invariant: for every field that appears in the config file, GET settings
// must report the same value.
//
// Run with -race to also verify no Go data races.
func TestSettingsSave_ConcurrentSave_FileParity(t *testing.T) {
	cfg, configPath := setupWritableConfig(t)
	handler, _ := setupTestUIServerForSave(t, cfg)

	// Authenticate once; all goroutines share the same session + CSRF token.
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	csrfRR := doGetCSRF(t, handler, cookies)
	if csrfRR.Code != http.StatusOK {
		t.Fatalf("CSRF fetch failed: %d", csrfRR.Code)
	}
	var csrfResp map[string]string
	if err := json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp); err != nil {
		t.Fatalf("parsing CSRF response: %v", err)
	}
	csrf := csrfResp["token"]
	cookies = append(cookies, csrfRR.Result().Cookies()...)

	// Two payloads that modify disjoint fields.
	// With serialization: the second save reads the file already updated by the
	// first save, so both fields end up in the file AND in runtime.
	// Without serialization: both reads happen from the original file, so the
	// last writer's file only has its own change — the other change is lost from
	// the file while runtime may have a mixed state.
	payloads := []map[string]interface{}{
		{"logging": map[string]interface{}{"level": "warn"}},
		{"s3": map[string]interface{}{"maxPresignTTL": "48h"}},
	}

	// Barrier: release all goroutines simultaneously to maximize overlap.
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(len(payloads))

	for _, p := range payloads {
		payload := p // capture
		go func() {
			defer wg.Done()
			<-start // wait for barrier
			doSettingsSave(t, handler, cookies, csrf, payload)
		}()
	}

	close(start) // release all goroutines at once
	wg.Wait()    // wait for all saves to complete

	// --- Invariant check: GET /ui/api/settings must match the config file ---

	// Read the config file on disk.
	fileData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("reading config file: %v", err)
	}
	var fileMap map[string]interface{}
	if err := yaml.Unmarshal(fileData, &fileMap); err != nil {
		t.Fatalf("parsing config file YAML: %v", err)
	}

	// GET the runtime settings.
	getRR := doSettings(t, handler, cookies)
	if getRR.Code != http.StatusOK {
		t.Fatalf("GET settings failed: %d: %s", getRR.Code, getRR.Body.String())
	}
	var settingsResp map[string]interface{}
	if err := json.Unmarshal(getRR.Body.Bytes(), &settingsResp); err != nil {
		t.Fatalf("parsing GET settings response: %v", err)
	}

	// Check logging.level parity.
	fileLogging, _ := fileMap["logging"].(map[string]interface{})
	respLogging, _ := settingsResp["logging"].(map[string]interface{})
	if fileLogging == nil || respLogging == nil {
		t.Fatal("missing logging section in file or response")
	}
	if fileLogging["level"] != respLogging["level"] {
		t.Errorf("parity violation: file logging.level=%v, runtime logging.level=%v",
			fileLogging["level"], respLogging["level"])
	}

	// Check s3.max_presign_ttl parity.
	// The file stores the raw duration string; the response serializes it via Duration.String().
	// We parse both to compare as time.Duration values.
	fileS3, _ := fileMap["s3"].(map[string]interface{})
	respS3, _ := settingsResp["s3"].(map[string]interface{})
	if fileS3 == nil || respS3 == nil {
		t.Fatal("missing s3 section in file or response")
	}
	fileMaxPresignRaw, _ := fileS3["max_presign_ttl"].(string)
	respMaxPresignStr, _ := respS3["maxPresignTTL"].(string)
	if fileMaxPresignRaw == "" || respMaxPresignStr == "" {
		t.Fatalf("missing max_presign_ttl: file=%q resp=%q", fileMaxPresignRaw, respMaxPresignStr)
	}
	fileDur, err := time.ParseDuration(fileMaxPresignRaw)
	if err != nil {
		t.Fatalf("parsing file max_presign_ttl %q: %v", fileMaxPresignRaw, err)
	}
	respDur, err := time.ParseDuration(respMaxPresignStr)
	if err != nil {
		t.Fatalf("parsing response maxPresignTTL %q: %v", respMaxPresignStr, err)
	}
	if fileDur != respDur {
		t.Errorf("parity violation: file max_presign_ttl=%v, runtime maxPresignTTL=%v",
			fileDur, respDur)
	}
}

// TestSettingsSave_ConcurrentSave_SameField verifies that concurrent saves of the
// same field do not leave file and runtime divergent.
//
// Only one value can "win"; the invariant is that file and runtime agree on which
// value won — they must report the same value.
func TestSettingsSave_ConcurrentSave_SameField(t *testing.T) {
	cfg, configPath := setupWritableConfig(t)
	handler, _ := setupTestUIServerForSave(t, cfg)

	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	csrfRR := doGetCSRF(t, handler, cookies)
	var csrfResp map[string]string
	json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp)
	csrf := csrfResp["token"]
	cookies = append(cookies, csrfRR.Result().Cookies()...)

	// Four concurrent saves of the same field (logging.level) with different values.
	// After all complete, file and runtime must agree on the winning value.
	levels := []string{"warn", "debug", "error", "info"}
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(len(levels))

	for _, lvl := range levels {
		level := lvl // capture
		go func() {
			defer wg.Done()
			<-start
			doSettingsSave(t, handler, cookies, csrf, map[string]interface{}{
				"logging": map[string]interface{}{"level": level},
			})
		}()
	}

	close(start)
	wg.Wait()

	// Read file.
	fileData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("reading config file: %v", err)
	}
	var fileMap map[string]interface{}
	if err := yaml.Unmarshal(fileData, &fileMap); err != nil {
		t.Fatalf("parsing config file: %v", err)
	}
	fileLogging, _ := fileMap["logging"].(map[string]interface{})
	if fileLogging == nil {
		t.Fatal("missing logging section in file")
	}
	fileLevel, _ := fileLogging["level"].(string)

	// GET runtime settings.
	getRR := doSettings(t, handler, cookies)
	if getRR.Code != http.StatusOK {
		t.Fatalf("GET settings failed: %d", getRR.Code)
	}
	var settingsResp map[string]interface{}
	json.Unmarshal(getRR.Body.Bytes(), &settingsResp)
	respLogging, _ := settingsResp["logging"].(map[string]interface{})
	if respLogging == nil {
		t.Fatal("missing logging section in response")
	}
	respLevel, _ := respLogging["level"].(string)

	// The exact winner is non-deterministic, but file and runtime must agree.
	if fileLevel != respLevel {
		t.Errorf("parity violation after concurrent same-field saves: file=%q, runtime=%q",
			fileLevel, respLevel)
	}

	// The winning value must be one of the submitted values.
	validLevels := map[string]bool{"warn": true, "debug": true, "error": true, "info": true}
	if !validLevels[fileLevel] {
		t.Errorf("unexpected logging.level in file after concurrent saves: %q", fileLevel)
	}
}
