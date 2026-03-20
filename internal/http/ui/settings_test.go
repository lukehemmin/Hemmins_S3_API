package ui_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lukehemmin/hemmins-s3-api/internal/auth"
	"github.com/lukehemmin/hemmins-s3-api/internal/config"
	ui "github.com/lukehemmin/hemmins-s3-api/internal/http/ui"
	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

// doSettings issues GET /ui/api/settings with the given cookies.
func doSettings(t *testing.T, handler http.Handler, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/ui/api/settings", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// setupTestUIServerWithConfig creates a bootstrapped DB, SessionStore, and ui.Server
// with a custom config for settings tests.
func setupTestUIServerWithConfig(t *testing.T, cfg *config.Config) (http.Handler, *metadata.DB) {
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

// testConfig returns a minimal config for settings tests.
func testConfig(t *testing.T) *config.Config {
	t.Helper()
	tempDir := t.TempDir()
	return &config.Config{
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
		EnvLocked: config.EnvLocked{
			ServerListen:   true,  // mark one field as env-locked for testing
			PathsObjectRoot: true, // mark another for testing
		},
		ConfigFilePath:     "/etc/hemmins/config.yaml",
		ConfigFileReadOnly: true,
	}
}

// Test 1: GET /ui/api/settings with a valid session returns 200.
func TestSettings_ValidSession(t *testing.T) {
	cfg := testConfig(t)
	handler, _ := setupTestUIServerWithConfig(t, cfg)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doSettings(t, handler, loginRR.Result().Cookies())
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 2: GET /ui/api/settings without a session returns 401.
func TestSettings_NoSession(t *testing.T) {
	cfg := testConfig(t)
	handler, _ := setupTestUIServerWithConfig(t, cfg)
	rr := doSettings(t, handler, nil)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// Test 3: settings response contains expected server fields.
func TestSettings_ContainsServerFields(t *testing.T) {
	cfg := testConfig(t)
	handler, _ := setupTestUIServerWithConfig(t, cfg)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doSettings(t, handler, loginRR.Result().Cookies())
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	server, ok := resp["server"].(map[string]interface{})
	if !ok {
		t.Fatal("missing server object in response")
	}
	if server["listen"] != ":9000" {
		t.Errorf("server.listen: got %v, want :9000", server["listen"])
	}
	if server["publicEndpoint"] != "http://localhost:9000" {
		t.Errorf("server.publicEndpoint: got %v, want http://localhost:9000", server["publicEndpoint"])
	}
	if server["enableUI"] != true {
		t.Errorf("server.enableUI: got %v, want true", server["enableUI"])
	}
}

// Test 4: settings response contains expected s3 fields.
func TestSettings_ContainsS3Fields(t *testing.T) {
	cfg := testConfig(t)
	handler, _ := setupTestUIServerWithConfig(t, cfg)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doSettings(t, handler, loginRR.Result().Cookies())
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	s3, ok := resp["s3"].(map[string]interface{})
	if !ok {
		t.Fatal("missing s3 object in response")
	}
	if s3["region"] != "us-east-1" {
		t.Errorf("s3.region: got %v, want us-east-1", s3["region"])
	}
	if s3["maxPresignTTL"] == nil || s3["maxPresignTTL"] == "" {
		t.Error("s3.maxPresignTTL should not be empty")
	}
}

// Test 5: settings response does NOT contain auth.master_key (sensitive).
func TestSettings_NoMasterKeyExposed(t *testing.T) {
	cfg := testConfig(t)
	handler, _ := setupTestUIServerWithConfig(t, cfg)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doSettings(t, handler, loginRR.Result().Cookies())
	body := rr.Body.String()

	// Ensure the actual master key value is not in the response.
	if containsString(body, cfg.Auth.MasterKey) {
		t.Error("response body contains auth.master_key value — sensitive data leak!")
	}

	// Ensure there's no "masterKey" field in the JSON.
	var resp map[string]interface{}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if _, ok := resp["auth"]; ok {
		t.Error("response contains 'auth' object — should be excluded")
	}
}

// Test 6: settings response contains envLocked fields.
func TestSettings_EnvLockedFieldsPresent(t *testing.T) {
	cfg := testConfig(t)
	handler, _ := setupTestUIServerWithConfig(t, cfg)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doSettings(t, handler, loginRR.Result().Cookies())
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	envLocked, ok := resp["envLocked"].(map[string]interface{})
	if !ok {
		t.Fatal("missing envLocked object in response")
	}

	// Check that the test config's locked fields are reflected.
	if envLocked["serverListen"] != true {
		t.Errorf("envLocked.serverListen: got %v, want true", envLocked["serverListen"])
	}
	if envLocked["pathsObjectRoot"] != true {
		t.Errorf("envLocked.pathsObjectRoot: got %v, want true", envLocked["pathsObjectRoot"])
	}
	// Check that unlocked fields are false.
	if envLocked["s3Region"] != false {
		t.Errorf("envLocked.s3Region: got %v, want false", envLocked["s3Region"])
	}
}

// Test 7: settings response contains configFile metadata.
func TestSettings_ConfigFileInfoPresent(t *testing.T) {
	cfg := testConfig(t)
	handler, _ := setupTestUIServerWithConfig(t, cfg)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doSettings(t, handler, loginRR.Result().Cookies())
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	configFile, ok := resp["configFile"].(map[string]interface{})
	if !ok {
		t.Fatal("missing configFile object in response")
	}
	if configFile["path"] != "/etc/hemmins/config.yaml" {
		t.Errorf("configFile.path: got %v, want /etc/hemmins/config.yaml", configFile["path"])
	}
	if configFile["readOnly"] != true {
		t.Errorf("configFile.readOnly: got %v, want true", configFile["readOnly"])
	}
}

// Test 8: settings response contains pathStatus with expected fields.
func TestSettings_PathStatusFieldsPresent(t *testing.T) {
	cfg := testConfig(t)
	// Create the directories so they exist.
	if err := os.MkdirAll(filepath.Dir(cfg.Paths.MetaDB), 0750); err != nil {
		t.Fatalf("creating meta dir: %v", err)
	}
	if err := os.MkdirAll(cfg.Paths.ObjectRoot, 0750); err != nil {
		t.Fatalf("creating object root: %v", err)
	}
	if err := os.MkdirAll(cfg.Paths.MultipartRoot, 0750); err != nil {
		t.Fatalf("creating multipart root: %v", err)
	}
	if err := os.MkdirAll(cfg.Paths.TempRoot, 0750); err != nil {
		t.Fatalf("creating temp root: %v", err)
	}
	if err := os.MkdirAll(cfg.Paths.LogRoot, 0750); err != nil {
		t.Fatalf("creating log root: %v", err)
	}
	// Create the meta_db file.
	f, err := os.Create(cfg.Paths.MetaDB)
	if err != nil {
		t.Fatalf("creating meta_db file: %v", err)
	}
	f.Close()

	handler, _ := setupTestUIServerWithConfig(t, cfg)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doSettings(t, handler, loginRR.Result().Cookies())
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	pathStatus, ok := resp["pathStatus"].(map[string]interface{})
	if !ok {
		t.Fatal("missing pathStatus object in response")
	}

	// Check objectRoot status.
	objectRoot, ok := pathStatus["objectRoot"].(map[string]interface{})
	if !ok {
		t.Fatal("missing pathStatus.objectRoot")
	}
	if objectRoot["exists"] != true {
		t.Errorf("pathStatus.objectRoot.exists: got %v, want true", objectRoot["exists"])
	}
	if objectRoot["writable"] != true {
		t.Errorf("pathStatus.objectRoot.writable: got %v, want true", objectRoot["writable"])
	}
	if objectRoot["kind"] != "dir" {
		t.Errorf("pathStatus.objectRoot.kind: got %v, want dir", objectRoot["kind"])
	}

	// Check metaDB status (file, not dir).
	metaDB, ok := pathStatus["metaDB"].(map[string]interface{})
	if !ok {
		t.Fatal("missing pathStatus.metaDB")
	}
	if metaDB["exists"] != true {
		t.Errorf("pathStatus.metaDB.exists: got %v, want true", metaDB["exists"])
	}
	if metaDB["kind"] != "file" {
		t.Errorf("pathStatus.metaDB.kind: got %v, want file", metaDB["kind"])
	}
}

// Test 9: pathStatus handles non-existent paths gracefully.
func TestSettings_PathStatus_NonExistentPath(t *testing.T) {
	cfg := testConfig(t)
	// Paths don't exist in this test; temp dir is clean.

	handler, _ := setupTestUIServerWithConfig(t, cfg)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doSettings(t, handler, loginRR.Result().Cookies())
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	pathStatus, ok := resp["pathStatus"].(map[string]interface{})
	if !ok {
		t.Fatal("missing pathStatus object in response")
	}

	objectRoot, ok := pathStatus["objectRoot"].(map[string]interface{})
	if !ok {
		t.Fatal("missing pathStatus.objectRoot")
	}
	if objectRoot["exists"] != false {
		t.Errorf("pathStatus.objectRoot.exists: got %v, want false (path does not exist)", objectRoot["exists"])
	}
	if objectRoot["writable"] != false {
		t.Errorf("pathStatus.objectRoot.writable: got %v, want false (path does not exist)", objectRoot["writable"])
	}
	if objectRoot["kind"] != "unknown" {
		t.Errorf("pathStatus.objectRoot.kind: got %v, want unknown", objectRoot["kind"])
	}
}

// Test 10: settings response contains paths configuration.
func TestSettings_ContainsPathsFields(t *testing.T) {
	cfg := testConfig(t)
	handler, _ := setupTestUIServerWithConfig(t, cfg)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doSettings(t, handler, loginRR.Result().Cookies())
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	paths, ok := resp["paths"].(map[string]interface{})
	if !ok {
		t.Fatal("missing paths object in response")
	}
	if paths["metaDB"] == nil || paths["metaDB"] == "" {
		t.Error("paths.metaDB should not be empty")
	}
	if paths["objectRoot"] == nil || paths["objectRoot"] == "" {
		t.Error("paths.objectRoot should not be empty")
	}
	if paths["multipartRoot"] == nil || paths["multipartRoot"] == "" {
		t.Error("paths.multipartRoot should not be empty")
	}
	if paths["tempRoot"] == nil || paths["tempRoot"] == "" {
		t.Error("paths.tempRoot should not be empty")
	}
	if paths["logRoot"] == nil || paths["logRoot"] == "" {
		t.Error("paths.logRoot should not be empty")
	}
}

// Test 11: settings response contains ui configuration.
func TestSettings_ContainsUIFields(t *testing.T) {
	cfg := testConfig(t)
	handler, _ := setupTestUIServerWithConfig(t, cfg)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doSettings(t, handler, loginRR.Result().Cookies())
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	uiCfg, ok := resp["ui"].(map[string]interface{})
	if !ok {
		t.Fatal("missing ui object in response")
	}
	if uiCfg["sessionTTL"] == nil || uiCfg["sessionTTL"] == "" {
		t.Error("ui.sessionTTL should not be empty")
	}
	if uiCfg["sessionIdleTTL"] == nil || uiCfg["sessionIdleTTL"] == "" {
		t.Error("ui.sessionIdleTTL should not be empty")
	}
}

// Test 12: settings response contains logging configuration.
func TestSettings_ContainsLoggingFields(t *testing.T) {
	cfg := testConfig(t)
	handler, _ := setupTestUIServerWithConfig(t, cfg)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doSettings(t, handler, loginRR.Result().Cookies())
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	logging, ok := resp["logging"].(map[string]interface{})
	if !ok {
		t.Fatal("missing logging object in response")
	}
	if logging["level"] != "info" {
		t.Errorf("logging.level: got %v, want info", logging["level"])
	}
	if logging["accessLog"] != true {
		t.Errorf("logging.accessLog: got %v, want true", logging["accessLog"])
	}
}

// Test 13: settings response contains gc configuration.
func TestSettings_ContainsGCFields(t *testing.T) {
	cfg := testConfig(t)
	handler, _ := setupTestUIServerWithConfig(t, cfg)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doSettings(t, handler, loginRR.Result().Cookies())
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	gc, ok := resp["gc"].(map[string]interface{})
	if !ok {
		t.Fatal("missing gc object in response")
	}
	if gc["orphanScanInterval"] == nil || gc["orphanScanInterval"] == "" {
		t.Error("gc.orphanScanInterval should not be empty")
	}
	if gc["orphanGracePeriod"] == nil || gc["orphanGracePeriod"] == "" {
		t.Error("gc.orphanGracePeriod should not be empty")
	}
	if gc["multipartExpiry"] == nil || gc["multipartExpiry"] == "" {
		t.Error("gc.multipartExpiry should not be empty")
	}
}

// Test 14: POST to /ui/api/settings returns 405 Method Not Allowed.
func TestSettings_MethodNotAllowed(t *testing.T) {
	cfg := testConfig(t)
	handler, _ := setupTestUIServerWithConfig(t, cfg)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	req := httptest.NewRequest(http.MethodPost, "/ui/api/settings", nil)
	for _, c := range loginRR.Result().Cookies() {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// Test 15: disk stats fields are present in pathStatus when path exists.
// Per product-spec.md section 7.4: disk usage and free space.
func TestSettings_DiskStatsPresent(t *testing.T) {
	cfg := testConfig(t)
	// Create directories so they exist.
	if err := os.MkdirAll(cfg.Paths.ObjectRoot, 0750); err != nil {
		t.Fatalf("creating object root: %v", err)
	}

	handler, _ := setupTestUIServerWithConfig(t, cfg)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doSettings(t, handler, loginRR.Result().Cookies())
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	pathStatus, ok := resp["pathStatus"].(map[string]interface{})
	if !ok {
		t.Fatal("missing pathStatus object in response")
	}

	objectRoot, ok := pathStatus["objectRoot"].(map[string]interface{})
	if !ok {
		t.Fatal("missing pathStatus.objectRoot")
	}

	diskStats, ok := objectRoot["diskStats"].(map[string]interface{})
	if !ok {
		t.Fatal("missing pathStatus.objectRoot.diskStats")
	}

	// Verify disk stats fields are present.
	if _, ok := diskStats["totalBytes"]; !ok {
		t.Error("diskStats.totalBytes field missing")
	}
	if _, ok := diskStats["freeBytes"]; !ok {
		t.Error("diskStats.freeBytes field missing")
	}
	if _, ok := diskStats["usedBytes"]; !ok {
		t.Error("diskStats.usedBytes field missing")
	}
}

// Test 16: disk stats values are non-negative numbers when path exists.
func TestSettings_DiskStatsNonNegative(t *testing.T) {
	cfg := testConfig(t)
	if err := os.MkdirAll(cfg.Paths.ObjectRoot, 0750); err != nil {
		t.Fatalf("creating object root: %v", err)
	}

	handler, _ := setupTestUIServerWithConfig(t, cfg)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doSettings(t, handler, loginRR.Result().Cookies())
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	pathStatus := resp["pathStatus"].(map[string]interface{})
	objectRoot := pathStatus["objectRoot"].(map[string]interface{})
	diskStats := objectRoot["diskStats"].(map[string]interface{})

	// JSON numbers are decoded as float64.
	totalBytes, ok := diskStats["totalBytes"].(float64)
	if !ok {
		t.Fatal("totalBytes is not a number")
	}
	if totalBytes < 0 {
		t.Errorf("totalBytes should be non-negative, got %f", totalBytes)
	}

	freeBytes, ok := diskStats["freeBytes"].(float64)
	if !ok {
		t.Fatal("freeBytes is not a number")
	}
	if freeBytes < 0 {
		t.Errorf("freeBytes should be non-negative, got %f", freeBytes)
	}

	usedBytes, ok := diskStats["usedBytes"].(float64)
	if !ok {
		t.Fatal("usedBytes is not a number")
	}
	if usedBytes < 0 {
		t.Errorf("usedBytes should be non-negative, got %f", usedBytes)
	}

	// Sanity check: used + free should approximately equal total.
	// Allow some rounding error from filesystem overhead.
	if totalBytes > 0 && (usedBytes+freeBytes) > totalBytes*1.1 {
		t.Errorf("disk math inconsistent: total=%f, used=%f, free=%f", totalBytes, usedBytes, freeBytes)
	}
}

// Test 17: meta_db (file path) gets disk stats from parent directory.
func TestSettings_DiskStats_MetaDBFilePath(t *testing.T) {
	cfg := testConfig(t)
	// Create the parent directory and file.
	metaDir := filepath.Dir(cfg.Paths.MetaDB)
	if err := os.MkdirAll(metaDir, 0750); err != nil {
		t.Fatalf("creating meta dir: %v", err)
	}
	f, err := os.Create(cfg.Paths.MetaDB)
	if err != nil {
		t.Fatalf("creating meta_db file: %v", err)
	}
	f.Close()

	handler, _ := setupTestUIServerWithConfig(t, cfg)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doSettings(t, handler, loginRR.Result().Cookies())
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	pathStatus := resp["pathStatus"].(map[string]interface{})
	metaDB, ok := pathStatus["metaDB"].(map[string]interface{})
	if !ok {
		t.Fatal("missing pathStatus.metaDB")
	}

	// Verify it's recognized as a file.
	if metaDB["kind"] != "file" {
		t.Errorf("metaDB.kind: got %v, want file", metaDB["kind"])
	}

	diskStats, ok := metaDB["diskStats"].(map[string]interface{})
	if !ok {
		t.Fatal("missing pathStatus.metaDB.diskStats")
	}

	// Should have non-zero stats since the parent directory exists.
	totalBytes, ok := diskStats["totalBytes"].(float64)
	if !ok {
		t.Fatal("totalBytes is not a number")
	}
	if totalBytes == 0 {
		t.Error("metaDB diskStats.totalBytes should be non-zero when file exists")
	}
}

// Test 18: non-existent path has zero disk stats.
// Per policy: path does not exist → disk stats are 0.
func TestSettings_DiskStats_NonExistentPath(t *testing.T) {
	cfg := testConfig(t)
	// Don't create any directories; paths don't exist.

	handler, _ := setupTestUIServerWithConfig(t, cfg)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doSettings(t, handler, loginRR.Result().Cookies())
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	pathStatus := resp["pathStatus"].(map[string]interface{})
	objectRoot := pathStatus["objectRoot"].(map[string]interface{})

	// Path should not exist.
	if objectRoot["exists"] != false {
		t.Errorf("objectRoot.exists: got %v, want false", objectRoot["exists"])
	}

	diskStats, ok := objectRoot["diskStats"].(map[string]interface{})
	if !ok {
		t.Fatal("missing pathStatus.objectRoot.diskStats")
	}

	// All disk stats should be zero for non-existent path.
	totalBytes := diskStats["totalBytes"].(float64)
	freeBytes := diskStats["freeBytes"].(float64)
	usedBytes := diskStats["usedBytes"].(float64)

	if totalBytes != 0 {
		t.Errorf("non-existent path should have totalBytes=0, got %f", totalBytes)
	}
	if freeBytes != 0 {
		t.Errorf("non-existent path should have freeBytes=0, got %f", freeBytes)
	}
	if usedBytes != 0 {
		t.Errorf("non-existent path should have usedBytes=0, got %f", usedBytes)
	}
}

// Test 19: all five path types have diskStats in response.
func TestSettings_DiskStats_AllPathsHaveStats(t *testing.T) {
	cfg := testConfig(t)
	// Create all paths.
	if err := os.MkdirAll(filepath.Dir(cfg.Paths.MetaDB), 0750); err != nil {
		t.Fatalf("creating meta dir: %v", err)
	}
	f, err := os.Create(cfg.Paths.MetaDB)
	if err != nil {
		t.Fatalf("creating meta_db file: %v", err)
	}
	f.Close()
	if err := os.MkdirAll(cfg.Paths.ObjectRoot, 0750); err != nil {
		t.Fatalf("creating object root: %v", err)
	}
	if err := os.MkdirAll(cfg.Paths.MultipartRoot, 0750); err != nil {
		t.Fatalf("creating multipart root: %v", err)
	}
	if err := os.MkdirAll(cfg.Paths.TempRoot, 0750); err != nil {
		t.Fatalf("creating temp root: %v", err)
	}
	if err := os.MkdirAll(cfg.Paths.LogRoot, 0750); err != nil {
		t.Fatalf("creating log root: %v", err)
	}

	handler, _ := setupTestUIServerWithConfig(t, cfg)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doSettings(t, handler, loginRR.Result().Cookies())
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	pathStatus := resp["pathStatus"].(map[string]interface{})

	pathNames := []string{"metaDB", "objectRoot", "multipartRoot", "tempRoot", "logRoot"}
	for _, name := range pathNames {
		pathInfo, ok := pathStatus[name].(map[string]interface{})
		if !ok {
			t.Errorf("missing pathStatus.%s", name)
			continue
		}

		diskStats, ok := pathInfo["diskStats"].(map[string]interface{})
		if !ok {
			t.Errorf("missing pathStatus.%s.diskStats", name)
			continue
		}

		// Verify all three fields exist.
		if _, ok := diskStats["totalBytes"]; !ok {
			t.Errorf("pathStatus.%s.diskStats.totalBytes missing", name)
		}
		if _, ok := diskStats["freeBytes"]; !ok {
			t.Errorf("pathStatus.%s.diskStats.freeBytes missing", name)
		}
		if _, ok := diskStats["usedBytes"]; !ok {
			t.Errorf("pathStatus.%s.diskStats.usedBytes missing", name)
		}
	}
}

// containsString checks if substr is in s.
func containsString(s, substr string) bool {
	return len(substr) > 0 && len(s) >= len(substr) && (s == substr || containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
