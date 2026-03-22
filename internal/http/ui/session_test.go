package ui_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lukehemmin/hemmins-s3-api/internal/auth"
	"github.com/lukehemmin/hemmins-s3-api/internal/config"
	ui "github.com/lukehemmin/hemmins-s3-api/internal/http/ui"
	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

const (
	testAdminUsername  = "testadmin"
	testAdminPassword  = "testpassword123!"
	testAccessKey      = "AKIATESTUI00000001"
	testMasterKey      = "test-master-key-for-ui-tests-only"
	testRootSecretKey  = "testsecret123"
	testRegion         = "us-east-1"
	testPublicEndpoint = "http://localhost:9000"
)

// setupTestUIServer creates a bootstrapped DB, a SessionStore, and a ui.Server.
// The admin user is created via db.Bootstrap (same flow as real startup).
func setupTestUIServer(t *testing.T, secureCookie bool) (http.Handler, *metadata.DB) {
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

	// Create temp directories for object storage.
	dataDir := t.TempDir()
	objectRoot := filepath.Join(dataDir, "objects")
	tempRoot := filepath.Join(dataDir, "tmp")
	if err := os.MkdirAll(objectRoot, 0750); err != nil {
		t.Fatalf("MkdirAll objectRoot: %v", err)
	}
	if err := os.MkdirAll(tempRoot, 0750); err != nil {
		t.Fatalf("MkdirAll tempRoot: %v", err)
	}

	// Create config with storage paths and presign settings.
	cfg := &config.Config{
		Paths: config.PathsConfig{
			ObjectRoot: objectRoot,
			TempRoot:   tempRoot,
		},
		Server: config.ServerConfig{
			PublicEndpoint: testPublicEndpoint,
		},
		S3: config.S3Config{
			Region:        testRegion,
			MaxPresignTTL: config.Duration{Duration: 1 * time.Hour},
		},
		Auth: config.AuthConfig{
			MasterKey: testMasterKey,
		},
	}

	store := ui.NewSessionStore(12*time.Hour, 30*time.Minute)
	srv := ui.NewServer(db, store, secureCookie)
	srv.SetConfig(cfg)
	return srv.Handler(), db
}

// doLogin issues POST /ui/api/session/login with JSON credentials and CSRF token.
// Automatically fetches a CSRF token first.
func doLogin(t *testing.T, handler http.Handler, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	// First, get a CSRF token.
	csrfRR := doCSRF(t, handler)
	if csrfRR.Code != http.StatusOK {
		t.Fatalf("failed to get CSRF token: %d", csrfRR.Code)
	}
	csrfCookie := findCSRFCookie(csrfRR)
	if csrfCookie == nil {
		t.Fatal("no CSRF cookie in response")
	}
	var csrfResp map[string]string
	if err := json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp); err != nil {
		t.Fatalf("parsing CSRF response: %v", err)
	}
	token := csrfResp["token"]

	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	req := httptest.NewRequest(http.MethodPost, "/ui/api/session/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", token)
	req.AddCookie(csrfCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// doLoginWithoutCSRF issues POST /ui/api/session/login WITHOUT CSRF token (for testing CSRF enforcement).
func doLoginWithoutCSRF(t *testing.T, handler http.Handler, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	req := httptest.NewRequest(http.MethodPost, "/ui/api/session/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// doLoginWithMismatchedCSRF issues POST /ui/api/session/login with a mismatched CSRF token.
func doLoginWithMismatchedCSRF(t *testing.T, handler http.Handler, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	// Get a CSRF token.
	csrfRR := doCSRF(t, handler)
	if csrfRR.Code != http.StatusOK {
		t.Fatalf("failed to get CSRF token: %d", csrfRR.Code)
	}
	csrfCookie := findCSRFCookie(csrfRR)
	if csrfCookie == nil {
		t.Fatal("no CSRF cookie in response")
	}

	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	req := httptest.NewRequest(http.MethodPost, "/ui/api/session/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// Use a different token in header than what's in cookie.
	req.Header.Set("X-CSRF-Token", "wrong-token-value")
	req.AddCookie(csrfCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// doCSRF issues GET /ui/api/session/csrf.
func doCSRF(t *testing.T, handler http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/ui/api/session/csrf", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// doMe issues GET /ui/api/session/me with the given cookies.
func doMe(t *testing.T, handler http.Handler, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/ui/api/session/me", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// doLogout issues POST /ui/api/session/logout with the given cookies and CSRF token.
// Automatically fetches a CSRF token first.
func doLogout(t *testing.T, handler http.Handler, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	// First, get a CSRF token.
	csrfRR := doCSRF(t, handler)
	if csrfRR.Code != http.StatusOK {
		t.Fatalf("failed to get CSRF token: %d", csrfRR.Code)
	}
	csrfCookie := findCSRFCookie(csrfRR)
	if csrfCookie == nil {
		t.Fatal("no CSRF cookie in response")
	}
	var csrfResp map[string]string
	if err := json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp); err != nil {
		t.Fatalf("parsing CSRF response: %v", err)
	}
	token := csrfResp["token"]

	req := httptest.NewRequest(http.MethodPost, "/ui/api/session/logout", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	req.Header.Set("X-CSRF-Token", token)
	req.AddCookie(csrfCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// doLogoutWithoutCSRF issues POST /ui/api/session/logout WITHOUT CSRF token (for testing CSRF enforcement).
func doLogoutWithoutCSRF(t *testing.T, handler http.Handler, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/ui/api/session/logout", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// findSessionCookie extracts the hemmins_session cookie from the response, or nil.
func findSessionCookie(rr *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rr.Result().Cookies() {
		if c.Name == "hemmins_session" {
			return c
		}
	}
	return nil
}

// findCSRFCookie extracts the hemmins_csrf cookie from the response, or nil.
func findCSRFCookie(rr *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rr.Result().Cookies() {
		if c.Name == "hemmins_csrf" {
			return c
		}
	}
	return nil
}

// Test 1: bootstrap-created admin can log in successfully.
func TestLogin_BootstrapAdminSuccess(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	rr := doLogin(t, handler, testAdminUsername, testAdminPassword)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response body: %v", err)
	}
	if resp["username"] != testAdminUsername {
		t.Errorf("username: got %q, want %q", resp["username"], testAdminUsername)
	}
	if resp["role"] != "admin" {
		t.Errorf("role: got %q, want %q", resp["role"], "admin")
	}
}

// Test 2: wrong password returns 401.
func TestLogin_WrongPassword(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	rr := doLogin(t, handler, testAdminUsername, "wrongpassword!")

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// Test 3: unknown username returns 401.
func TestLogin_UnknownUsername(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	rr := doLogin(t, handler, "nosuchuser", testAdminPassword)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// Test 4: successful login sets the session cookie.
func TestLogin_SetsCookie(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	rr := doLogin(t, handler, testAdminUsername, testAdminPassword)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	c := findSessionCookie(rr)
	if c == nil {
		t.Fatal("expected hemmins_session cookie in response, got none")
	}
	if c.Value == "" {
		t.Error("expected non-empty cookie value")
	}
}

// Test 5: the session cookie has HttpOnly set.
func TestLogin_CookieIsHttpOnly(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	rr := doLogin(t, handler, testAdminUsername, testAdminPassword)

	c := findSessionCookie(rr)
	if c == nil {
		t.Fatal("no session cookie in response")
	}
	if !c.HttpOnly {
		t.Error("expected cookie to be HttpOnly")
	}
}

// Test 6: the session cookie has SameSite=Lax.
func TestLogin_CookieSameSiteLax(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	rr := doLogin(t, handler, testAdminUsername, testAdminPassword)

	c := findSessionCookie(rr)
	if c == nil {
		t.Fatal("no session cookie in response")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("expected SameSite=Lax, got %v", c.SameSite)
	}
}

// Test 7: when public endpoint is https://, the session cookie has the Secure flag.
func TestLogin_SecureEndpoint_CookieIsSecure(t *testing.T) {
	handler, _ := setupTestUIServer(t, true /* secureCookie=true */)
	rr := doLogin(t, handler, testAdminUsername, testAdminPassword)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	c := findSessionCookie(rr)
	if c == nil {
		t.Fatal("no session cookie in response")
	}
	if !c.Secure {
		t.Error("expected cookie to have Secure flag when public endpoint is https://")
	}
}

// Test 8: GET /ui/api/session/me with a valid cookie returns 200 with username and role.
func TestMe_ValidSession(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	meRR := doMe(t, handler, loginRR.Result().Cookies())
	if meRR.Code != http.StatusOK {
		t.Fatalf("expected 200 from /me, got %d: %s", meRR.Code, meRR.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(meRR.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing /me response: %v", err)
	}
	if resp["username"] != testAdminUsername {
		t.Errorf("username: got %q, want %q", resp["username"], testAdminUsername)
	}
	if resp["role"] != "admin" {
		t.Errorf("role: got %q, want %q", resp["role"], "admin")
	}
}

// Test 9: GET /ui/api/session/me without a cookie returns 401.
func TestMe_NoCookie(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	rr := doMe(t, handler, nil)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// Test 10: idle expiry is enforced — session expires after idle TTL without activity.
func TestSession_IdleExpiry(t *testing.T) {
	db, err := metadata.Open(":memory:")
	if err != nil {
		t.Fatalf("metadata.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	pwHash, err := auth.HashPassword(testAdminPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	ciphertext, err := auth.EncryptSecret(testMasterKey, "testsecret")
	if err != nil {
		t.Fatalf("EncryptSecret: %v", err)
	}
	if err := db.Bootstrap(testAdminUsername, pwHash, testAccessKey, ciphertext); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	// Very short idle TTL (50ms) to make expiry testable without long waits.
	store := ui.NewSessionStore(10*time.Second, 50*time.Millisecond)
	srv := ui.NewServer(db, store, false)
	handler := srv.Handler()

	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Immediately after login: session is valid.
	meRR := doMe(t, handler, loginRR.Result().Cookies())
	if meRR.Code != http.StatusOK {
		t.Fatalf("expected 200 immediately after login, got %d", meRR.Code)
	}

	// Wait longer than the idle TTL without any activity.
	time.Sleep(80 * time.Millisecond)

	// Session should now be expired due to idle TTL.
	meRR2 := doMe(t, handler, loginRR.Result().Cookies())
	if meRR2.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 after idle TTL, got %d", meRR2.Code)
	}
}

// Test 11: logout invalidates the session — subsequent /me returns 401.
func TestLogout_InvalidatesSession(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	logoutRR := doLogout(t, handler, loginRR.Result().Cookies())
	if logoutRR.Code != http.StatusNoContent {
		t.Errorf("expected 204 from logout, got %d", logoutRR.Code)
	}

	// Session must be gone after logout.
	meRR := doMe(t, handler, loginRR.Result().Cookies())
	if meRR.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 after logout, got %d", meRR.Code)
	}
}

// Test 12: logout response includes a Set-Cookie that clears the session cookie.
func TestLogout_ClearsCookie(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	logoutRR := doLogout(t, handler, loginRR.Result().Cookies())
	if logoutRR.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", logoutRR.Code)
	}

	// Set-Cookie header must be present and contain Max-Age=0.
	rawHeader := logoutRR.Header().Get("Set-Cookie")
	if rawHeader == "" {
		t.Fatal("expected Set-Cookie header in logout response")
	}
	if !strings.Contains(rawHeader, "Max-Age=0") {
		t.Errorf("expected Max-Age=0 in logout Set-Cookie, got: %q", rawHeader)
	}

	// Cookie value must be empty.
	c := findSessionCookie(logoutRR)
	if c != nil && c.Value != "" {
		t.Errorf("expected empty cookie value on logout, got %q", c.Value)
	}
}

// Test 14: DB lookup failure returns 500, not 401.
// Closing the DB forces LookupUIUser to return a non-ErrUserNotFound error.
// A server-side failure must not be misclassified as an authentication failure.
func TestLogin_DBLookupFailure_Returns500(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	// Close the DB before the request to simulate a lookup failure.
	// t.Cleanup will call Close again; double-close on sql.DB is safe.
	db.Close()

	rr := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 on DB failure, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 15: malformed stored password hash returns 500, not 401.
// A corrupted hash in the DB is a server-side data problem, not an auth failure.
// VerifyPassword returns (false, err) on parse errors — must map to 500.
func TestLogin_MalformedStoredHash_Returns500(t *testing.T) {
	db, err := metadata.Open(":memory:")
	if err != nil {
		t.Fatalf("metadata.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// Insert a user with a deliberately malformed password hash to simulate corruption.
	_, err = db.SQLDB().Exec(
		"INSERT INTO ui_users (username, password_hash, role, created_at) VALUES (?, ?, 'admin', datetime('now'))",
		"corrupteduser", "not-a-valid-argon2id-hash",
	)
	if err != nil {
		t.Fatalf("inserting user with bad hash: %v", err)
	}

	store := ui.NewSessionStore(12*time.Hour, 30*time.Minute)
	srv := ui.NewServer(db, store, false)
	handler := srv.Handler()

	rr := doLogin(t, handler, "corrupteduser", "anypassword")
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 on malformed stored hash, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 13: logout is idempotent — no-session returns 204, not an error.
// Policy: absent or invalid session → 204 (no info leaked). Pinned here.
// Note: CSRF validation is still required even for idempotent logout.
func TestLogout_Idempotent(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	// Logout with no session cookie at all (but with valid CSRF).
	rr1 := doLogout(t, handler, nil)
	if rr1.Code != http.StatusNoContent {
		t.Errorf("logout with no cookie: expected 204, got %d", rr1.Code)
	}

	// Logout with an invalid session cookie (but with valid CSRF).
	// Get a CSRF token first.
	csrfRR := doCSRF(t, handler)
	csrfCookie := findCSRFCookie(csrfRR)
	var csrfResp map[string]string
	_ = json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp)
	token := csrfResp["token"]

	req := httptest.NewRequest(http.MethodPost, "/ui/api/session/logout", nil)
	req.AddCookie(&http.Cookie{Name: "hemmins_session", Value: "invalid-session-token"})
	req.Header.Set("X-CSRF-Token", token)
	req.AddCookie(csrfCookie)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req)
	if rr2.Code != http.StatusNoContent {
		t.Errorf("logout with invalid cookie: expected 204, got %d", rr2.Code)
	}
}

// ============================================================================
// CSRF Tests (Tests 16-26)
// Per security-model.md section 6: state-changing requests require CSRF protection.
// ============================================================================

// Test 16: GET /ui/api/session/csrf returns 200 and a token.
func TestCSRF_ReturnsToken(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	rr := doCSRF(t, handler)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if resp["token"] == "" {
		t.Error("expected non-empty token in response")
	}
}

// Test 17: CSRF endpoint sets a cookie.
func TestCSRF_SetsCookie(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	rr := doCSRF(t, handler)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	c := findCSRFCookie(rr)
	if c == nil {
		t.Fatal("expected hemmins_csrf cookie in response, got none")
	}
	if c.Value == "" {
		t.Error("expected non-empty cookie value")
	}
}

// Test 18: CSRF cookie value matches JSON token.
func TestCSRF_CookieMatchesToken(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	rr := doCSRF(t, handler)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	c := findCSRFCookie(rr)
	if c == nil {
		t.Fatal("no CSRF cookie")
	}

	if c.Value != resp["token"] {
		t.Errorf("cookie value %q does not match JSON token %q", c.Value, resp["token"])
	}
}

// Test 19: CSRF cookie has SameSite=Lax.
func TestCSRF_CookieSameSiteLax(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	rr := doCSRF(t, handler)

	c := findCSRFCookie(rr)
	if c == nil {
		t.Fatal("no CSRF cookie")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("expected SameSite=Lax, got %v", c.SameSite)
	}
}

// Test 20: CSRF cookie is NOT HttpOnly (required for double-submit pattern).
func TestCSRF_CookieNotHttpOnly(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	rr := doCSRF(t, handler)

	c := findCSRFCookie(rr)
	if c == nil {
		t.Fatal("no CSRF cookie")
	}
	// CSRF cookie must NOT be HttpOnly so JS can read it.
	if c.HttpOnly {
		t.Error("CSRF cookie should not be HttpOnly; JS must read it for double-submit pattern")
	}
}

// Test 21: HTTPS mode sets Secure on CSRF cookie.
func TestCSRF_SecureEndpoint_CookieIsSecure(t *testing.T) {
	handler, _ := setupTestUIServer(t, true /* secureCookie=true */)
	rr := doCSRF(t, handler)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	c := findCSRFCookie(rr)
	if c == nil {
		t.Fatal("no CSRF cookie")
	}
	if !c.Secure {
		t.Error("expected CSRF cookie to have Secure flag when public endpoint is https://")
	}
}

// Test 22: Login without CSRF token returns 403.
func TestLogin_WithoutCSRF_Returns403(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	rr := doLoginWithoutCSRF(t, handler, testAdminUsername, testAdminPassword)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing error response: %v", err)
	}
	if !strings.Contains(resp["error"], "CSRF") {
		t.Errorf("expected CSRF error message, got %q", resp["error"])
	}
}

// Test 23: Login with mismatched CSRF token returns 403.
func TestLogin_MismatchedCSRF_Returns403(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	rr := doLoginWithMismatchedCSRF(t, handler, testAdminUsername, testAdminPassword)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 24: Login with valid CSRF token succeeds.
func TestLogin_ValidCSRF_Returns200(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	rr := doLogin(t, handler, testAdminUsername, testAdminPassword)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 25: Logout without CSRF token returns 403.
func TestLogout_WithoutCSRF_Returns403(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	// First login successfully.
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Attempt logout without CSRF.
	rr := doLogoutWithoutCSRF(t, handler, loginRR.Result().Cookies())
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 26: Logout with valid CSRF token returns 204.
func TestLogout_ValidCSRF_Returns204(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	// First login successfully.
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Logout with valid CSRF.
	rr := doLogout(t, handler, loginRR.Result().Cookies())
	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 27: GET endpoints (me, dashboard, buckets, settings) don't require CSRF.
func TestGETEndpoints_NoCSRFRequired(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	// Login to get a valid session.
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Test each GET endpoint without any CSRF token - they should all work.
	endpoints := []string{
		"/ui/api/session/me",
		"/ui/api/dashboard",
		"/ui/api/buckets",
	}

	for _, ep := range endpoints {
		req := httptest.NewRequest(http.MethodGet, ep, nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("%s: expected 200, got %d", ep, rr.Code)
		}
	}
}

// Test 28: Logout clears the CSRF cookie.
func TestLogout_ClearsCSRFCookie(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	// Login.
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Logout.
	logoutRR := doLogout(t, handler, loginRR.Result().Cookies())
	if logoutRR.Code != http.StatusNoContent {
		t.Fatalf("logout failed: %d", logoutRR.Code)
	}

	// Check that CSRF cookie is cleared.
	c := findCSRFCookie(logoutRR)
	if c != nil && c.MaxAge != -1 && c.Value != "" {
		t.Errorf("expected CSRF cookie to be cleared, got value=%q maxAge=%d", c.Value, c.MaxAge)
	}
}
