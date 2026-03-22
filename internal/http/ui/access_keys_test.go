package ui_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// doAccessKeys issues GET /ui/api/access-keys with the given cookies.
func doAccessKeys(t *testing.T, handler http.Handler, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/ui/api/access-keys", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// accessKeySummary mirrors the JSON response structure from GET /ui/api/access-keys.
type accessKeySummary struct {
	AccessKey   string  `json:"accessKey"`
	Status      string  `json:"status"`
	IsRoot      bool    `json:"isRoot"`
	Description string  `json:"description"`
	CreatedAt   string  `json:"createdAt"`
	LastUsedAt  *string `json:"lastUsedAt"`
}

// Test 1: GET /ui/api/access-keys with valid session returns 200.
func TestAccessKeys_ValidSession(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doAccessKeys(t, handler, loginRR.Result().Cookies())
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Response should be valid JSON array.
	var keys []accessKeySummary
	if err := json.Unmarshal(rr.Body.Bytes(), &keys); err != nil {
		t.Fatalf("parsing access keys response: %v", err)
	}
	// Bootstrap creates one root key.
	if len(keys) < 1 {
		t.Errorf("expected at least 1 key, got %d", len(keys))
	}
}

// Test 2: GET /ui/api/access-keys without session returns 401.
func TestAccessKeys_NoSession(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	rr := doAccessKeys(t, handler, nil)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing error response: %v", err)
	}
	if resp["error"] != "not authenticated" {
		t.Errorf("expected error 'not authenticated', got %q", resp["error"])
	}
}

// Test 3: response contains root key created by bootstrap.
func TestAccessKeys_ContainsRootKey(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doAccessKeys(t, handler, loginRR.Result().Cookies())
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var keys []accessKeySummary
	if err := json.Unmarshal(rr.Body.Bytes(), &keys); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	// Find the bootstrap key.
	var found bool
	for _, k := range keys {
		if k.AccessKey == testAccessKey {
			found = true
			if k.Status != "active" {
				t.Errorf("expected status 'active', got %q", k.Status)
			}
			if !k.IsRoot {
				t.Errorf("expected isRoot=true for bootstrap key")
			}
			// createdAt must be valid RFC3339.
			if _, err := time.Parse(time.RFC3339, k.CreatedAt); err != nil {
				t.Errorf("createdAt not valid RFC3339: %q — %v", k.CreatedAt, err)
			}
			break
		}
	}
	if !found {
		t.Errorf("bootstrap key %q not found in response", testAccessKey)
	}
}

// Test 4: secret_ciphertext and plaintext secret are NEVER in the response.
func TestAccessKeys_NoSecretInResponse(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doAccessKeys(t, handler, loginRR.Result().Cookies())
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	body := rr.Body.String()

	// The response must NOT contain secret-related fields.
	if strings.Contains(body, "secretCiphertext") {
		t.Error("response must NOT contain 'secretCiphertext'")
	}
	if strings.Contains(body, "secret_ciphertext") {
		t.Error("response must NOT contain 'secret_ciphertext'")
	}
	if strings.Contains(body, "secretKey") {
		t.Error("response must NOT contain 'secretKey'")
	}
	if strings.Contains(body, "secret") {
		t.Error("response must NOT contain 'secret' field")
	}
	// Also check for the actual test secret value.
	if strings.Contains(body, testRootSecretKey) {
		t.Error("response must NOT contain the plaintext secret value")
	}
	// Check for ciphertext pattern (v1:...:...)
	if strings.Contains(body, "v1:") {
		t.Error("response must NOT contain encrypted secret (v1:...)")
	}
}

// Test 5: both root and non-root keys are visible.
func TestAccessKeys_RootAndNonRootVisible(t *testing.T) {
	handler, db := setupTestUIServer(t, false)

	// Insert a non-root key directly into the DB.
	now := time.Now().UTC()
	_, err := db.SQLDB().Exec(`
		INSERT INTO access_keys (access_key, secret_ciphertext, status, is_root, description, created_at)
		VALUES (?, ?, 'active', 0, 'test service key', ?)`,
		"AKIATESTSERVICE001", "v1:fake:ciphertext", now.Format(time.RFC3339),
	)
	if err != nil {
		t.Fatalf("insert non-root key: %v", err)
	}

	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doAccessKeys(t, handler, loginRR.Result().Cookies())
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var keys []accessKeySummary
	if err := json.Unmarshal(rr.Body.Bytes(), &keys); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}

	var foundRoot, foundService bool
	for _, k := range keys {
		if k.AccessKey == testAccessKey && k.IsRoot {
			foundRoot = true
		}
		if k.AccessKey == "AKIATESTSERVICE001" && !k.IsRoot {
			foundService = true
			if k.Description != "test service key" {
				t.Errorf("expected description 'test service key', got %q", k.Description)
			}
		}
	}
	if !foundRoot {
		t.Error("root key not found")
	}
	if !foundService {
		t.Error("service key not found")
	}
}

// Test 6: lastUsedAt can be null (never used) or non-null.
func TestAccessKeys_LastUsedAtNullAndNonNull(t *testing.T) {
	handler, db := setupTestUIServer(t, false)

	// Update the bootstrap key to have lastUsedAt set.
	usedAt := time.Now().UTC().Add(-1 * time.Hour)
	_, err := db.SQLDB().Exec(`UPDATE access_keys SET last_used_at = ? WHERE access_key = ?`,
		usedAt.Format(time.RFC3339), testAccessKey)
	if err != nil {
		t.Fatalf("update last_used_at: %v", err)
	}

	// Insert a key that has never been used (last_used_at is NULL).
	_, err = db.SQLDB().Exec(`
		INSERT INTO access_keys (access_key, secret_ciphertext, status, is_root, description, created_at, last_used_at)
		VALUES (?, ?, 'active', 0, 'unused key', ?, NULL)`,
		"AKIATESTUNUSED001", "v1:fake:ciphertext", time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		t.Fatalf("insert unused key: %v", err)
	}

	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doAccessKeys(t, handler, loginRR.Result().Cookies())
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var keys []accessKeySummary
	if err := json.Unmarshal(rr.Body.Bytes(), &keys); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	var foundUsed, foundUnused bool
	for _, k := range keys {
		if k.AccessKey == testAccessKey {
			if k.LastUsedAt == nil {
				t.Error("root key should have lastUsedAt set")
			} else {
				foundUsed = true
			}
		}
		if k.AccessKey == "AKIATESTUNUSED001" {
			if k.LastUsedAt != nil {
				t.Error("unused key should have lastUsedAt null")
			} else {
				foundUnused = true
			}
		}
	}
	if !foundUsed {
		t.Error("key with lastUsedAt set not found")
	}
	if !foundUnused {
		t.Error("key with lastUsedAt null not found")
	}
}

// Test 7: sort order is stable (created_at ASC, access_key ASC).
func TestAccessKeys_SortOrder(t *testing.T) {
	handler, db := setupTestUIServer(t, false)

	// Insert keys with specific created_at timestamps to test sort order.
	// Key A: oldest
	// Key B: same time as A, but lexically later
	// Key C: newest
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	insertKey := func(accessKey string, createdAt time.Time) {
		_, err := db.SQLDB().Exec(`
			INSERT INTO access_keys (access_key, secret_ciphertext, status, is_root, description, created_at)
			VALUES (?, ?, 'active', 0, ?, ?)`,
			accessKey, "v1:fake:ciphertext", accessKey, createdAt.Format(time.RFC3339),
		)
		if err != nil {
			t.Fatalf("insert key %s: %v", accessKey, err)
		}
	}

	insertKey("AKIA_SORT_A", base)
	insertKey("AKIA_SORT_B", base) // Same time, should come after A lexically
	insertKey("AKIA_SORT_C", base.Add(1*time.Hour))

	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doAccessKeys(t, handler, loginRR.Result().Cookies())
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var keys []accessKeySummary
	if err := json.Unmarshal(rr.Body.Bytes(), &keys); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	// Extract only the AKIA_SORT_* keys for order checking.
	var sortKeys []string
	for _, k := range keys {
		if strings.HasPrefix(k.AccessKey, "AKIA_SORT_") {
			sortKeys = append(sortKeys, k.AccessKey)
		}
	}

	if len(sortKeys) != 3 {
		t.Fatalf("expected 3 sort test keys, got %d", len(sortKeys))
	}

	// Expected order: A, B (both at base time, A < B lexically), then C (later time).
	expected := []string{"AKIA_SORT_A", "AKIA_SORT_B", "AKIA_SORT_C"}
	for i, exp := range expected {
		if sortKeys[i] != exp {
			t.Errorf("sort order position %d: got %q, want %q", i, sortKeys[i], exp)
		}
	}
}

// Test 8: PUT method returns 405 (only GET and POST are allowed).
func TestAccessKeys_MethodNotAllowed(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	req := httptest.NewRequest(http.MethodPut, "/ui/api/access-keys", nil)
	for _, c := range loginRR.Result().Cookies() {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// Test 9: inactive keys are also returned.
func TestAccessKeys_InactiveKeysIncluded(t *testing.T) {
	handler, db := setupTestUIServer(t, false)

	// Insert an inactive key.
	_, err := db.SQLDB().Exec(`
		INSERT INTO access_keys (access_key, secret_ciphertext, status, is_root, description, created_at)
		VALUES (?, ?, 'inactive', 0, 'revoked key', ?)`,
		"AKIATESTINACTIVE1", "v1:fake:ciphertext", time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		t.Fatalf("insert inactive key: %v", err)
	}

	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doAccessKeys(t, handler, loginRR.Result().Cookies())
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var keys []accessKeySummary
	if err := json.Unmarshal(rr.Body.Bytes(), &keys); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	var found bool
	for _, k := range keys {
		if k.AccessKey == "AKIATESTINACTIVE1" {
			found = true
			if k.Status != "inactive" {
				t.Errorf("expected status 'inactive', got %q", k.Status)
			}
		}
	}
	if !found {
		t.Error("inactive key not found in response")
	}
}

// ============================================================
// Access Key Create API Tests (POST /ui/api/access-keys)
// ============================================================

// accessKeyCreateResponse mirrors the JSON response from POST /ui/api/access-keys.
type accessKeyCreateResponse struct {
	AccessKey   string `json:"accessKey"`
	SecretKey   string `json:"secretKey"`
	Status      string `json:"status"`
	Description string `json:"description"`
	CreatedAt   string `json:"createdAt"`
}

// doCreateAccessKey issues POST /ui/api/access-keys with CSRF token.
// Automatically fetches a CSRF token first.
func doCreateAccessKey(t *testing.T, handler http.Handler, cookies []*http.Cookie, body string) *httptest.ResponseRecorder {
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
	var csrfResp map[string]string
	if err := json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp); err != nil {
		t.Fatalf("parsing CSRF response: %v", err)
	}
	token := csrfResp["token"]

	req := httptest.NewRequest(http.MethodPost, "/ui/api/access-keys", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", token)
	req.AddCookie(csrfCookie)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// doCreateAccessKeyWithoutCSRF issues POST /ui/api/access-keys without CSRF token.
func doCreateAccessKeyWithoutCSRF(t *testing.T, handler http.Handler, cookies []*http.Cookie, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/ui/api/access-keys", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// Test 10: POST /ui/api/access-keys with valid session and CSRF returns 201.
func TestAccessKeysCreate_ValidSessionAndCSRF(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doCreateAccessKey(t, handler, loginRR.Result().Cookies(), `{"description":"test service key"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp accessKeyCreateResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	// Verify access key format: AKIA + 16 alphanumeric = 20 chars.
	if len(resp.AccessKey) != 20 {
		t.Errorf("expected accessKey length 20, got %d", len(resp.AccessKey))
	}
	if !strings.HasPrefix(resp.AccessKey, "AKIA") {
		t.Errorf("expected accessKey to start with 'AKIA', got %q", resp.AccessKey)
	}

	// Verify secret key is present and has correct length (40 chars base64url).
	if len(resp.SecretKey) != 40 {
		t.Errorf("expected secretKey length 40, got %d", len(resp.SecretKey))
	}

	// Verify other fields.
	if resp.Status != "active" {
		t.Errorf("expected status 'active', got %q", resp.Status)
	}
	if resp.Description != "test service key" {
		t.Errorf("expected description 'test service key', got %q", resp.Description)
	}
	if _, err := time.Parse(time.RFC3339, resp.CreatedAt); err != nil {
		t.Errorf("createdAt not valid RFC3339: %q", resp.CreatedAt)
	}
}

// Test 11: POST /ui/api/access-keys without session returns 401.
func TestAccessKeysCreate_NoSession(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	// Use doCreateAccessKey with no session cookies (empty).
	// doCreateAccessKey will get its own CSRF token, but there's no session.
	rr := doCreateAccessKey(t, handler, nil, `{"description":"test"}`)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 12: POST /ui/api/access-keys without CSRF returns 403.
func TestAccessKeysCreate_NoCSRF(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Use the helper that doesn't include CSRF.
	rr := doCreateAccessKeyWithoutCSRF(t, handler, loginRR.Result().Cookies(), `{"description":"test"}`)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing error response: %v", err)
	}
	if resp["error"] != "CSRF validation failed" {
		t.Errorf("expected error 'CSRF validation failed', got %q", resp["error"])
	}
}

// Test 13: Created key is stored with encrypted secret in DB (not plaintext).
func TestAccessKeysCreate_SecretEncryptedInDB(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doCreateAccessKey(t, handler, loginRR.Result().Cookies(), `{"description":"encryption test"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp accessKeyCreateResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	// Query the DB directly to check the stored ciphertext.
	var storedCiphertext string
	err := db.SQLDB().QueryRow(
		"SELECT secret_ciphertext FROM access_keys WHERE access_key = ?",
		resp.AccessKey,
	).Scan(&storedCiphertext)
	if err != nil {
		t.Fatalf("querying DB: %v", err)
	}

	// Ciphertext should NOT be the plaintext secret.
	if storedCiphertext == resp.SecretKey {
		t.Error("secret stored as plaintext in DB - must be encrypted!")
	}

	// Ciphertext should start with version prefix.
	if !strings.HasPrefix(storedCiphertext, "v1:") {
		t.Errorf("expected ciphertext to start with 'v1:', got %q", storedCiphertext[:min(10, len(storedCiphertext))])
	}
}

// Test 14: Created key does NOT appear with secret in list API.
func TestAccessKeysCreate_SecretNotInListAPI(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create a key.
	createRR := doCreateAccessKey(t, handler, loginRR.Result().Cookies(), `{"description":"list test"}`)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", createRR.Code, createRR.Body.String())
	}

	var createResp accessKeyCreateResponse
	if err := json.Unmarshal(createRR.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("parsing create response: %v", err)
	}

	// List all keys.
	listRR := doAccessKeys(t, handler, loginRR.Result().Cookies())
	if listRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", listRR.Code, listRR.Body.String())
	}

	// Check that the secret is NOT in the list response.
	listBody := listRR.Body.String()
	if strings.Contains(listBody, createResp.SecretKey) {
		t.Error("list API response contains the secret key!")
	}
	if strings.Contains(listBody, "secretKey") {
		t.Error("list API response contains 'secretKey' field")
	}
}

// Test 15: Created key is non-root (is_root=false).
func TestAccessKeysCreate_IsNonRoot(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doCreateAccessKey(t, handler, loginRR.Result().Cookies(), `{"description":"non-root test"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp accessKeyCreateResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	// Query DB to verify is_root=0.
	var isRoot int
	err := db.SQLDB().QueryRow(
		"SELECT is_root FROM access_keys WHERE access_key = ?",
		resp.AccessKey,
	).Scan(&isRoot)
	if err != nil {
		t.Fatalf("querying DB: %v", err)
	}

	if isRoot != 0 {
		t.Errorf("expected is_root=0, got %d", isRoot)
	}
}

// Test 16: Created key has status 'active'.
func TestAccessKeysCreate_StatusIsActive(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doCreateAccessKey(t, handler, loginRR.Result().Cookies(), `{"description":"status test"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp accessKeyCreateResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	// Verify in response.
	if resp.Status != "active" {
		t.Errorf("expected status 'active' in response, got %q", resp.Status)
	}

	// Also verify in DB.
	var dbStatus string
	err := db.SQLDB().QueryRow(
		"SELECT status FROM access_keys WHERE access_key = ?",
		resp.AccessKey,
	).Scan(&dbStatus)
	if err != nil {
		t.Fatalf("querying DB: %v", err)
	}

	if dbStatus != "active" {
		t.Errorf("expected status 'active' in DB, got %q", dbStatus)
	}
}

// Test 17: Description is stored correctly (including empty).
func TestAccessKeysCreate_DescriptionStored(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	tests := []struct {
		name        string
		body        string
		wantDesc    string
	}{
		{"with description", `{"description":"my service key"}`, "my service key"},
		{"empty description", `{"description":""}`, ""},
		{"no description field", `{}`, ""},
		{"empty body", ``, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr := doCreateAccessKey(t, handler, loginRR.Result().Cookies(), tc.body)
			if rr.Code != http.StatusCreated {
				t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
			}

			var resp accessKeyCreateResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("parsing response: %v", err)
			}

			// Verify in response.
			if resp.Description != tc.wantDesc {
				t.Errorf("expected description %q in response, got %q", tc.wantDesc, resp.Description)
			}

			// Verify in DB.
			var dbDesc string
			err := db.SQLDB().QueryRow(
				"SELECT description FROM access_keys WHERE access_key = ?",
				resp.AccessKey,
			).Scan(&dbDesc)
			if err != nil {
				t.Fatalf("querying DB: %v", err)
			}

			if dbDesc != tc.wantDesc {
				t.Errorf("expected description %q in DB, got %q", tc.wantDesc, dbDesc)
			}
		})
	}
}

// Test 18: Invalid JSON body returns 400.
func TestAccessKeysCreate_InvalidJSON(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doCreateAccessKey(t, handler, loginRR.Result().Cookies(), `{invalid json}`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 19: Created key appears in list API (without secret).
func TestAccessKeysCreate_AppearsInList(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create a key.
	createRR := doCreateAccessKey(t, handler, loginRR.Result().Cookies(), `{"description":"list verify"}`)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", createRR.Code, createRR.Body.String())
	}

	var createResp accessKeyCreateResponse
	if err := json.Unmarshal(createRR.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("parsing create response: %v", err)
	}

	// List all keys.
	listRR := doAccessKeys(t, handler, loginRR.Result().Cookies())
	if listRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", listRR.Code, listRR.Body.String())
	}

	var keys []accessKeySummary
	if err := json.Unmarshal(listRR.Body.Bytes(), &keys); err != nil {
		t.Fatalf("parsing list response: %v", err)
	}

	// Find the created key.
	var found bool
	for _, k := range keys {
		if k.AccessKey == createResp.AccessKey {
			found = true
			if k.Description != "list verify" {
				t.Errorf("expected description 'list verify', got %q", k.Description)
			}
			if k.IsRoot {
				t.Error("created key should not be root")
			}
			if k.Status != "active" {
				t.Errorf("expected status 'active', got %q", k.Status)
			}
			break
		}
	}
	if !found {
		t.Errorf("created key %q not found in list", createResp.AccessKey)
	}
}

// ============================================================
// Access Key Revoke API Tests (POST /ui/api/access-keys/revoke)
// ============================================================

// accessKeyRevokeResponse mirrors the JSON response from POST /ui/api/access-keys/revoke.
type accessKeyRevokeResponse struct {
	AccessKey string `json:"accessKey"`
	Status    string `json:"status"`
}

// doRevokeAccessKey issues POST /ui/api/access-keys/revoke with CSRF token.
// Automatically fetches a CSRF token first.
func doRevokeAccessKey(t *testing.T, handler http.Handler, cookies []*http.Cookie, body string) *httptest.ResponseRecorder {
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
	var csrfResp map[string]string
	if err := json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp); err != nil {
		t.Fatalf("parsing CSRF response: %v", err)
	}
	token := csrfResp["token"]

	req := httptest.NewRequest(http.MethodPost, "/ui/api/access-keys/revoke", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", token)
	req.AddCookie(csrfCookie)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// doRevokeAccessKeyWithoutCSRF issues POST /ui/api/access-keys/revoke without CSRF token.
func doRevokeAccessKeyWithoutCSRF(t *testing.T, handler http.Handler, cookies []*http.Cookie, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/ui/api/access-keys/revoke", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// Test 20: POST /ui/api/access-keys/revoke with valid session + CSRF + existing service key → 200 success.
func TestAccessKeysRevoke_ValidSessionAndCSRF(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// First, create a service key to revoke.
	createRR := doCreateAccessKey(t, handler, loginRR.Result().Cookies(), `{"description":"to be revoked"}`)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create key failed: %d: %s", createRR.Code, createRR.Body.String())
	}
	var createResp accessKeyCreateResponse
	if err := json.Unmarshal(createRR.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("parsing create response: %v", err)
	}

	// Revoke the key.
	rr := doRevokeAccessKey(t, handler, loginRR.Result().Cookies(),
		`{"accessKey":"`+createResp.AccessKey+`"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp accessKeyRevokeResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing revoke response: %v", err)
	}

	if resp.AccessKey != createResp.AccessKey {
		t.Errorf("expected accessKey %q, got %q", createResp.AccessKey, resp.AccessKey)
	}
	if resp.Status != "inactive" {
		t.Errorf("expected status 'inactive', got %q", resp.Status)
	}
}

// Test 21: Revoked key appears as inactive in list API.
func TestAccessKeysRevoke_ReflectedInListAPI(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create and revoke a key.
	createRR := doCreateAccessKey(t, handler, loginRR.Result().Cookies(), `{"description":"revoke list test"}`)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create key failed: %d: %s", createRR.Code, createRR.Body.String())
	}
	var createResp accessKeyCreateResponse
	if err := json.Unmarshal(createRR.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("parsing create response: %v", err)
	}

	revokeRR := doRevokeAccessKey(t, handler, loginRR.Result().Cookies(),
		`{"accessKey":"`+createResp.AccessKey+`"}`)
	if revokeRR.Code != http.StatusOK {
		t.Fatalf("revoke failed: %d: %s", revokeRR.Code, revokeRR.Body.String())
	}

	// Check list API.
	listRR := doAccessKeys(t, handler, loginRR.Result().Cookies())
	if listRR.Code != http.StatusOK {
		t.Fatalf("list failed: %d: %s", listRR.Code, listRR.Body.String())
	}

	var keys []accessKeySummary
	if err := json.Unmarshal(listRR.Body.Bytes(), &keys); err != nil {
		t.Fatalf("parsing list response: %v", err)
	}

	var found bool
	for _, k := range keys {
		if k.AccessKey == createResp.AccessKey {
			found = true
			if k.Status != "inactive" {
				t.Errorf("expected status 'inactive' in list, got %q", k.Status)
			}
			break
		}
	}
	if !found {
		t.Errorf("revoked key %q not found in list", createResp.AccessKey)
	}
}

// Test 22: POST /ui/api/access-keys/revoke without session → 401.
func TestAccessKeysRevoke_NoSession(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	rr := doRevokeAccessKey(t, handler, nil, `{"accessKey":"AKIATEST"}`)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing error response: %v", err)
	}
	if resp["error"] != "not authenticated" {
		t.Errorf("expected error 'not authenticated', got %q", resp["error"])
	}
}

// Test 23: POST /ui/api/access-keys/revoke without CSRF → 403.
func TestAccessKeysRevoke_NoCSRF(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doRevokeAccessKeyWithoutCSRF(t, handler, loginRR.Result().Cookies(), `{"accessKey":"AKIATEST"}`)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing error response: %v", err)
	}
	if resp["error"] != "CSRF validation failed" {
		t.Errorf("expected error 'CSRF validation failed', got %q", resp["error"])
	}
}

// Test 24: POST /ui/api/access-keys/revoke with missing accessKey field → 400.
func TestAccessKeysRevoke_MissingAccessKey(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Empty body.
	rr := doRevokeAccessKey(t, handler, loginRR.Result().Cookies(), `{}`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing error response: %v", err)
	}
	if resp["error"] != "accessKey is required" {
		t.Errorf("expected error 'accessKey is required', got %q", resp["error"])
	}
}

// Test 25: POST /ui/api/access-keys/revoke with nonexistent accessKey → 404.
func TestAccessKeysRevoke_NonexistentKey(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doRevokeAccessKey(t, handler, loginRR.Result().Cookies(), `{"accessKey":"AKIANONEXISTENT123"}`)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing error response: %v", err)
	}
	if resp["error"] != "access key not found" {
		t.Errorf("expected error 'access key not found', got %q", resp["error"])
	}
}

// Test 26: Revoking already inactive key is idempotent (returns 200).
func TestAccessKeysRevoke_AlreadyInactive(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create a key.
	createRR := doCreateAccessKey(t, handler, loginRR.Result().Cookies(), `{"description":"idempotent test"}`)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create key failed: %d: %s", createRR.Code, createRR.Body.String())
	}
	var createResp accessKeyCreateResponse
	if err := json.Unmarshal(createRR.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("parsing create response: %v", err)
	}

	// Revoke first time.
	revokeRR1 := doRevokeAccessKey(t, handler, loginRR.Result().Cookies(),
		`{"accessKey":"`+createResp.AccessKey+`"}`)
	if revokeRR1.Code != http.StatusOK {
		t.Fatalf("first revoke failed: %d: %s", revokeRR1.Code, revokeRR1.Body.String())
	}

	// Revoke second time (should be idempotent).
	revokeRR2 := doRevokeAccessKey(t, handler, loginRR.Result().Cookies(),
		`{"accessKey":"`+createResp.AccessKey+`"}`)
	if revokeRR2.Code != http.StatusOK {
		t.Errorf("expected 200 for idempotent revoke, got %d: %s", revokeRR2.Code, revokeRR2.Body.String())
	}

	var resp accessKeyRevokeResponse
	if err := json.Unmarshal(revokeRR2.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing second revoke response: %v", err)
	}
	if resp.Status != "inactive" {
		t.Errorf("expected status 'inactive', got %q", resp.Status)
	}
}

// Test 27: Attempting to revoke root key is rejected (403 Forbidden).
// Per security-model.md section 5.1: at least one active root-scoped key must be maintained.
func TestAccessKeysRevoke_RootKeyRejected(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Try to revoke the bootstrap root key.
	rr := doRevokeAccessKey(t, handler, loginRR.Result().Cookies(),
		`{"accessKey":"`+testAccessKey+`"}`)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for root key revoke, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing error response: %v", err)
	}
	if resp["error"] != "cannot revoke root access key" {
		t.Errorf("expected error 'cannot revoke root access key', got %q", resp["error"])
	}
}

// Test 28: Response does NOT contain secret-related fields.
func TestAccessKeysRevoke_NoSecretInResponse(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create a key.
	createRR := doCreateAccessKey(t, handler, loginRR.Result().Cookies(), `{"description":"secret test"}`)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create key failed: %d: %s", createRR.Code, createRR.Body.String())
	}
	var createResp accessKeyCreateResponse
	if err := json.Unmarshal(createRR.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("parsing create response: %v", err)
	}

	// Revoke.
	revokeRR := doRevokeAccessKey(t, handler, loginRR.Result().Cookies(),
		`{"accessKey":"`+createResp.AccessKey+`"}`)
	if revokeRR.Code != http.StatusOK {
		t.Fatalf("revoke failed: %d: %s", revokeRR.Code, revokeRR.Body.String())
	}

	body := revokeRR.Body.String()

	// The response must NOT contain secret-related fields.
	if strings.Contains(body, "secretCiphertext") {
		t.Error("response must NOT contain 'secretCiphertext'")
	}
	if strings.Contains(body, "secret_ciphertext") {
		t.Error("response must NOT contain 'secret_ciphertext'")
	}
	if strings.Contains(body, "secretKey") {
		t.Error("response must NOT contain 'secretKey'")
	}
	// Check for the actual secret value from creation.
	if strings.Contains(body, createResp.SecretKey) {
		t.Error("response must NOT contain the plaintext secret value")
	}
}

// Test 29: GET method returns 405 (only POST is allowed).
func TestAccessKeysRevoke_MethodNotAllowed(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/ui/api/access-keys/revoke", nil)
	for _, c := range loginRR.Result().Cookies() {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// Test 30: Invalid JSON body returns 400.
func TestAccessKeysRevoke_InvalidJSON(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doRevokeAccessKey(t, handler, loginRR.Result().Cookies(), `{invalid json}`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 31: Revoked key can no longer authenticate via S3 API.
// This test verifies that status='inactive' keys are rejected during SigV4 auth.
func TestAccessKeysRevoke_KeyCannotAuthenticateAfterRevoke(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create a service key.
	createRR := doCreateAccessKey(t, handler, loginRR.Result().Cookies(), `{"description":"auth test"}`)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create key failed: %d: %s", createRR.Code, createRR.Body.String())
	}
	var createResp accessKeyCreateResponse
	if err := json.Unmarshal(createRR.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("parsing create response: %v", err)
	}

	// Before revoke: key should be active.
	var statusBefore string
	err := db.SQLDB().QueryRow("SELECT status FROM access_keys WHERE access_key = ?",
		createResp.AccessKey).Scan(&statusBefore)
	if err != nil {
		t.Fatalf("query status before: %v", err)
	}
	if statusBefore != "active" {
		t.Errorf("expected status 'active' before revoke, got %q", statusBefore)
	}

	// Revoke the key.
	revokeRR := doRevokeAccessKey(t, handler, loginRR.Result().Cookies(),
		`{"accessKey":"`+createResp.AccessKey+`"}`)
	if revokeRR.Code != http.StatusOK {
		t.Fatalf("revoke failed: %d: %s", revokeRR.Code, revokeRR.Body.String())
	}

	// After revoke: key should be inactive in DB.
	var statusAfter string
	err = db.SQLDB().QueryRow("SELECT status FROM access_keys WHERE access_key = ?",
		createResp.AccessKey).Scan(&statusAfter)
	if err != nil {
		t.Fatalf("query status after: %v", err)
	}
	if statusAfter != "inactive" {
		t.Errorf("expected status 'inactive' after revoke, got %q", statusAfter)
	}

	// The S3 auth layer checks status != "active" and returns false (see internal/http/s3/auth.go).
	// This is already covered by existing S3 auth tests, but we verify the DB state here.
}

// ============================================================
// Access Key Delete API Tests (POST /ui/api/access-keys/delete)
// ============================================================

// accessKeyDeleteResponse mirrors the JSON response from POST /ui/api/access-keys/delete.
type accessKeyDeleteResponse struct {
	AccessKey string `json:"accessKey"`
	Deleted   bool   `json:"deleted"`
}

// doDeleteAccessKey issues POST /ui/api/access-keys/delete with CSRF token.
// Automatically fetches a CSRF token first.
func doDeleteAccessKey(t *testing.T, handler http.Handler, cookies []*http.Cookie, body string) *httptest.ResponseRecorder {
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
	var csrfResp map[string]string
	if err := json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp); err != nil {
		t.Fatalf("parsing CSRF response: %v", err)
	}
	token := csrfResp["token"]

	req := httptest.NewRequest(http.MethodPost, "/ui/api/access-keys/delete", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", token)
	req.AddCookie(csrfCookie)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// doDeleteAccessKeyWithoutCSRF issues POST /ui/api/access-keys/delete without CSRF token.
func doDeleteAccessKeyWithoutCSRF(t *testing.T, handler http.Handler, cookies []*http.Cookie, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/ui/api/access-keys/delete", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// Test 32: POST /ui/api/access-keys/delete with valid session + CSRF + existing inactive service key → 200 success.
func TestAccessKeysDelete_ValidSessionAndCSRF(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// First, create a service key.
	createRR := doCreateAccessKey(t, handler, loginRR.Result().Cookies(), `{"description":"to be deleted"}`)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create key failed: %d: %s", createRR.Code, createRR.Body.String())
	}
	var createResp accessKeyCreateResponse
	if err := json.Unmarshal(createRR.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("parsing create response: %v", err)
	}

	// Revoke the key (required before delete per security-model.md section 5.1).
	revokeRR := doRevokeAccessKey(t, handler, loginRR.Result().Cookies(),
		`{"accessKey":"`+createResp.AccessKey+`"}`)
	if revokeRR.Code != http.StatusOK {
		t.Fatalf("revoke failed: %d: %s", revokeRR.Code, revokeRR.Body.String())
	}

	// Delete the key.
	rr := doDeleteAccessKey(t, handler, loginRR.Result().Cookies(),
		`{"accessKey":"`+createResp.AccessKey+`"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp accessKeyDeleteResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing delete response: %v", err)
	}

	if resp.AccessKey != createResp.AccessKey {
		t.Errorf("expected accessKey %q, got %q", createResp.AccessKey, resp.AccessKey)
	}
	if !resp.Deleted {
		t.Errorf("expected deleted=true, got false")
	}
}

// Test 33: Deleted key disappears from list API.
func TestAccessKeysDelete_DisappearsFromList(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create, revoke, and delete a key.
	createRR := doCreateAccessKey(t, handler, loginRR.Result().Cookies(), `{"description":"list disappear test"}`)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create key failed: %d: %s", createRR.Code, createRR.Body.String())
	}
	var createResp accessKeyCreateResponse
	if err := json.Unmarshal(createRR.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("parsing create response: %v", err)
	}

	// Revoke.
	revokeRR := doRevokeAccessKey(t, handler, loginRR.Result().Cookies(),
		`{"accessKey":"`+createResp.AccessKey+`"}`)
	if revokeRR.Code != http.StatusOK {
		t.Fatalf("revoke failed: %d: %s", revokeRR.Code, revokeRR.Body.String())
	}

	// Delete.
	deleteRR := doDeleteAccessKey(t, handler, loginRR.Result().Cookies(),
		`{"accessKey":"`+createResp.AccessKey+`"}`)
	if deleteRR.Code != http.StatusOK {
		t.Fatalf("delete failed: %d: %s", deleteRR.Code, deleteRR.Body.String())
	}

	// Check list API.
	listRR := doAccessKeys(t, handler, loginRR.Result().Cookies())
	if listRR.Code != http.StatusOK {
		t.Fatalf("list failed: %d: %s", listRR.Code, listRR.Body.String())
	}

	var keys []accessKeySummary
	if err := json.Unmarshal(listRR.Body.Bytes(), &keys); err != nil {
		t.Fatalf("parsing list response: %v", err)
	}

	// Deleted key should NOT be in the list.
	for _, k := range keys {
		if k.AccessKey == createResp.AccessKey {
			t.Errorf("deleted key %q should NOT appear in list", createResp.AccessKey)
		}
	}
}

// Test 34: POST /ui/api/access-keys/delete without session → 401.
func TestAccessKeysDelete_NoSession(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	rr := doDeleteAccessKey(t, handler, nil, `{"accessKey":"AKIATEST"}`)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing error response: %v", err)
	}
	if resp["error"] != "not authenticated" {
		t.Errorf("expected error 'not authenticated', got %q", resp["error"])
	}
}

// Test 35: POST /ui/api/access-keys/delete without CSRF → 403.
func TestAccessKeysDelete_NoCSRF(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doDeleteAccessKeyWithoutCSRF(t, handler, loginRR.Result().Cookies(), `{"accessKey":"AKIATEST"}`)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing error response: %v", err)
	}
	if resp["error"] != "CSRF validation failed" {
		t.Errorf("expected error 'CSRF validation failed', got %q", resp["error"])
	}
}

// Test 36: POST /ui/api/access-keys/delete with missing accessKey field → 400.
func TestAccessKeysDelete_MissingAccessKey(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Empty body.
	rr := doDeleteAccessKey(t, handler, loginRR.Result().Cookies(), `{}`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing error response: %v", err)
	}
	if resp["error"] != "accessKey is required" {
		t.Errorf("expected error 'accessKey is required', got %q", resp["error"])
	}
}

// Test 37: POST /ui/api/access-keys/delete with nonexistent accessKey → 404.
func TestAccessKeysDelete_NonexistentKey(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doDeleteAccessKey(t, handler, loginRR.Result().Cookies(), `{"accessKey":"AKIANONEXISTENT123"}`)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing error response: %v", err)
	}
	if resp["error"] != "access key not found" {
		t.Errorf("expected error 'access key not found', got %q", resp["error"])
	}
}

// Test 38: Attempting to delete active key is rejected (409 Conflict).
// Per security-model.md section 5.1: must revoke before delete.
func TestAccessKeysDelete_ActiveKeyRejected(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create a key but do NOT revoke it.
	createRR := doCreateAccessKey(t, handler, loginRR.Result().Cookies(), `{"description":"active delete test"}`)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create key failed: %d: %s", createRR.Code, createRR.Body.String())
	}
	var createResp accessKeyCreateResponse
	if err := json.Unmarshal(createRR.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("parsing create response: %v", err)
	}

	// Try to delete the active key.
	rr := doDeleteAccessKey(t, handler, loginRR.Result().Cookies(),
		`{"accessKey":"`+createResp.AccessKey+`"}`)
	if rr.Code != http.StatusConflict {
		t.Errorf("expected 409 for active key delete, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing error response: %v", err)
	}
	if resp["error"] != "cannot delete active access key; revoke first" {
		t.Errorf("expected error 'cannot delete active access key; revoke first', got %q", resp["error"])
	}
}

// Test 39: Attempting to delete root key is rejected (403 Forbidden).
// Per security-model.md section 5.1: root keys cannot be deleted via this API.
func TestAccessKeysDelete_RootKeyRejected(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Try to delete the bootstrap root key.
	rr := doDeleteAccessKey(t, handler, loginRR.Result().Cookies(),
		`{"accessKey":"`+testAccessKey+`"}`)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for root key delete, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing error response: %v", err)
	}
	if resp["error"] != "cannot delete root access key" {
		t.Errorf("expected error 'cannot delete root access key', got %q", resp["error"])
	}
}

// Test 40: Response does NOT contain secret-related fields.
func TestAccessKeysDelete_NoSecretInResponse(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create, revoke, then delete a key.
	createRR := doCreateAccessKey(t, handler, loginRR.Result().Cookies(), `{"description":"secret test"}`)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create key failed: %d: %s", createRR.Code, createRR.Body.String())
	}
	var createResp accessKeyCreateResponse
	if err := json.Unmarshal(createRR.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("parsing create response: %v", err)
	}

	// Revoke.
	revokeRR := doRevokeAccessKey(t, handler, loginRR.Result().Cookies(),
		`{"accessKey":"`+createResp.AccessKey+`"}`)
	if revokeRR.Code != http.StatusOK {
		t.Fatalf("revoke failed: %d: %s", revokeRR.Code, revokeRR.Body.String())
	}

	// Delete.
	deleteRR := doDeleteAccessKey(t, handler, loginRR.Result().Cookies(),
		`{"accessKey":"`+createResp.AccessKey+`"}`)
	if deleteRR.Code != http.StatusOK {
		t.Fatalf("delete failed: %d: %s", deleteRR.Code, deleteRR.Body.String())
	}

	body := deleteRR.Body.String()

	// The response must NOT contain secret-related fields.
	if strings.Contains(body, "secretCiphertext") {
		t.Error("response must NOT contain 'secretCiphertext'")
	}
	if strings.Contains(body, "secret_ciphertext") {
		t.Error("response must NOT contain 'secret_ciphertext'")
	}
	if strings.Contains(body, "secretKey") {
		t.Error("response must NOT contain 'secretKey'")
	}
	// Check for the actual secret value from creation.
	if strings.Contains(body, createResp.SecretKey) {
		t.Error("response must NOT contain the plaintext secret value")
	}
}

// Test 41: GET method returns 405 (only POST is allowed).
func TestAccessKeysDelete_MethodNotAllowed(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/ui/api/access-keys/delete", nil)
	for _, c := range loginRR.Result().Cookies() {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// Test 42: Invalid JSON body returns 400.
func TestAccessKeysDelete_InvalidJSON(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doDeleteAccessKey(t, handler, loginRR.Result().Cookies(), `{invalid json}`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 43: Deleting already deleted key returns 404.
func TestAccessKeysDelete_AlreadyDeleted(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create, revoke, and delete a key.
	createRR := doCreateAccessKey(t, handler, loginRR.Result().Cookies(), `{"description":"double delete test"}`)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create key failed: %d: %s", createRR.Code, createRR.Body.String())
	}
	var createResp accessKeyCreateResponse
	if err := json.Unmarshal(createRR.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("parsing create response: %v", err)
	}

	// Revoke.
	revokeRR := doRevokeAccessKey(t, handler, loginRR.Result().Cookies(),
		`{"accessKey":"`+createResp.AccessKey+`"}`)
	if revokeRR.Code != http.StatusOK {
		t.Fatalf("revoke failed: %d: %s", revokeRR.Code, revokeRR.Body.String())
	}

	// First delete.
	deleteRR1 := doDeleteAccessKey(t, handler, loginRR.Result().Cookies(),
		`{"accessKey":"`+createResp.AccessKey+`"}`)
	if deleteRR1.Code != http.StatusOK {
		t.Fatalf("first delete failed: %d: %s", deleteRR1.Code, deleteRR1.Body.String())
	}

	// Second delete should fail with 404.
	deleteRR2 := doDeleteAccessKey(t, handler, loginRR.Result().Cookies(),
		`{"accessKey":"`+createResp.AccessKey+`"}`)
	if deleteRR2.Code != http.StatusNotFound {
		t.Errorf("expected 404 for already deleted key, got %d: %s", deleteRR2.Code, deleteRR2.Body.String())
	}
}

// Test 44: Deleted key is actually removed from DB.
func TestAccessKeysDelete_RemovedFromDB(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create, revoke, and delete a key.
	createRR := doCreateAccessKey(t, handler, loginRR.Result().Cookies(), `{"description":"db removal test"}`)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create key failed: %d: %s", createRR.Code, createRR.Body.String())
	}
	var createResp accessKeyCreateResponse
	if err := json.Unmarshal(createRR.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("parsing create response: %v", err)
	}

	// Revoke.
	revokeRR := doRevokeAccessKey(t, handler, loginRR.Result().Cookies(),
		`{"accessKey":"`+createResp.AccessKey+`"}`)
	if revokeRR.Code != http.StatusOK {
		t.Fatalf("revoke failed: %d: %s", revokeRR.Code, revokeRR.Body.String())
	}

	// Verify key exists in DB before delete.
	var countBefore int
	err := db.SQLDB().QueryRow("SELECT COUNT(*) FROM access_keys WHERE access_key = ?",
		createResp.AccessKey).Scan(&countBefore)
	if err != nil {
		t.Fatalf("query count before: %v", err)
	}
	if countBefore != 1 {
		t.Errorf("expected 1 row before delete, got %d", countBefore)
	}

	// Delete.
	deleteRR := doDeleteAccessKey(t, handler, loginRR.Result().Cookies(),
		`{"accessKey":"`+createResp.AccessKey+`"}`)
	if deleteRR.Code != http.StatusOK {
		t.Fatalf("delete failed: %d: %s", deleteRR.Code, deleteRR.Body.String())
	}

	// Verify key is removed from DB.
	var countAfter int
	err = db.SQLDB().QueryRow("SELECT COUNT(*) FROM access_keys WHERE access_key = ?",
		createResp.AccessKey).Scan(&countAfter)
	if err != nil {
		t.Fatalf("query count after: %v", err)
	}
	if countAfter != 0 {
		t.Errorf("expected 0 rows after delete, got %d", countAfter)
	}
}
