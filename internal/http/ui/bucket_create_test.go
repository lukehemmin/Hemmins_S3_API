package ui_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// doCreateBucket issues POST /ui/api/buckets with CSRF token.
// Automatically fetches a CSRF token first.
func doCreateBucket(t *testing.T, handler http.Handler, cookies []*http.Cookie, name string) *httptest.ResponseRecorder {
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

	body, _ := json.Marshal(map[string]string{"name": name})
	req := httptest.NewRequest(http.MethodPost, "/ui/api/buckets", bytes.NewReader(body))
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

// doCreateBucketWithoutCSRF issues POST /ui/api/buckets without CSRF token.
func doCreateBucketWithoutCSRF(t *testing.T, handler http.Handler, cookies []*http.Cookie, name string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"name": name})
	req := httptest.NewRequest(http.MethodPost, "/ui/api/buckets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// Test 1: valid session + valid CSRF + valid name → 201 Created
func TestBucketCreate_Success(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doCreateBucket(t, handler, loginRR.Result().Cookies(), "my-new-bucket")
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify response body.
	var resp struct {
		Name         string `json:"name"`
		CreationDate string `json:"creationDate"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if resp.Name != "my-new-bucket" {
		t.Errorf("name: got %q, want %q", resp.Name, "my-new-bucket")
	}
	if resp.CreationDate == "" {
		t.Error("creationDate must not be empty")
	}
	if _, err := time.Parse(time.RFC3339, resp.CreationDate); err != nil {
		t.Errorf("creationDate not valid RFC3339: %q — %v", resp.CreationDate, err)
	}
}

// Test 2: no session → 401
func TestBucketCreate_NoSession(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	// Get CSRF token first (endpoint doesn't require session).
	csrfRR := doCSRF(t, handler)
	if csrfRR.Code != http.StatusOK {
		t.Fatalf("failed to get CSRF token: %d", csrfRR.Code)
	}
	csrfCookie := findCSRFCookie(csrfRR)
	var csrfResp map[string]string
	json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp)
	token := csrfResp["token"]

	body, _ := json.Marshal(map[string]string{"name": "test-bucket"})
	req := httptest.NewRequest(http.MethodPost, "/ui/api/buckets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", token)
	req.AddCookie(csrfCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 3: missing CSRF → 403
func TestBucketCreate_MissingCSRF(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doCreateBucketWithoutCSRF(t, handler, loginRR.Result().Cookies(), "test-bucket")
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 4: invalid bucket name (too short) → 400
func TestBucketCreate_InvalidName_TooShort(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doCreateBucket(t, handler, loginRR.Result().Cookies(), "ab")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "invalid bucket name" {
		t.Errorf("unexpected error message: %q", resp["error"])
	}
}

// Test 5: invalid bucket name (uppercase) → 400
func TestBucketCreate_InvalidName_Uppercase(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doCreateBucket(t, handler, loginRR.Result().Cookies(), "MyBucket")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 6: invalid bucket name (starts with hyphen) → 400
func TestBucketCreate_InvalidName_StartsWithHyphen(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doCreateBucket(t, handler, loginRR.Result().Cookies(), "-test-bucket")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 7: empty bucket name → 400
func TestBucketCreate_EmptyName(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doCreateBucket(t, handler, loginRR.Result().Cookies(), "")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "bucket name is required" {
		t.Errorf("unexpected error message: %q", resp["error"])
	}
}

// Test 8: duplicate bucket → 409
func TestBucketCreate_Duplicate(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// First create.
	rr1 := doCreateBucket(t, handler, loginRR.Result().Cookies(), "dup-bucket")
	if rr1.Code != http.StatusCreated {
		t.Fatalf("first create failed: %d: %s", rr1.Code, rr1.Body.String())
	}

	// Second create with same name.
	rr2 := doCreateBucket(t, handler, loginRR.Result().Cookies(), "dup-bucket")
	if rr2.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d: %s", rr2.Code, rr2.Body.String())
	}

	var resp map[string]string
	json.Unmarshal(rr2.Body.Bytes(), &resp)
	if resp["error"] != "bucket already exists" {
		t.Errorf("unexpected error message: %q", resp["error"])
	}
}

// Test 9: created bucket appears in GET /ui/api/buckets
func TestBucketCreate_AppearsInList(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create bucket.
	createRR := doCreateBucket(t, handler, loginRR.Result().Cookies(), "list-test-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create failed: %d: %s", createRR.Code, createRR.Body.String())
	}

	// List buckets.
	listRR := doBuckets(t, handler, loginRR.Result().Cookies())
	if listRR.Code != http.StatusOK {
		t.Fatalf("list failed: %d: %s", listRR.Code, listRR.Body.String())
	}

	var buckets []struct {
		Name         string `json:"name"`
		CreationDate string `json:"creationDate"`
	}
	if err := json.Unmarshal(listRR.Body.Bytes(), &buckets); err != nil {
		t.Fatalf("parsing list response: %v", err)
	}

	found := false
	for _, b := range buckets {
		if b.Name == "list-test-bucket" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("created bucket not found in list: %v", buckets)
	}
}

// Test 10: invalid JSON body → 400
func TestBucketCreate_InvalidJSON(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Get CSRF token.
	csrfRR := doCSRF(t, handler)
	csrfCookie := findCSRFCookie(csrfRR)
	var csrfResp map[string]string
	json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp)
	token := csrfResp["token"]

	req := httptest.NewRequest(http.MethodPost, "/ui/api/buckets", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", token)
	req.AddCookie(csrfCookie)
	for _, c := range loginRR.Result().Cookies() {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "invalid JSON body" {
		t.Errorf("unexpected error message: %q", resp["error"])
	}
}

// Test 11: valid bucket names (edge cases)
func TestBucketCreate_ValidNames(t *testing.T) {
	testCases := []string{
		"abc",                          // minimum length
		"bucket-with-hyphen",           // hyphen in middle
		"bucket.with.dots",             // dots in middle
		"bucket123",                    // numbers
		"123bucket",                    // starts with number
		"a-b-c-d-e-f-g-h-i-j-k-l-m-n", // many hyphens
	}

	for _, name := range testCases {
		t.Run(name, func(t *testing.T) {
			handler, _ := setupTestUIServer(t, false)
			loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
			if loginRR.Code != http.StatusOK {
				t.Fatalf("login failed: %d", loginRR.Code)
			}

			rr := doCreateBucket(t, handler, loginRR.Result().Cookies(), name)
			if rr.Code != http.StatusCreated {
				t.Errorf("expected 201, got %d: %s", rr.Code, rr.Body.String())
			}
		})
	}
}

// Test 12: invalid bucket names (edge cases)
func TestBucketCreate_InvalidNames(t *testing.T) {
	testCases := []struct {
		name string
		desc string
	}{
		{"ab", "too short"},
		{"bucket_underscore", "underscore"},
		{"UPPER", "uppercase"},
		{"-starts-hyphen", "starts with hyphen"},
		{"ends-hyphen-", "ends with hyphen"},
		{".starts-dot", "starts with dot"},
		{"ends-dot.", "ends with dot"},
		{"double..dots", "double dots"},
		{"192.168.1.1", "IP address format"},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			handler, _ := setupTestUIServer(t, false)
			loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
			if loginRR.Code != http.StatusOK {
				t.Fatalf("login failed: %d", loginRR.Code)
			}

			rr := doCreateBucket(t, handler, loginRR.Result().Cookies(), tc.name)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("expected 400 for %q (%s), got %d: %s", tc.name, tc.desc, rr.Code, rr.Body.String())
			}
		})
	}
}

// Test 13: method not allowed (PUT, DELETE on /ui/api/buckets)
func TestBucketCreate_MethodNotAllowed(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/ui/api/buckets", nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("expected 405 for %s, got %d", method, rr.Code)
			}
		})
	}
}

// Test 14: existing GET /ui/api/buckets still works after adding POST
func TestBuckets_GetStillWorks(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// GET should still return 200.
	rr := doBuckets(t, handler, loginRR.Result().Cookies())
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}
