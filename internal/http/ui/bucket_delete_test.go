package ui_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

// doDeleteBucket issues DELETE /ui/api/buckets/{name} with CSRF token.
// Automatically fetches a CSRF token first.
func doDeleteBucket(t *testing.T, handler http.Handler, cookies []*http.Cookie, name string) *httptest.ResponseRecorder {
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

	req := httptest.NewRequest(http.MethodDelete, "/ui/api/buckets/"+name, nil)
	req.Header.Set("X-CSRF-Token", token)
	req.AddCookie(csrfCookie)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// doDeleteBucketWithoutCSRF issues DELETE /ui/api/buckets/{name} without CSRF token.
func doDeleteBucketWithoutCSRF(t *testing.T, handler http.Handler, cookies []*http.Cookie, name string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, "/ui/api/buckets/"+name, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// Test 1: valid session + valid CSRF + empty bucket → 204 No Content
func TestBucketDelete_Success(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// First create a bucket.
	createRR := doCreateBucket(t, handler, loginRR.Result().Cookies(), "delete-test-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create failed: %d: %s", createRR.Code, createRR.Body.String())
	}

	// Delete the bucket.
	deleteRR := doDeleteBucket(t, handler, loginRR.Result().Cookies(), "delete-test-bucket")
	if deleteRR.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", deleteRR.Code, deleteRR.Body.String())
	}
}

// Test 2: no session → 401
func TestBucketDelete_NoSession(t *testing.T) {
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

	req := httptest.NewRequest(http.MethodDelete, "/ui/api/buckets/test-bucket", nil)
	req.Header.Set("X-CSRF-Token", token)
	req.AddCookie(csrfCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 3: missing CSRF → 403
func TestBucketDelete_MissingCSRF(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doDeleteBucketWithoutCSRF(t, handler, loginRR.Result().Cookies(), "test-bucket")
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 4: invalid bucket name → 400
func TestBucketDelete_InvalidName(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Invalid bucket names.
	invalidNames := []string{
		"ab",           // too short
		"UPPER",        // uppercase
		"-starts-with", // starts with hyphen
	}

	for _, name := range invalidNames {
		t.Run(name, func(t *testing.T) {
			rr := doDeleteBucket(t, handler, loginRR.Result().Cookies(), name)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("expected 400 for %q, got %d: %s", name, rr.Code, rr.Body.String())
			}
		})
	}
}

// Test 5: nonexistent bucket → 404
func TestBucketDelete_NotFound(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doDeleteBucket(t, handler, loginRR.Result().Cookies(), "nonexistent-bucket")
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "bucket not found" {
		t.Errorf("unexpected error message: %q", resp["error"])
	}
}

// Test 6: non-empty bucket → 409
func TestBucketDelete_NotEmpty(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create a bucket.
	createRR := doCreateBucket(t, handler, loginRR.Result().Cookies(), "nonempty-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create failed: %d: %s", createRR.Code, createRR.Body.String())
	}

	// Add an object to the bucket (directly via DB).
	err := db.UpsertObject("nonempty-bucket", "test-key", metadata.PutObjectInput{
		Size:         100,
		ETag:         "etag123",
		ContentType:  "text/plain",
		StoragePath:  "/fake/path",
		LastModified: time.Now().UTC(),
		MetadataJSON: "{}",
	})
	if err != nil {
		t.Fatalf("failed to create object: %v", err)
	}

	// Try to delete the bucket.
	rr := doDeleteBucket(t, handler, loginRR.Result().Cookies(), "nonempty-bucket")
	if rr.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "bucket not empty" {
		t.Errorf("unexpected error message: %q", resp["error"])
	}
}

// Test 7: deleted bucket disappears from GET /ui/api/buckets
func TestBucketDelete_DisappearsFromList(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create a bucket.
	createRR := doCreateBucket(t, handler, loginRR.Result().Cookies(), "list-delete-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create failed: %d: %s", createRR.Code, createRR.Body.String())
	}

	// Verify it appears in the list.
	listRR1 := doBuckets(t, handler, loginRR.Result().Cookies())
	if listRR1.Code != http.StatusOK {
		t.Fatalf("list failed: %d", listRR1.Code)
	}
	var buckets1 []map[string]string
	json.Unmarshal(listRR1.Body.Bytes(), &buckets1)
	found1 := false
	for _, b := range buckets1 {
		if b["name"] == "list-delete-bucket" {
			found1 = true
			break
		}
	}
	if !found1 {
		t.Error("bucket should appear in list before deletion")
	}

	// Delete the bucket.
	deleteRR := doDeleteBucket(t, handler, loginRR.Result().Cookies(), "list-delete-bucket")
	if deleteRR.Code != http.StatusNoContent {
		t.Fatalf("delete failed: %d: %s", deleteRR.Code, deleteRR.Body.String())
	}

	// Verify it no longer appears in the list.
	listRR2 := doBuckets(t, handler, loginRR.Result().Cookies())
	if listRR2.Code != http.StatusOK {
		t.Fatalf("list failed: %d", listRR2.Code)
	}
	var buckets2 []map[string]string
	json.Unmarshal(listRR2.Body.Bytes(), &buckets2)
	found2 := false
	for _, b := range buckets2 {
		if b["name"] == "list-delete-bucket" {
			found2 = true
			break
		}
	}
	if found2 {
		t.Error("bucket should not appear in list after deletion")
	}
}

// Test 8: empty bucket name in path → 400
func TestBucketDelete_EmptyName(t *testing.T) {
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

	req := httptest.NewRequest(http.MethodDelete, "/ui/api/buckets/", nil)
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
	if resp["error"] != "bucket name is required" {
		t.Errorf("unexpected error message: %q", resp["error"])
	}
}

// Test 9: method not allowed (GET, POST, PUT on /ui/api/buckets/{name})
func TestBucketDelete_MethodNotAllowed(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/ui/api/buckets/some-bucket", nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("expected 405 for %s, got %d", method, rr.Code)
			}
		})
	}
}

// Test 10: delete twice → second delete returns 404
func TestBucketDelete_DeleteTwice(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create a bucket.
	createRR := doCreateBucket(t, handler, loginRR.Result().Cookies(), "twice-delete-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create failed: %d: %s", createRR.Code, createRR.Body.String())
	}

	// First delete should succeed.
	rr1 := doDeleteBucket(t, handler, loginRR.Result().Cookies(), "twice-delete-bucket")
	if rr1.Code != http.StatusNoContent {
		t.Fatalf("first delete failed: %d: %s", rr1.Code, rr1.Body.String())
	}

	// Second delete should return 404.
	rr2 := doDeleteBucket(t, handler, loginRR.Result().Cookies(), "twice-delete-bucket")
	if rr2.Code != http.StatusNotFound {
		t.Errorf("expected 404 on second delete, got %d: %s", rr2.Code, rr2.Body.String())
	}
}

// Test 11: existing GET /ui/api/buckets still works
func TestBucketDelete_GetStillWorks(t *testing.T) {
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

// Test 12: existing POST /ui/api/buckets (create) still works
func TestBucketDelete_PostStillWorks(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// POST should still create buckets.
	rr := doCreateBucket(t, handler, loginRR.Result().Cookies(), "post-still-works")
	if rr.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}
}
