package ui_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

// doObjectDelete issues DELETE /ui/api/buckets/{bucket}/objects?key=...
// Automatically fetches a fresh CSRF token.
func doObjectDelete(t *testing.T, handler http.Handler, cookies []*http.Cookie, bucketName, key string) *httptest.ResponseRecorder {
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

	url := "/ui/api/buckets/" + bucketName + "/objects?key=" + key
	req := httptest.NewRequest(http.MethodDelete, url, nil)
	req.Header.Set("X-CSRF-Token", token)
	req.AddCookie(csrfCookie)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// doObjectDeleteWithoutCSRF issues DELETE without CSRF token.
func doObjectDeleteWithoutCSRF(t *testing.T, handler http.Handler, cookies []*http.Cookie, bucketName, key string) *httptest.ResponseRecorder {
	t.Helper()
	url := "/ui/api/buckets/" + bucketName + "/objects?key=" + key
	req := httptest.NewRequest(http.MethodDelete, url, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// doObjectDeleteWithoutKey issues DELETE /ui/api/buckets/{bucket}/objects (no key param)
func doObjectDeleteWithoutKey(t *testing.T, handler http.Handler, cookies []*http.Cookie, bucketName string) *httptest.ResponseRecorder {
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

	url := "/ui/api/buckets/" + bucketName + "/objects"
	req := httptest.NewRequest(http.MethodDelete, url, nil)
	req.Header.Set("X-CSRF-Token", token)
	req.AddCookie(csrfCookie)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// doObjectDeleteMismatchCSRF issues DELETE with wrong CSRF token.
func doObjectDeleteMismatchCSRF(t *testing.T, handler http.Handler, cookies []*http.Cookie, bucketName, key string) *httptest.ResponseRecorder {
	t.Helper()
	// Get a CSRF cookie but use a wrong token value.
	csrfRR := doCSRF(t, handler)
	if csrfRR.Code != http.StatusOK {
		t.Fatalf("failed to get CSRF token: %d", csrfRR.Code)
	}
	csrfCookie := findCSRFCookie(csrfRR)
	if csrfCookie == nil {
		t.Fatal("no CSRF cookie in response")
	}

	url := "/ui/api/buckets/" + bucketName + "/objects?key=" + key
	req := httptest.NewRequest(http.MethodDelete, url, nil)
	req.Header.Set("X-CSRF-Token", "wrong-csrf-token-value")
	req.AddCookie(csrfCookie)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// createTestObjectBlob creates a temporary blob file and adds the object to the database.
// Returns the blob path.
func createTestObjectBlob(t *testing.T, db *metadata.DB, bucketName, objectKey string, content []byte) string {
	t.Helper()
	tmpDir := t.TempDir()
	blobPath := filepath.Join(tmpDir, "test-object.blob")
	if err := os.WriteFile(blobPath, content, 0644); err != nil {
		t.Fatalf("failed to create test blob: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	if err := db.UpsertObject(bucketName, objectKey, metadata.PutObjectInput{
		Size:         int64(len(content)),
		ETag:         "testmd5hash123",
		ContentType:  "application/octet-stream",
		StoragePath:  blobPath,
		LastModified: now,
		MetadataJSON: "{}",
	}); err != nil {
		t.Fatalf("UpsertObject: %v", err)
	}
	return blobPath
}

// Test 1: valid session + valid CSRF + existing object → 204 success
func TestObjectDelete_Success(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "delete-test-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d: %s", createRR.Code, createRR.Body.String())
	}

	// Create a test object.
	content := []byte("test content for deletion")
	blobPath := createTestObjectBlob(t, db, "delete-test-bucket", "test-file.txt", content)

	// Verify blob exists before delete.
	if _, err := os.Stat(blobPath); os.IsNotExist(err) {
		t.Fatalf("blob should exist before delete")
	}

	// Delete the object.
	rr := doObjectDelete(t, handler, cookies, "delete-test-bucket", "test-file.txt")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify blob is removed after delete.
	if _, err := os.Stat(blobPath); !os.IsNotExist(err) {
		t.Errorf("blob should be removed after delete")
	}
}

// Test 2: no session → 401
func TestObjectDelete_NoSession(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create bucket and object with session.
	createRR := doCreateBucket(t, handler, cookies, "no-session-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}
	createTestObjectBlob(t, db, "no-session-bucket", "obj.txt", []byte("data"))

	// Get CSRF token (endpoint doesn't require session).
	csrfRR := doCSRF(t, handler)
	if csrfRR.Code != http.StatusOK {
		t.Fatalf("failed to get CSRF token: %d", csrfRR.Code)
	}
	csrfCookie := findCSRFCookie(csrfRR)
	var csrfResp map[string]string
	json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp)
	token := csrfResp["token"]

	// Try delete without session cookies (only CSRF).
	url := "/ui/api/buckets/no-session-bucket/objects?key=obj.txt"
	req := httptest.NewRequest(http.MethodDelete, url, nil)
	req.Header.Set("X-CSRF-Token", token)
	req.AddCookie(csrfCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 3: missing CSRF → 403
func TestObjectDelete_MissingCSRF(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create bucket and object.
	createRR := doCreateBucket(t, handler, cookies, "csrf-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}
	createTestObjectBlob(t, db, "csrf-bucket", "obj.txt", []byte("data"))

	// Try delete without CSRF token.
	rr := doObjectDeleteWithoutCSRF(t, handler, cookies, "csrf-bucket", "obj.txt")
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 4: mismatched CSRF → 403
func TestObjectDelete_MismatchedCSRF(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create bucket and object.
	createRR := doCreateBucket(t, handler, cookies, "mismatch-csrf")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}
	createTestObjectBlob(t, db, "mismatch-csrf", "obj.txt", []byte("data"))

	// Try delete with wrong CSRF token.
	rr := doObjectDeleteMismatchCSRF(t, handler, cookies, "mismatch-csrf", "obj.txt")
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 5: invalid bucket name → 400
func TestObjectDelete_InvalidBucketName(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Invalid bucket name (too short).
	rr := doObjectDelete(t, handler, cookies, "ab", "obj.txt")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if resp["error"] != "invalid bucket name" {
		t.Errorf("expected 'invalid bucket name', got %q", resp["error"])
	}
}

// Test 6: missing bucket → 404
func TestObjectDelete_MissingBucket(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Try to delete from non-existent bucket.
	rr := doObjectDelete(t, handler, cookies, "nonexistent-bucket", "obj.txt")
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if resp["error"] != "bucket not found" {
		t.Errorf("expected 'bucket not found', got %q", resp["error"])
	}
}

// Test 7: missing key query → 400
func TestObjectDelete_MissingKeyQuery(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "key-query-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Try delete without key parameter.
	rr := doObjectDeleteWithoutKey(t, handler, cookies, "key-query-bucket")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if resp["error"] != "key parameter is required" {
		t.Errorf("expected 'key parameter is required', got %q", resp["error"])
	}
}

// Test 8: missing object → 404
func TestObjectDelete_MissingObject(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket but don't add any objects.
	createRR := doCreateBucket(t, handler, cookies, "missing-obj-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Try to delete non-existent object.
	rr := doObjectDelete(t, handler, cookies, "missing-obj-bucket", "nonexistent.txt")
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if resp["error"] != "object not found" {
		t.Errorf("expected 'object not found', got %q", resp["error"])
	}
}

// Test 9: key with slashes works
func TestObjectDelete_KeyWithSlashes(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "slash-key-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Create object with slashes in key.
	objectKey := "path/to/nested/file.txt"
	content := []byte("nested content")
	createTestObjectBlob(t, db, "slash-key-bucket", objectKey, content)

	// Delete the object using URL-encoded key.
	rr := doObjectDelete(t, handler, cookies, "slash-key-bucket", "path/to/nested/file.txt")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify object is gone by trying to list it.
	listRR := doListObjects(t, handler, cookies, "slash-key-bucket", nil)
	if listRR.Code != http.StatusOK {
		t.Fatalf("list failed: %d", listRR.Code)
	}
	var resp listObjectsResponse
	if err := json.Unmarshal(listRR.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if resp.KeyCount != 0 {
		t.Errorf("expected 0 objects after delete, got %d", resp.KeyCount)
	}
}

// Test 10: delete then list → object is gone
func TestObjectDelete_ThenListShowsGone(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "list-verify-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Create two objects.
	createTestObjectBlob(t, db, "list-verify-bucket", "file1.txt", []byte("content1"))
	createTestObjectBlob(t, db, "list-verify-bucket", "file2.txt", []byte("content2"))

	// List objects - should have 2.
	listRR := doListObjects(t, handler, cookies, "list-verify-bucket", nil)
	if listRR.Code != http.StatusOK {
		t.Fatalf("list failed: %d", listRR.Code)
	}
	var listResp listObjectsResponse
	if err := json.Unmarshal(listRR.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if listResp.KeyCount != 2 {
		t.Fatalf("expected 2 objects before delete, got %d", listResp.KeyCount)
	}

	// Delete one object.
	delRR := doObjectDelete(t, handler, cookies, "list-verify-bucket", "file1.txt")
	if delRR.Code != http.StatusNoContent {
		t.Fatalf("delete failed: %d: %s", delRR.Code, delRR.Body.String())
	}

	// List objects again - should have 1.
	listRR2 := doListObjects(t, handler, cookies, "list-verify-bucket", nil)
	if listRR2.Code != http.StatusOK {
		t.Fatalf("list failed: %d", listRR2.Code)
	}
	var listResp2 listObjectsResponse
	if err := json.Unmarshal(listRR2.Body.Bytes(), &listResp2); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if listResp2.KeyCount != 1 {
		t.Errorf("expected 1 object after delete, got %d", listResp2.KeyCount)
	}
	if len(listResp2.Objects) != 1 || listResp2.Objects[0].Key != "file2.txt" {
		t.Errorf("expected file2.txt to remain, got %v", listResp2.Objects)
	}
}

// Test 11: missing blob (corrupt object) → still deleted successfully
// Per operations-runbook.md section 5.1: corrupt objects can be cleaned up via the API.
func TestObjectDelete_CorruptObject_BlobMissing(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "corrupt-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Create metadata row pointing to a non-existent blob.
	now := time.Now().UTC().Truncate(time.Second)
	if err := db.UpsertObject("corrupt-bucket", "corrupt-file.txt", metadata.PutObjectInput{
		Size:         100,
		ETag:         "fakeetag",
		ContentType:  "text/plain",
		StoragePath:  "/nonexistent/path/to/blob",
		LastModified: now,
		MetadataJSON: "{}",
	}); err != nil {
		t.Fatalf("UpsertObject: %v", err)
	}

	// Delete should succeed even though blob doesn't exist.
	rr := doObjectDelete(t, handler, cookies, "corrupt-bucket", "corrupt-file.txt")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify object is removed from DB.
	listRR := doListObjects(t, handler, cookies, "corrupt-bucket", nil)
	if listRR.Code != http.StatusOK {
		t.Fatalf("list failed: %d", listRR.Code)
	}
	var listResp listObjectsResponse
	if err := json.Unmarshal(listRR.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if listResp.KeyCount != 0 {
		t.Errorf("expected 0 objects after delete, got %d", listResp.KeyCount)
	}
}

// Test 12: GET method on objects endpoint still works after adding DELETE
func TestObjectDelete_GETListStillWorks(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "get-list-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Create an object.
	createTestObjectBlob(t, db, "get-list-bucket", "list-test.txt", []byte("data"))

	// GET should work (list objects).
	rr := doListObjects(t, handler, cookies, "get-list-bucket", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp listObjectsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if resp.KeyCount != 1 {
		t.Errorf("expected 1 object, got %d", resp.KeyCount)
	}
}

// Test 13: POST method on objects endpoint → 405
func TestObjectDelete_POSTMethodNotAllowed(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "post-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// POST to objects endpoint should be 405.
	url := "/ui/api/buckets/post-bucket/objects"
	req := httptest.NewRequest(http.MethodPost, url, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d: %s", rr.Code, rr.Body.String())
	}
}

