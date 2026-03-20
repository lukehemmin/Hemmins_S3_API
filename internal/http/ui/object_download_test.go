package ui_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

// doObjectDownload issues GET /ui/api/buckets/{bucket}/objects/download?key=...
func doObjectDownload(t *testing.T, handler http.Handler, cookies []*http.Cookie, bucketName, key string) *httptest.ResponseRecorder {
	t.Helper()
	url := "/ui/api/buckets/" + bucketName + "/objects/download?key=" + key
	req := httptest.NewRequest(http.MethodGet, url, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// doObjectDownloadWithoutKey issues GET /ui/api/buckets/{bucket}/objects/download (no key param)
func doObjectDownloadWithoutKey(t *testing.T, handler http.Handler, cookies []*http.Cookie, bucketName string) *httptest.ResponseRecorder {
	t.Helper()
	url := "/ui/api/buckets/" + bucketName + "/objects/download"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// doObjectDownloadPOST issues POST /ui/api/buckets/{bucket}/objects/download?key=...
func doObjectDownloadPOST(t *testing.T, handler http.Handler, cookies []*http.Cookie, bucketName, key string) *httptest.ResponseRecorder {
	t.Helper()
	url := "/ui/api/buckets/" + bucketName + "/objects/download?key=" + key
	req := httptest.NewRequest(http.MethodPost, url, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// createTestBlob creates a temporary blob file and returns its path.
func createTestBlob(t *testing.T, content []byte) string {
	t.Helper()
	tmpDir := t.TempDir()
	blobPath := filepath.Join(tmpDir, "test-object.blob")
	if err := os.WriteFile(blobPath, content, 0644); err != nil {
		t.Fatalf("failed to create test blob: %v", err)
	}
	return blobPath
}

// Test 1: valid session + existing object → 200 and body matches
func TestObjectDownload_Success(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create a bucket.
	createRR := doCreateBucket(t, handler, loginRR.Result().Cookies(), "download-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d: %s", createRR.Code, createRR.Body.String())
	}

	// Create a test blob file.
	content := []byte("Hello, World! This is test content.")
	blobPath := createTestBlob(t, content)

	// Add object to DB.
	now := time.Now().UTC().Truncate(time.Second)
	if err := db.UpsertObject("download-bucket", "test-file.txt", metadata.PutObjectInput{
		Size:         int64(len(content)),
		ETag:         "abc123def456",
		ContentType:  "text/plain",
		StoragePath:  blobPath,
		LastModified: now,
		MetadataJSON: "{}",
	}); err != nil {
		t.Fatalf("UpsertObject: %v", err)
	}

	// Download the object.
	rr := doObjectDownload(t, handler, loginRR.Result().Cookies(), "download-bucket", "test-file.txt")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify body content.
	if rr.Body.String() != string(content) {
		t.Errorf("body: got %q, want %q", rr.Body.String(), string(content))
	}
}

// Test 2: no session → 401
func TestObjectDownload_NoSession(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create a bucket (need valid session for this).
	createRR := doCreateBucket(t, handler, loginRR.Result().Cookies(), "no-session-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Add object to DB.
	blobPath := createTestBlob(t, []byte("test"))
	if err := db.UpsertObject("no-session-bucket", "file.txt", metadata.PutObjectInput{
		Size:         4,
		ETag:         "123",
		ContentType:  "text/plain",
		StoragePath:  blobPath,
		LastModified: time.Now().UTC(),
		MetadataJSON: "{}",
	}); err != nil {
		t.Fatalf("UpsertObject: %v", err)
	}

	// Try to download without session cookies.
	rr := doObjectDownload(t, handler, nil, "no-session-bucket", "file.txt")
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if resp["error"] == "" {
		t.Error("expected error message in response")
	}
}

// Test 3: invalid bucket name → 400
func TestObjectDownload_InvalidBucketName(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Try with invalid bucket name (uppercase).
	rr := doObjectDownload(t, handler, loginRR.Result().Cookies(), "INVALID", "file.txt")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if resp["error"] != "invalid bucket name" {
		t.Errorf("error: got %q, want %q", resp["error"], "invalid bucket name")
	}
}

// Test 4: missing bucket → 404
func TestObjectDownload_BucketNotFound(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Try to download from non-existent bucket.
	rr := doObjectDownload(t, handler, loginRR.Result().Cookies(), "nonexistent", "file.txt")
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if resp["error"] != "bucket not found" {
		t.Errorf("error: got %q, want %q", resp["error"], "bucket not found")
	}
}

// Test 5: missing key query parameter → 400
func TestObjectDownload_MissingKeyParam(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create a bucket.
	createRR := doCreateBucket(t, handler, loginRR.Result().Cookies(), "missing-key-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Try to download without key parameter.
	rr := doObjectDownloadWithoutKey(t, handler, loginRR.Result().Cookies(), "missing-key-bucket")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if resp["error"] != "key parameter is required" {
		t.Errorf("error: got %q, want %q", resp["error"], "key parameter is required")
	}
}

// Test 6: missing object → 404
func TestObjectDownload_ObjectNotFound(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create a bucket.
	createRR := doCreateBucket(t, handler, loginRR.Result().Cookies(), "object-not-found-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Try to download non-existent object.
	rr := doObjectDownload(t, handler, loginRR.Result().Cookies(), "object-not-found-bucket", "nonexistent.txt")
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if resp["error"] != "object not found" {
		t.Errorf("error: got %q, want %q", resp["error"], "object not found")
	}
}

// Test 7: key with slashes works
func TestObjectDownload_KeyWithSlashes(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create a bucket.
	createRR := doCreateBucket(t, handler, loginRR.Result().Cookies(), "slash-key-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Create a test blob file.
	content := []byte("Content in nested folder.")
	blobPath := createTestBlob(t, content)

	// Add object with slashes in key.
	objectKey := "folder/subfolder/deep/file.txt"
	if err := db.UpsertObject("slash-key-bucket", objectKey, metadata.PutObjectInput{
		Size:         int64(len(content)),
		ETag:         "slashkey123",
		ContentType:  "text/plain",
		StoragePath:  blobPath,
		LastModified: time.Now().UTC(),
		MetadataJSON: "{}",
	}); err != nil {
		t.Fatalf("UpsertObject: %v", err)
	}

	// Download with slashes in key (URL-encoded via query param).
	rr := doObjectDownload(t, handler, loginRR.Result().Cookies(), "slash-key-bucket", objectKey)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	if rr.Body.String() != string(content) {
		t.Errorf("body: got %q, want %q", rr.Body.String(), string(content))
	}
}

// Test 8: zero-byte object download works
func TestObjectDownload_ZeroByte(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create a bucket.
	createRR := doCreateBucket(t, handler, loginRR.Result().Cookies(), "zero-byte-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Create an empty blob file.
	blobPath := createTestBlob(t, []byte{})

	// Add zero-byte object.
	if err := db.UpsertObject("zero-byte-bucket", "empty.txt", metadata.PutObjectInput{
		Size:         0,
		ETag:         "d41d8cd98f00b204e9800998ecf8427e", // MD5 of empty string
		ContentType:  "application/octet-stream",
		StoragePath:  blobPath,
		LastModified: time.Now().UTC(),
		MetadataJSON: "{}",
	}); err != nil {
		t.Fatalf("UpsertObject: %v", err)
	}

	// Download the zero-byte object.
	rr := doObjectDownload(t, handler, loginRR.Result().Cookies(), "zero-byte-bucket", "empty.txt")
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	if rr.Body.Len() != 0 {
		t.Errorf("body length: got %d, want 0", rr.Body.Len())
	}

	// Verify Content-Length header.
	if cl := rr.Header().Get("Content-Length"); cl != "0" {
		t.Errorf("Content-Length: got %q, want %q", cl, "0")
	}
}

// Test 9: Content-Type restored
func TestObjectDownload_ContentType(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create a bucket.
	createRR := doCreateBucket(t, handler, loginRR.Result().Cookies(), "content-type-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Create a test blob file.
	content := []byte(`{"key":"value"}`)
	blobPath := createTestBlob(t, content)

	// Add object with specific content type.
	if err := db.UpsertObject("content-type-bucket", "data.json", metadata.PutObjectInput{
		Size:         int64(len(content)),
		ETag:         "jsonetag123",
		ContentType:  "application/json",
		StoragePath:  blobPath,
		LastModified: time.Now().UTC(),
		MetadataJSON: "{}",
	}); err != nil {
		t.Fatalf("UpsertObject: %v", err)
	}

	// Download the object.
	rr := doObjectDownload(t, handler, loginRR.Result().Cookies(), "content-type-bucket", "data.json")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify Content-Type header.
	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type: got %q, want %q", ct, "application/json")
	}
}

// Test 10: ETag restored (quoted)
func TestObjectDownload_ETag(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create a bucket.
	createRR := doCreateBucket(t, handler, loginRR.Result().Cookies(), "etag-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Create a test blob file.
	content := []byte("test content for etag")
	blobPath := createTestBlob(t, content)

	// Add object with specific ETag.
	rawETag := "abcdef1234567890"
	if err := db.UpsertObject("etag-bucket", "etag-file.txt", metadata.PutObjectInput{
		Size:         int64(len(content)),
		ETag:         rawETag,
		ContentType:  "text/plain",
		StoragePath:  blobPath,
		LastModified: time.Now().UTC(),
		MetadataJSON: "{}",
	}); err != nil {
		t.Fatalf("UpsertObject: %v", err)
	}

	// Download the object.
	rr := doObjectDownload(t, handler, loginRR.Result().Cookies(), "etag-bucket", "etag-file.txt")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify ETag header (should be quoted).
	etag := rr.Header().Get("ETag")
	expectedETag := `"` + rawETag + `"`
	if etag != expectedETag {
		t.Errorf("ETag: got %q, want %q", etag, expectedETag)
	}
}

// Test 11: Last-Modified present
func TestObjectDownload_LastModified(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create a bucket.
	createRR := doCreateBucket(t, handler, loginRR.Result().Cookies(), "lastmod-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Create a test blob file.
	content := []byte("test content")
	blobPath := createTestBlob(t, content)

	// Add object with specific last modified time.
	lastMod := time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC)
	if err := db.UpsertObject("lastmod-bucket", "lastmod-file.txt", metadata.PutObjectInput{
		Size:         int64(len(content)),
		ETag:         "lastmodetag",
		ContentType:  "text/plain",
		StoragePath:  blobPath,
		LastModified: lastMod,
		MetadataJSON: "{}",
	}); err != nil {
		t.Fatalf("UpsertObject: %v", err)
	}

	// Download the object.
	rr := doObjectDownload(t, handler, loginRR.Result().Cookies(), "lastmod-bucket", "lastmod-file.txt")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify Last-Modified header is present and valid.
	lm := rr.Header().Get("Last-Modified")
	if lm == "" {
		t.Error("Last-Modified header is missing")
	}

	// Parse and verify the time format (HTTP date format).
	parsedTime, err := time.Parse(http.TimeFormat, lm)
	if err != nil {
		t.Errorf("Last-Modified header is not valid HTTP date format: %q — %v", lm, err)
	}

	// Verify it matches the expected time.
	if !parsedTime.Equal(lastMod) {
		t.Errorf("Last-Modified: got %v, want %v", parsedTime, lastMod)
	}
}

// Test 12: x-amz-meta-* headers restored
func TestObjectDownload_UserMetadata(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create a bucket.
	createRR := doCreateBucket(t, handler, loginRR.Result().Cookies(), "usermeta-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Create a test blob file.
	content := []byte("file with user metadata")
	blobPath := createTestBlob(t, content)

	// Add object with user metadata.
	metaJSON := `{"author":"test-user","version":"1.0"}`
	if err := db.UpsertObject("usermeta-bucket", "meta-file.txt", metadata.PutObjectInput{
		Size:         int64(len(content)),
		ETag:         "metaetag123",
		ContentType:  "text/plain",
		StoragePath:  blobPath,
		LastModified: time.Now().UTC(),
		MetadataJSON: metaJSON,
	}); err != nil {
		t.Fatalf("UpsertObject: %v", err)
	}

	// Download the object.
	rr := doObjectDownload(t, handler, loginRR.Result().Cookies(), "usermeta-bucket", "meta-file.txt")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify x-amz-meta-* headers.
	author := rr.Header().Get("X-Amz-Meta-author")
	if author != "test-user" {
		t.Errorf("X-Amz-Meta-author: got %q, want %q", author, "test-user")
	}

	version := rr.Header().Get("X-Amz-Meta-version")
	if version != "1.0" {
		t.Errorf("X-Amz-Meta-version: got %q, want %q", version, "1.0")
	}
}

// Test 13: Content-Length restored
func TestObjectDownload_ContentLength(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create a bucket.
	createRR := doCreateBucket(t, handler, loginRR.Result().Cookies(), "content-len-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Create a test blob file.
	content := []byte("content with known size")
	blobPath := createTestBlob(t, content)

	// Add object.
	if err := db.UpsertObject("content-len-bucket", "sized-file.txt", metadata.PutObjectInput{
		Size:         int64(len(content)),
		ETag:         "sizeetag",
		ContentType:  "text/plain",
		StoragePath:  blobPath,
		LastModified: time.Now().UTC(),
		MetadataJSON: "{}",
	}); err != nil {
		t.Fatalf("UpsertObject: %v", err)
	}

	// Download the object.
	rr := doObjectDownload(t, handler, loginRR.Result().Cookies(), "content-len-bucket", "sized-file.txt")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify Content-Length header.
	cl := rr.Header().Get("Content-Length")
	expectedLen := "23"
	if cl != expectedLen {
		t.Errorf("Content-Length: got %q, want %q", cl, expectedLen)
	}
}

// Test 14: method not allowed (POST)
func TestObjectDownload_MethodNotAllowed(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create a bucket.
	createRR := doCreateBucket(t, handler, loginRR.Result().Cookies(), "method-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Try POST method.
	rr := doObjectDownloadPOST(t, handler, loginRR.Result().Cookies(), "method-bucket", "file.txt")
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 15: missing blob file (internal error)
func TestObjectDownload_MissingBlob(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create a bucket.
	createRR := doCreateBucket(t, handler, loginRR.Result().Cookies(), "missing-blob-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Add object with non-existent storage path.
	if err := db.UpsertObject("missing-blob-bucket", "ghost.txt", metadata.PutObjectInput{
		Size:         100,
		ETag:         "ghostetag",
		ContentType:  "text/plain",
		StoragePath:  "/non/existent/path/ghost.blob",
		LastModified: time.Now().UTC(),
		MetadataJSON: "{}",
	}); err != nil {
		t.Fatalf("UpsertObject: %v", err)
	}

	// Try to download — should return 500 (internal error, not 404).
	rr := doObjectDownload(t, handler, loginRR.Result().Cookies(), "missing-blob-bucket", "ghost.txt")
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify error message doesn't expose the raw path.
	bodyStr := rr.Body.String()
	if strings.Contains(bodyStr, "/non/existent/path") {
		t.Error("response body should not contain raw filesystem path")
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if resp["error"] != "internal error" {
		t.Errorf("error: got %q, want %q", resp["error"], "internal error")
	}
}

// Test 16: existing list/create/delete routes still work
func TestObjectDownload_ExistingRoutesStillWork(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Test bucket create still works.
	createRR := doCreateBucket(t, handler, loginRR.Result().Cookies(), "existing-routes-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d: %s", createRR.Code, createRR.Body.String())
	}

	// Test bucket list still works.
	listRR := doListObjects(t, handler, loginRR.Result().Cookies(), "existing-routes-bucket", nil)
	if listRR.Code != http.StatusOK {
		t.Errorf("list objects failed: %d: %s", listRR.Code, listRR.Body.String())
	}

	// Test bucket delete still works.
	deleteRR := doDeleteBucket(t, handler, loginRR.Result().Cookies(), "existing-routes-bucket")
	if deleteRR.Code != http.StatusNoContent {
		t.Errorf("delete bucket failed: %d: %s", deleteRR.Code, deleteRR.Body.String())
	}
}
