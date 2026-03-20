package ui_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// doObjectUpload issues POST /ui/api/buckets/{bucket}/objects/upload?key=...
// Automatically fetches a fresh CSRF token.
func doObjectUpload(t *testing.T, handler http.Handler, cookies []*http.Cookie, bucketName, key string, body []byte, contentType string) *httptest.ResponseRecorder {
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

	url := "/ui/api/buckets/" + bucketName + "/objects/upload?key=" + key
	req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("X-CSRF-Token", token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.AddCookie(csrfCookie)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// doObjectUploadWithoutCSRF issues POST without CSRF token.
func doObjectUploadWithoutCSRF(t *testing.T, handler http.Handler, cookies []*http.Cookie, bucketName, key string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	url := "/ui/api/buckets/" + bucketName + "/objects/upload?key=" + key
	req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// doObjectUploadWithoutKey issues POST /ui/api/buckets/{bucket}/objects/upload (no key param)
func doObjectUploadWithoutKey(t *testing.T, handler http.Handler, cookies []*http.Cookie, bucketName string, body []byte) *httptest.ResponseRecorder {
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

	url := "/ui/api/buckets/" + bucketName + "/objects/upload"
	req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("X-CSRF-Token", token)
	req.AddCookie(csrfCookie)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// doObjectUploadMismatchCSRF issues POST with wrong CSRF token.
func doObjectUploadMismatchCSRF(t *testing.T, handler http.Handler, cookies []*http.Cookie, bucketName, key string, body []byte) *httptest.ResponseRecorder {
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

	url := "/ui/api/buckets/" + bucketName + "/objects/upload?key=" + key
	req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("X-CSRF-Token", "wrong-csrf-token-value")
	req.AddCookie(csrfCookie)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// doObjectUploadWithMeta issues POST with custom x-amz-meta-* headers.
func doObjectUploadWithMeta(t *testing.T, handler http.Handler, cookies []*http.Cookie, bucketName, key string, body []byte, contentType string, meta map[string]string) *httptest.ResponseRecorder {
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

	url := "/ui/api/buckets/" + bucketName + "/objects/upload?key=" + key
	req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("X-CSRF-Token", token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range meta {
		req.Header.Set("X-Amz-Meta-"+k, v)
	}
	req.AddCookie(csrfCookie)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

type uploadResponse struct {
	Bucket       string `json:"bucket"`
	Key          string `json:"key"`
	Size         int64  `json:"size"`
	ETag         string `json:"etag"`
	ContentType  string `json:"contentType"`
	LastModified string `json:"lastModified"`
}

// Test 1: valid session + valid CSRF + raw body + key → success
func TestObjectUpload_Success(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "upload-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d: %s", createRR.Code, createRR.Body.String())
	}

	// Upload an object.
	content := []byte("Hello, World! This is test content for upload.")
	rr := doObjectUpload(t, handler, cookies, "upload-bucket", "test-upload.txt", content, "text/plain")
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp uploadResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	// Verify response fields.
	if resp.Bucket != "upload-bucket" {
		t.Errorf("expected bucket 'upload-bucket', got %q", resp.Bucket)
	}
	if resp.Key != "test-upload.txt" {
		t.Errorf("expected key 'test-upload.txt', got %q", resp.Key)
	}
	if resp.Size != int64(len(content)) {
		t.Errorf("expected size %d, got %d", len(content), resp.Size)
	}
	if resp.ContentType != "text/plain" {
		t.Errorf("expected content type 'text/plain', got %q", resp.ContentType)
	}
	// ETag should be quoted.
	if !strings.HasPrefix(resp.ETag, `"`) || !strings.HasSuffix(resp.ETag, `"`) {
		t.Errorf("ETag should be quoted, got %q", resp.ETag)
	}
	if resp.LastModified == "" {
		t.Error("lastModified should not be empty")
	}
}

// Test 2: no session → 401
func TestObjectUpload_NoSession(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create bucket with session.
	createRR := doCreateBucket(t, handler, cookies, "no-session-upload")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Get CSRF token (endpoint doesn't require session).
	csrfRR := doCSRF(t, handler)
	if csrfRR.Code != http.StatusOK {
		t.Fatalf("failed to get CSRF token: %d", csrfRR.Code)
	}
	csrfCookie := findCSRFCookie(csrfRR)
	var csrfResp map[string]string
	json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp)
	token := csrfResp["token"]

	// Try upload without session cookies (only CSRF).
	url := "/ui/api/buckets/no-session-upload/objects/upload?key=test.txt"
	req := httptest.NewRequest(http.MethodPost, url, strings.NewReader("data"))
	req.Header.Set("X-CSRF-Token", token)
	req.AddCookie(csrfCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 3: missing CSRF → 403
func TestObjectUpload_MissingCSRF(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create bucket.
	createRR := doCreateBucket(t, handler, cookies, "csrf-upload-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Try upload without CSRF token.
	rr := doObjectUploadWithoutCSRF(t, handler, cookies, "csrf-upload-bucket", "test.txt", []byte("data"))
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 4: mismatched CSRF → 403
func TestObjectUpload_MismatchedCSRF(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create bucket.
	createRR := doCreateBucket(t, handler, cookies, "mismatch-csrf-upload")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Try upload with wrong CSRF token.
	rr := doObjectUploadMismatchCSRF(t, handler, cookies, "mismatch-csrf-upload", "test.txt", []byte("data"))
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 5: invalid bucket name → 400
func TestObjectUpload_InvalidBucketName(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Invalid bucket name (too short).
	rr := doObjectUpload(t, handler, cookies, "ab", "test.txt", []byte("data"), "")
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
func TestObjectUpload_MissingBucket(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Try to upload to non-existent bucket.
	rr := doObjectUpload(t, handler, cookies, "nonexistent-bucket", "test.txt", []byte("data"), "")
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
func TestObjectUpload_MissingKeyQuery(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "key-query-upload")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Try upload without key parameter.
	rr := doObjectUploadWithoutKey(t, handler, cookies, "key-query-upload", []byte("data"))
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

// Test 8: zero-byte object upload works
func TestObjectUpload_ZeroByteObject(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "zero-byte-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Upload zero-byte object.
	rr := doObjectUpload(t, handler, cookies, "zero-byte-bucket", "empty.txt", []byte{}, "text/plain")
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp uploadResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if resp.Size != 0 {
		t.Errorf("expected size 0, got %d", resp.Size)
	}
}

// Test 9: Content-Type stored and later reflected
func TestObjectUpload_ContentTypeStored(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "content-type-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Upload with specific content type.
	content := []byte("<html><body>test</body></html>")
	rr := doObjectUpload(t, handler, cookies, "content-type-bucket", "page.html", content, "text/html; charset=utf-8")
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var uploadResp uploadResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &uploadResp); err != nil {
		t.Fatalf("parsing upload response: %v", err)
	}
	if uploadResp.ContentType != "text/html; charset=utf-8" {
		t.Errorf("expected content type 'text/html; charset=utf-8', got %q", uploadResp.ContentType)
	}

	// Verify via object list.
	listRR := doListObjects(t, handler, cookies, "content-type-bucket", nil)
	if listRR.Code != http.StatusOK {
		t.Fatalf("list failed: %d", listRR.Code)
	}
	var listResp listObjectsResponse
	if err := json.Unmarshal(listRR.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("parsing list response: %v", err)
	}
	if len(listResp.Objects) != 1 {
		t.Fatalf("expected 1 object, got %d", len(listResp.Objects))
	}
	if listResp.Objects[0].ContentType != "text/html; charset=utf-8" {
		t.Errorf("list content type: expected 'text/html; charset=utf-8', got %q", listResp.Objects[0].ContentType)
	}
}

// Test 10: default Content-Type is application/octet-stream
func TestObjectUpload_DefaultContentType(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "default-ct-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Upload without content type header.
	rr := doObjectUpload(t, handler, cookies, "default-ct-bucket", "binary.bin", []byte{0x00, 0x01, 0x02}, "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp uploadResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if resp.ContentType != "application/octet-stream" {
		t.Errorf("expected default content type 'application/octet-stream', got %q", resp.ContentType)
	}
}

// Test 11: overwrite existing object works
func TestObjectUpload_Overwrite(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "overwrite-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Upload first version.
	content1 := []byte("version 1")
	rr1 := doObjectUpload(t, handler, cookies, "overwrite-bucket", "file.txt", content1, "text/plain")
	if rr1.Code != http.StatusCreated {
		t.Fatalf("first upload failed: %d: %s", rr1.Code, rr1.Body.String())
	}
	var resp1 uploadResponse
	json.Unmarshal(rr1.Body.Bytes(), &resp1)

	// Upload second version (overwrite).
	content2 := []byte("version 2 - longer content")
	rr2 := doObjectUpload(t, handler, cookies, "overwrite-bucket", "file.txt", content2, "text/plain")
	if rr2.Code != http.StatusCreated {
		t.Fatalf("second upload failed: %d: %s", rr2.Code, rr2.Body.String())
	}
	var resp2 uploadResponse
	json.Unmarshal(rr2.Body.Bytes(), &resp2)

	// Verify the size changed.
	if resp2.Size != int64(len(content2)) {
		t.Errorf("expected size %d after overwrite, got %d", len(content2), resp2.Size)
	}
	if resp1.ETag == resp2.ETag {
		t.Error("ETag should have changed after overwrite")
	}

	// Verify only one object in list.
	listRR := doListObjects(t, handler, cookies, "overwrite-bucket", nil)
	var listResp listObjectsResponse
	json.Unmarshal(listRR.Body.Bytes(), &listResp)
	if listResp.KeyCount != 1 {
		t.Errorf("expected 1 object after overwrite, got %d", listResp.KeyCount)
	}
}

// Test 12: object appears in GET /ui/api/buckets/{name}/objects
func TestObjectUpload_AppearsInList(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "list-verify-upload")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Upload an object.
	content := []byte("test content")
	rr := doObjectUpload(t, handler, cookies, "list-verify-upload", "new-object.txt", content, "text/plain")
	if rr.Code != http.StatusCreated {
		t.Fatalf("upload failed: %d: %s", rr.Code, rr.Body.String())
	}

	// Verify it appears in list.
	listRR := doListObjects(t, handler, cookies, "list-verify-upload", nil)
	if listRR.Code != http.StatusOK {
		t.Fatalf("list failed: %d", listRR.Code)
	}
	var listResp listObjectsResponse
	if err := json.Unmarshal(listRR.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("parsing list response: %v", err)
	}
	if listResp.KeyCount != 1 {
		t.Fatalf("expected 1 object in list, got %d", listResp.KeyCount)
	}
	if listResp.Objects[0].Key != "new-object.txt" {
		t.Errorf("expected key 'new-object.txt', got %q", listResp.Objects[0].Key)
	}
}

// Test 13: uploaded object downloadable via UI object download API
func TestObjectUpload_ThenDownload(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "download-verify")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Upload an object.
	content := []byte("downloadable test content")
	rr := doObjectUpload(t, handler, cookies, "download-verify", "download-me.txt", content, "text/plain")
	if rr.Code != http.StatusCreated {
		t.Fatalf("upload failed: %d: %s", rr.Code, rr.Body.String())
	}

	// Download and verify content.
	dlRR := doObjectDownload(t, handler, cookies, "download-verify", "download-me.txt")
	if dlRR.Code != http.StatusOK {
		t.Fatalf("download failed: %d: %s", dlRR.Code, dlRR.Body.String())
	}

	downloaded, _ := io.ReadAll(dlRR.Body)
	if !bytes.Equal(downloaded, content) {
		t.Errorf("downloaded content mismatch: got %q, want %q", downloaded, content)
	}

	// Check headers.
	if ct := dlRR.Header().Get("Content-Type"); ct != "text/plain" {
		t.Errorf("Content-Type: got %q, want 'text/plain'", ct)
	}
	if etag := dlRR.Header().Get("ETag"); etag == "" {
		t.Error("ETag header should be set")
	}
}

// Test 14: key with slashes works
func TestObjectUpload_KeyWithSlashes(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "slash-key-upload")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Upload with slashes in key.
	content := []byte("nested content")
	rr := doObjectUpload(t, handler, cookies, "slash-key-upload", "path/to/nested/file.txt", content, "text/plain")
	if rr.Code != http.StatusCreated {
		t.Fatalf("upload failed: %d: %s", rr.Code, rr.Body.String())
	}

	var resp uploadResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if resp.Key != "path/to/nested/file.txt" {
		t.Errorf("expected key 'path/to/nested/file.txt', got %q", resp.Key)
	}
}

// Test 15: x-amz-meta-* headers stored and retrievable
func TestObjectUpload_UserMetadata(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "metadata-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Upload with user metadata.
	content := []byte("content with metadata")
	meta := map[string]string{
		"author":  "test-user",
		"version": "1.0",
	}
	rr := doObjectUploadWithMeta(t, handler, cookies, "metadata-bucket", "meta-file.txt", content, "text/plain", meta)
	if rr.Code != http.StatusCreated {
		t.Fatalf("upload failed: %d: %s", rr.Code, rr.Body.String())
	}

	// Download and check metadata headers.
	dlRR := doObjectDownload(t, handler, cookies, "metadata-bucket", "meta-file.txt")
	if dlRR.Code != http.StatusOK {
		t.Fatalf("download failed: %d", dlRR.Code)
	}

	// Check x-amz-meta-* headers (note: keys are lowercased in storage).
	if author := dlRR.Header().Get("X-Amz-Meta-author"); author != "test-user" {
		t.Errorf("X-Amz-Meta-author: got %q, want 'test-user'", author)
	}
	if version := dlRR.Header().Get("X-Amz-Meta-version"); version != "1.0" {
		t.Errorf("X-Amz-Meta-version: got %q, want '1.0'", version)
	}
}

// Test 16: GET method on upload endpoint → 405
func TestObjectUpload_GETMethodNotAllowed(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "method-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Try GET on upload endpoint.
	url := "/ui/api/buckets/method-bucket/objects/upload?key=test.txt"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d: %s", rr.Code, rr.Body.String())
	}
}
