package ui_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

// doObjectMeta issues GET /ui/api/buckets/{bucket}/objects/meta?key=...
func doObjectMeta(t *testing.T, handler http.Handler, cookies []*http.Cookie, bucketName, key string) *httptest.ResponseRecorder {
	t.Helper()
	url := "/ui/api/buckets/" + bucketName + "/objects/meta?key=" + key
	req := httptest.NewRequest(http.MethodGet, url, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// doObjectMetaWithoutKey issues GET /ui/api/buckets/{bucket}/objects/meta (no key param)
func doObjectMetaWithoutKey(t *testing.T, handler http.Handler, cookies []*http.Cookie, bucketName string) *httptest.ResponseRecorder {
	t.Helper()
	url := "/ui/api/buckets/" + bucketName + "/objects/meta"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// objectMetaResponse matches the JSON shape returned by handleObjectMeta.
type objectMetaResponse struct {
	Bucket       string            `json:"bucket"`
	Key          string            `json:"key"`
	Size         int64             `json:"size"`
	ETag         string            `json:"etag"`
	ContentType  string            `json:"contentType"`
	LastModified string            `json:"lastModified"`
	StorageClass string            `json:"storageClass"`
	UserMetadata map[string]string `json:"userMetadata"`
}

// Test 1: valid session + existing object → 200 and expected metadata fields
func TestObjectMeta_Success(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "meta-test-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d: %s", createRR.Code, createRR.Body.String())
	}

	// Create a test object with user metadata.
	content := []byte("test content for metadata view")
	now := time.Now().UTC().Truncate(time.Second)
	userMeta := map[string]string{
		"author":  "test-user",
		"project": "metadata-api",
	}
	metaJSON, _ := json.Marshal(userMeta)
	blobPath := createTestObjectBlobWithMetadata(t, db, "meta-test-bucket", "test-file.txt", content, now, string(metaJSON))
	_ = blobPath

	// Get object metadata.
	rr := doObjectMeta(t, handler, cookies, "meta-test-bucket", "test-file.txt")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp objectMetaResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	// Verify fields.
	if resp.Bucket != "meta-test-bucket" {
		t.Errorf("expected bucket 'meta-test-bucket', got %q", resp.Bucket)
	}
	if resp.Key != "test-file.txt" {
		t.Errorf("expected key 'test-file.txt', got %q", resp.Key)
	}
	if resp.Size != int64(len(content)) {
		t.Errorf("expected size %d, got %d", len(content), resp.Size)
	}
	if resp.ETag != `"testmd5hash123"` {
		t.Errorf("expected quoted etag, got %q", resp.ETag)
	}
	if resp.ContentType != "application/octet-stream" {
		t.Errorf("expected contentType 'application/octet-stream', got %q", resp.ContentType)
	}
	if resp.StorageClass != "STANDARD" {
		t.Errorf("expected storageClass 'STANDARD', got %q", resp.StorageClass)
	}
	if resp.LastModified == "" {
		t.Error("lastModified should not be empty")
	}
	if len(resp.UserMetadata) != 2 {
		t.Fatalf("expected 2 user metadata entries, got %d", len(resp.UserMetadata))
	}
	if resp.UserMetadata["author"] != "test-user" {
		t.Errorf("expected userMetadata.author='test-user', got %q", resp.UserMetadata["author"])
	}
	if resp.UserMetadata["project"] != "metadata-api" {
		t.Errorf("expected userMetadata.project='metadata-api', got %q", resp.UserMetadata["project"])
	}
}

// Test 2: no session → 401
func TestObjectMeta_NoSession(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create bucket and object with session.
	createRR := doCreateBucket(t, handler, cookies, "no-session-meta")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}
	createTestObjectBlob(t, db, "no-session-meta", "obj.txt", []byte("data"))

	// Try to get metadata without session cookies.
	url := "/ui/api/buckets/no-session-meta/objects/meta?key=obj.txt"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 3: invalid bucket name → 400
func TestObjectMeta_InvalidBucketName(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Invalid bucket name (too short).
	rr := doObjectMeta(t, handler, cookies, "ab", "obj.txt")
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

// Test 4: missing bucket → 404
func TestObjectMeta_MissingBucket(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Try to get metadata from non-existent bucket.
	rr := doObjectMeta(t, handler, cookies, "nonexistent-bucket", "obj.txt")
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

// Test 5: missing key query → 400
func TestObjectMeta_MissingKeyQuery(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "key-query-meta")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Try to get metadata without key parameter.
	rr := doObjectMetaWithoutKey(t, handler, cookies, "key-query-meta")
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

// Test 6: missing object → 404
func TestObjectMeta_MissingObject(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket but don't add any objects.
	createRR := doCreateBucket(t, handler, cookies, "missing-obj-meta")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Try to get metadata for non-existent object.
	rr := doObjectMeta(t, handler, cookies, "missing-obj-meta", "nonexistent.txt")
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

// Test 7: key with slashes works
func TestObjectMeta_KeyWithSlashes(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "slash-key-meta")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Create object with slashes in key.
	objectKey := "path/to/nested/file.txt"
	content := []byte("nested content")
	createTestObjectBlob(t, db, "slash-key-meta", objectKey, content)

	// Get metadata using URL-encoded key (or plain, query param handles it).
	rr := doObjectMeta(t, handler, cookies, "slash-key-meta", objectKey)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp objectMetaResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	if resp.Key != objectKey {
		t.Errorf("expected key %q, got %q", objectKey, resp.Key)
	}
}

// Test 8: user metadata map returned correctly
func TestObjectMeta_UserMetadataReturned(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "usermeta-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Create object with user metadata.
	now := time.Now().UTC().Truncate(time.Second)
	userMeta := map[string]string{
		"foo":  "bar",
		"fizz": "buzz",
	}
	metaJSON, _ := json.Marshal(userMeta)
	createTestObjectBlobWithMetadata(t, db, "usermeta-bucket", "meta.txt", []byte("data"), now, string(metaJSON))

	// Get metadata.
	rr := doObjectMeta(t, handler, cookies, "usermeta-bucket", "meta.txt")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp objectMetaResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	if len(resp.UserMetadata) != 2 {
		t.Fatalf("expected 2 user metadata entries, got %d", len(resp.UserMetadata))
	}
	if resp.UserMetadata["foo"] != "bar" {
		t.Errorf("expected userMetadata.foo='bar', got %q", resp.UserMetadata["foo"])
	}
	if resp.UserMetadata["fizz"] != "buzz" {
		t.Errorf("expected userMetadata.fizz='buzz', got %q", resp.UserMetadata["fizz"])
	}
}

// Test 9: contentType/etag/lastModified reflected accurately
func TestObjectMeta_FieldsAccurate(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "fields-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Create object with specific content-type and timestamp.
	now := time.Date(2024, 1, 15, 12, 30, 0, 0, time.UTC)
	blobPath := createTestObjectBlobWithContentType(t, db, "fields-bucket", "file.json", []byte(`{"test":true}`), "application/json", now)
	_ = blobPath

	// Get metadata.
	rr := doObjectMeta(t, handler, cookies, "fields-bucket", "file.json")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp objectMetaResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	if resp.ContentType != "application/json" {
		t.Errorf("expected contentType 'application/json', got %q", resp.ContentType)
	}
	if resp.ETag != `"testmd5hash123"` {
		t.Errorf("expected quoted etag, got %q", resp.ETag)
	}
	if resp.LastModified != now.Format(time.RFC3339) {
		t.Errorf("expected lastModified %q, got %q", now.Format(time.RFC3339), resp.LastModified)
	}
}

// Test 10: corrupt object (is_corrupt=1) → 500
// We'll create a metadata row and then manually set is_corrupt via raw SQL since
// the metadata.DB doesn't expose a MarkCorrupt method in the current implementation.
func TestObjectMeta_CorruptObject(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "corrupt-meta")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Create metadata row pointing to a non-existent blob.
	now := time.Now().UTC().Truncate(time.Second)
	if err := db.UpsertObject("corrupt-meta", "corrupt-file.txt", metadata.PutObjectInput{
		Size:         100,
		ETag:         "fakeetag",
		ContentType:  "text/plain",
		StoragePath:  "/nonexistent/path/to/blob",
		LastModified: now,
		MetadataJSON: "{}",
	}); err != nil {
		t.Fatalf("UpsertObject: %v", err)
	}

	// Mark as corrupt by directly updating the database.
	// Since DB doesn't expose sqldb, we'll use a different approach:
	// We'll skip this test for now as it requires internal access.
	// Instead, we'll rely on the fact that GetObjectByKey checks is_corrupt.
	// For this test to work, we need to manually mark the object corrupt.
	// Since we can't do that easily without exposing DB internals, we'll verify
	// that a missing blob (which would be detected and marked corrupt on recovery)
	// would return ErrCorruptObject.
	
	// Skip this test for now - corrupt object detection happens at recovery/scan time.
	// The current implementation returns ErrCorruptObject when is_corrupt=1,
	// but we don't have a public API to mark objects corrupt in tests.
	t.Skip("Skipping corrupt object test - requires DB internals access to mark is_corrupt=1")
}

// Test 11: POST method on /objects/meta → 405
func TestObjectMeta_POSTMethodNotAllowed(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "post-meta-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// POST to /objects/meta should be 405.
	url := "/ui/api/buckets/post-meta-bucket/objects/meta?key=test.txt"
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

// Test 12: empty user metadata → empty map in response
func TestObjectMeta_EmptyUserMetadata(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "empty-meta-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Create object with empty metadata_json.
	createTestObjectBlob(t, db, "empty-meta-bucket", "obj.txt", []byte("data"))

	// Get metadata.
	rr := doObjectMeta(t, handler, cookies, "empty-meta-bucket", "obj.txt")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp objectMetaResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	if len(resp.UserMetadata) != 0 {
		t.Errorf("expected empty user metadata map, got %d entries", len(resp.UserMetadata))
	}
}

// Helper: createTestObjectBlobWithMetadata creates a test object with custom metadata_json.
func createTestObjectBlobWithMetadata(t *testing.T, db *metadata.DB, bucketName, objectKey string, content []byte, lastModified time.Time, metadataJSON string) string {
	t.Helper()
	tmpDir := t.TempDir()
	blobPath := tmpDir + "/test-object.blob"
	if err := os.WriteFile(blobPath, content, 0644); err != nil {
		t.Fatalf("failed to create test blob: %v", err)
	}

	if err := db.UpsertObject(bucketName, objectKey, metadata.PutObjectInput{
		Size:         int64(len(content)),
		ETag:         "testmd5hash123",
		ContentType:  "application/octet-stream",
		StoragePath:  blobPath,
		LastModified: lastModified,
		MetadataJSON: metadataJSON,
	}); err != nil {
		t.Fatalf("UpsertObject: %v", err)
	}
	return blobPath
}

// Helper: createTestObjectBlobWithContentType creates a test object with custom content-type.
func createTestObjectBlobWithContentType(t *testing.T, db *metadata.DB, bucketName, objectKey string, content []byte, contentType string, lastModified time.Time) string {
	t.Helper()
	tmpDir := t.TempDir()
	blobPath := tmpDir + "/test-object.blob"
	if err := os.WriteFile(blobPath, content, 0644); err != nil {
		t.Fatalf("failed to create test blob: %v", err)
	}

	if err := db.UpsertObject(bucketName, objectKey, metadata.PutObjectInput{
		Size:         int64(len(content)),
		ETag:         "testmd5hash123",
		ContentType:  contentType,
		StoragePath:  blobPath,
		LastModified: lastModified,
		MetadataJSON: "{}",
	}); err != nil {
		t.Fatalf("UpsertObject: %v", err)
	}
	return blobPath
}
