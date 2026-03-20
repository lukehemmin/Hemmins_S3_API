package ui_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

// doListObjects issues GET /ui/api/buckets/{name}/objects with the given cookies and query params.
func doListObjects(t *testing.T, handler http.Handler, cookies []*http.Cookie, bucketName string, params map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	url := "/ui/api/buckets/" + bucketName + "/objects"
	if len(params) > 0 {
		url += "?"
		first := true
		for k, v := range params {
			if !first {
				url += "&"
			}
			url += k + "=" + v
			first = false
		}
	}
	req := httptest.NewRequest(http.MethodGet, url, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// listObjectsResponse mirrors the JSON response structure.
type listObjectsResponse struct {
	Bucket                string `json:"bucket"`
	Prefix                string `json:"prefix"`
	Delimiter             string `json:"delimiter"`
	MaxKeys               int    `json:"maxKeys"`
	KeyCount              int    `json:"keyCount"`
	IsTruncated           bool   `json:"isTruncated"`
	NextContinuationToken string `json:"nextContinuationToken"`
	Objects               []struct {
		Key          string `json:"key"`
		Size         int64  `json:"size"`
		ETag         string `json:"etag"`
		LastModified string `json:"lastModified"`
		ContentType  string `json:"contentType"`
		StorageClass string `json:"storageClass"`
	} `json:"objects"`
	CommonPrefixes []string `json:"commonPrefixes"`
}

// Test 1: valid session + empty bucket → 200 with empty objects list
func TestListObjects_EmptyBucket(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create a bucket.
	createRR := doCreateBucket(t, handler, loginRR.Result().Cookies(), "empty-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d: %s", createRR.Code, createRR.Body.String())
	}

	// List objects.
	rr := doListObjects(t, handler, loginRR.Result().Cookies(), "empty-bucket", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp listObjectsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	if resp.Bucket != "empty-bucket" {
		t.Errorf("bucket: got %q, want %q", resp.Bucket, "empty-bucket")
	}
	if resp.KeyCount != 0 {
		t.Errorf("keyCount: got %d, want 0", resp.KeyCount)
	}
	if len(resp.Objects) != 0 {
		t.Errorf("objects: got %d items, want 0", len(resp.Objects))
	}
	if resp.IsTruncated {
		t.Errorf("isTruncated: got true, want false")
	}
	if resp.MaxKeys != 1000 {
		t.Errorf("maxKeys: got %d, want 1000", resp.MaxKeys)
	}
}

// Test 2: bucket with objects returns proper fields
func TestListObjects_WithObjects(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create a bucket.
	createRR := doCreateBucket(t, handler, loginRR.Result().Cookies(), "objects-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d: %s", createRR.Code, createRR.Body.String())
	}

	// Add objects directly via DB.
	now := time.Now().UTC().Truncate(time.Second)
	objects := []struct {
		key         string
		size        int64
		etag        string
		contentType string
	}{
		{"file1.txt", 100, "abc123", "text/plain"},
		{"file2.txt", 200, "def456", "text/plain"},
		{"folder/file3.txt", 300, "ghi789", "text/plain"},
	}
	for _, obj := range objects {
		if err := db.UpsertObject("objects-bucket", obj.key, metadata.PutObjectInput{
			Size:         obj.size,
			ETag:         obj.etag,
			ContentType:  obj.contentType,
			StoragePath:  "/fake/path/" + obj.key,
			LastModified: now,
			MetadataJSON: "{}",
		}); err != nil {
			t.Fatalf("UpsertObject(%q): %v", obj.key, err)
		}
	}

	// List objects.
	rr := doListObjects(t, handler, loginRR.Result().Cookies(), "objects-bucket", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp listObjectsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	if resp.KeyCount != 3 {
		t.Errorf("keyCount: got %d, want 3", resp.KeyCount)
	}
	if len(resp.Objects) != 3 {
		t.Errorf("objects: got %d items, want 3", len(resp.Objects))
	}

	// Verify first object fields.
	if len(resp.Objects) > 0 {
		obj := resp.Objects[0]
		if obj.Key != "file1.txt" {
			t.Errorf("first object key: got %q, want %q", obj.Key, "file1.txt")
		}
		if obj.Size != 100 {
			t.Errorf("first object size: got %d, want 100", obj.Size)
		}
		// ETag should be quoted.
		if obj.ETag != "\"abc123\"" {
			t.Errorf("first object etag: got %q, want %q", obj.ETag, "\"abc123\"")
		}
		if obj.ContentType != "text/plain" {
			t.Errorf("first object contentType: got %q, want %q", obj.ContentType, "text/plain")
		}
		if obj.StorageClass != "STANDARD" {
			t.Errorf("first object storageClass: got %q, want %q", obj.StorageClass, "STANDARD")
		}
		if obj.LastModified == "" {
			t.Error("first object lastModified must not be empty")
		}
		// Verify lastModified is valid RFC3339.
		if _, err := time.Parse(time.RFC3339, obj.LastModified); err != nil {
			t.Errorf("first object lastModified not valid RFC3339: %q — %v", obj.LastModified, err)
		}
	}
}

// Test 3: prefix filter works
func TestListObjects_PrefixFilter(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create a bucket.
	createRR := doCreateBucket(t, handler, loginRR.Result().Cookies(), "prefix-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d: %s", createRR.Code, createRR.Body.String())
	}

	// Add objects.
	now := time.Now().UTC()
	keys := []string{"docs/readme.txt", "docs/guide.txt", "images/logo.png", "images/icon.png", "root.txt"}
	for _, key := range keys {
		if err := db.UpsertObject("prefix-bucket", key, metadata.PutObjectInput{
			Size:         100,
			ETag:         "etag",
			ContentType:  "application/octet-stream",
			StoragePath:  "/fake/" + key,
			LastModified: now,
			MetadataJSON: "{}",
		}); err != nil {
			t.Fatalf("UpsertObject(%q): %v", key, err)
		}
	}

	// List with prefix.
	rr := doListObjects(t, handler, loginRR.Result().Cookies(), "prefix-bucket", map[string]string{"prefix": "docs/"})
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp listObjectsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	if resp.Prefix != "docs/" {
		t.Errorf("prefix: got %q, want %q", resp.Prefix, "docs/")
	}
	if resp.KeyCount != 2 {
		t.Errorf("keyCount: got %d, want 2", resp.KeyCount)
	}
	for _, obj := range resp.Objects {
		if !hasPrefix(obj.Key, "docs/") {
			t.Errorf("object %q does not have prefix %q", obj.Key, "docs/")
		}
	}
}

// Test 4: delimiter grouping works
func TestListObjects_DelimiterGrouping(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create a bucket.
	createRR := doCreateBucket(t, handler, loginRR.Result().Cookies(), "delimiter-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d: %s", createRR.Code, createRR.Body.String())
	}

	// Add objects.
	now := time.Now().UTC()
	keys := []string{"docs/readme.txt", "docs/guide.txt", "images/logo.png", "root.txt"}
	for _, key := range keys {
		if err := db.UpsertObject("delimiter-bucket", key, metadata.PutObjectInput{
			Size:         100,
			ETag:         "etag",
			ContentType:  "application/octet-stream",
			StoragePath:  "/fake/" + key,
			LastModified: now,
			MetadataJSON: "{}",
		}); err != nil {
			t.Fatalf("UpsertObject(%q): %v", key, err)
		}
	}

	// List with delimiter.
	rr := doListObjects(t, handler, loginRR.Result().Cookies(), "delimiter-bucket", map[string]string{"delimiter": "/"})
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp listObjectsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	if resp.Delimiter != "/" {
		t.Errorf("delimiter: got %q, want %q", resp.Delimiter, "/")
	}

	// Should have 1 object (root.txt) and 2 common prefixes (docs/, images/).
	if len(resp.Objects) != 1 {
		t.Errorf("objects count: got %d, want 1", len(resp.Objects))
	}
	if len(resp.Objects) > 0 && resp.Objects[0].Key != "root.txt" {
		t.Errorf("object key: got %q, want %q", resp.Objects[0].Key, "root.txt")
	}

	if len(resp.CommonPrefixes) != 2 {
		t.Errorf("commonPrefixes count: got %d, want 2", len(resp.CommonPrefixes))
	}
	// Common prefixes should be sorted.
	if len(resp.CommonPrefixes) >= 2 {
		if resp.CommonPrefixes[0] != "docs/" {
			t.Errorf("commonPrefixes[0]: got %q, want %q", resp.CommonPrefixes[0], "docs/")
		}
		if resp.CommonPrefixes[1] != "images/" {
			t.Errorf("commonPrefixes[1]: got %q, want %q", resp.CommonPrefixes[1], "images/")
		}
	}

	// KeyCount should include both objects and common prefixes.
	if resp.KeyCount != 3 {
		t.Errorf("keyCount: got %d, want 3", resp.KeyCount)
	}
}

// Test 5: continuation token works (pagination)
func TestListObjects_Pagination(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create a bucket.
	createRR := doCreateBucket(t, handler, loginRR.Result().Cookies(), "pagination-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d: %s", createRR.Code, createRR.Body.String())
	}

	// Add 5 objects.
	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		key := "file" + string(rune('a'+i)) + ".txt"
		if err := db.UpsertObject("pagination-bucket", key, metadata.PutObjectInput{
			Size:         100,
			ETag:         "etag",
			ContentType:  "text/plain",
			StoragePath:  "/fake/" + key,
			LastModified: now,
			MetadataJSON: "{}",
		}); err != nil {
			t.Fatalf("UpsertObject(%q): %v", key, err)
		}
	}

	// First page: maxKeys=2.
	rr1 := doListObjects(t, handler, loginRR.Result().Cookies(), "pagination-bucket", map[string]string{"maxKeys": "2"})
	if rr1.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr1.Code, rr1.Body.String())
	}

	var resp1 listObjectsResponse
	if err := json.Unmarshal(rr1.Body.Bytes(), &resp1); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	if resp1.MaxKeys != 2 {
		t.Errorf("page1 maxKeys: got %d, want 2", resp1.MaxKeys)
	}
	if resp1.KeyCount != 2 {
		t.Errorf("page1 keyCount: got %d, want 2", resp1.KeyCount)
	}
	if !resp1.IsTruncated {
		t.Error("page1 isTruncated: got false, want true")
	}
	if resp1.NextContinuationToken == "" {
		t.Error("page1 nextContinuationToken must not be empty")
	}

	// Second page using continuation token.
	rr2 := doListObjects(t, handler, loginRR.Result().Cookies(), "pagination-bucket", map[string]string{
		"maxKeys":           "2",
		"continuationToken": resp1.NextContinuationToken,
	})
	if rr2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr2.Code, rr2.Body.String())
	}

	var resp2 listObjectsResponse
	if err := json.Unmarshal(rr2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	if resp2.KeyCount != 2 {
		t.Errorf("page2 keyCount: got %d, want 2", resp2.KeyCount)
	}
	if !resp2.IsTruncated {
		t.Error("page2 isTruncated: got false, want true")
	}

	// Third page should have 1 item and not be truncated.
	rr3 := doListObjects(t, handler, loginRR.Result().Cookies(), "pagination-bucket", map[string]string{
		"maxKeys":           "2",
		"continuationToken": resp2.NextContinuationToken,
	})
	if rr3.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr3.Code, rr3.Body.String())
	}

	var resp3 listObjectsResponse
	if err := json.Unmarshal(rr3.Body.Bytes(), &resp3); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	if resp3.KeyCount != 1 {
		t.Errorf("page3 keyCount: got %d, want 1", resp3.KeyCount)
	}
	if resp3.IsTruncated {
		t.Error("page3 isTruncated: got true, want false")
	}
}

// Test 6: invalid continuation token → 400
func TestListObjects_InvalidContinuationToken(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create a bucket.
	createRR := doCreateBucket(t, handler, loginRR.Result().Cookies(), "invalid-token-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d: %s", createRR.Code, createRR.Body.String())
	}

	// List with invalid continuation token.
	rr := doListObjects(t, handler, loginRR.Result().Cookies(), "invalid-token-bucket", map[string]string{
		"continuationToken": "not-valid-base64!!!",
	})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "invalid continuation token" {
		t.Errorf("unexpected error message: %q", resp["error"])
	}
}

// Test 7: no session → 401
func TestListObjects_NoSession(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	// Create bucket first with session.
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	createRR := doCreateBucket(t, handler, loginRR.Result().Cookies(), "nosession-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d: %s", createRR.Code, createRR.Body.String())
	}

	// List without session.
	rr := doListObjects(t, handler, nil, "nosession-bucket", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 8: invalid bucket name → 400
func TestListObjects_InvalidBucketName(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	invalidNames := []string{
		"ab",           // too short
		"UPPER",        // uppercase
		"-starts-with", // starts with hyphen
	}

	for _, name := range invalidNames {
		t.Run(name, func(t *testing.T) {
			rr := doListObjects(t, handler, loginRR.Result().Cookies(), name, nil)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("expected 400 for %q, got %d: %s", name, rr.Code, rr.Body.String())
			}
		})
	}
}

// Test 9: nonexistent bucket → 404
func TestListObjects_BucketNotFound(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doListObjects(t, handler, loginRR.Result().Cookies(), "nonexistent-bucket", nil)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "bucket not found" {
		t.Errorf("unexpected error message: %q", resp["error"])
	}
}

// Test 10: invalid maxKeys → 400
func TestListObjects_InvalidMaxKeys(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create bucket.
	createRR := doCreateBucket(t, handler, loginRR.Result().Cookies(), "maxkeys-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d: %s", createRR.Code, createRR.Body.String())
	}

	invalidValues := []string{"0", "-1", "abc", ""}
	for _, v := range invalidValues {
		if v == "" {
			continue // empty string means default, which is valid
		}
		t.Run(v, func(t *testing.T) {
			rr := doListObjects(t, handler, loginRR.Result().Cookies(), "maxkeys-bucket", map[string]string{"maxKeys": v})
			if rr.Code != http.StatusBadRequest {
				t.Errorf("expected 400 for maxKeys=%q, got %d: %s", v, rr.Code, rr.Body.String())
			}
		})
	}
}

// Test 11: maxKeys above 1000 is capped at 1000
func TestListObjects_MaxKeysCapped(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create bucket.
	createRR := doCreateBucket(t, handler, loginRR.Result().Cookies(), "capped-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d: %s", createRR.Code, createRR.Body.String())
	}

	rr := doListObjects(t, handler, loginRR.Result().Cookies(), "capped-bucket", map[string]string{"maxKeys": "5000"})
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp listObjectsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	if resp.MaxKeys != 1000 {
		t.Errorf("maxKeys should be capped at 1000, got %d", resp.MaxKeys)
	}
}

// Test 12: method not allowed (POST, PUT, DELETE on /objects)
func TestListObjects_MethodNotAllowed(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create bucket.
	createRR := doCreateBucket(t, handler, loginRR.Result().Cookies(), "method-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d: %s", createRR.Code, createRR.Body.String())
	}

	// POST, PUT, and PATCH should return 405.
	// DELETE is now allowed (for object deletion) so it's excluded from this test.
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/ui/api/buckets/method-bucket/objects", nil)
			for _, c := range loginRR.Result().Cookies() {
				req.AddCookie(c)
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("expected 405 for %s, got %d", method, rr.Code)
			}
		})
	}
}

// Test 13: existing bucket delete still works
func TestListObjects_DeleteStillWorks(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create bucket.
	createRR := doCreateBucket(t, handler, loginRR.Result().Cookies(), "delete-test-bucket2")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d: %s", createRR.Code, createRR.Body.String())
	}

	// Delete should still work.
	rr := doDeleteBucket(t, handler, loginRR.Result().Cookies(), "delete-test-bucket2")
	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 14: existing bucket list still works
func TestListObjects_BucketListStillWorks(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// GET /ui/api/buckets should still work.
	rr := doBuckets(t, handler, loginRR.Result().Cookies())
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 15: ETag is properly quoted
func TestListObjects_ETagQuoted(t *testing.T) {
	handler, db := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create bucket and object.
	createRR := doCreateBucket(t, handler, loginRR.Result().Cookies(), "etag-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d: %s", createRR.Code, createRR.Body.String())
	}

	now := time.Now().UTC()
	if err := db.UpsertObject("etag-bucket", "test.txt", metadata.PutObjectInput{
		Size:         100,
		ETag:         "d41d8cd98f00b204e9800998ecf8427e",
		ContentType:  "text/plain",
		StoragePath:  "/fake/test.txt",
		LastModified: now,
		MetadataJSON: "{}",
	}); err != nil {
		t.Fatalf("UpsertObject: %v", err)
	}

	rr := doListObjects(t, handler, loginRR.Result().Cookies(), "etag-bucket", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp listObjectsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	if len(resp.Objects) != 1 {
		t.Fatalf("expected 1 object, got %d", len(resp.Objects))
	}

	// ETag must be quoted per S3 convention.
	expectedETag := "\"d41d8cd98f00b204e9800998ecf8427e\""
	if resp.Objects[0].ETag != expectedETag {
		t.Errorf("ETag: got %q, want %q", resp.Objects[0].ETag, expectedETag)
	}
}

// Test 16: unknown sub-resource returns 404
func TestListObjects_UnknownSubResource(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	// Create bucket.
	createRR := doCreateBucket(t, handler, loginRR.Result().Cookies(), "unknown-sub-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d: %s", createRR.Code, createRR.Body.String())
	}

	// Request unknown sub-resource.
	req := httptest.NewRequest(http.MethodGet, "/ui/api/buckets/unknown-sub-bucket/unknown", nil)
	for _, c := range loginRR.Result().Cookies() {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Helper function to check string prefix.
func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
