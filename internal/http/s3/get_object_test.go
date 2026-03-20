package s3_test

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// makeSignedGetRequest builds a correctly-signed GET request for the given path.
// Wraps makeSignedRequest from list_buckets_test.go (same package).
func makeSignedGetRequest(t *testing.T, path string, now time.Time) *http.Request {
	t.Helper()
	return makeSignedRequest(t, http.MethodGet, path, now)
}

// doGet performs a signed GET request and returns the recorder result.
func doGet(t *testing.T, handler http.Handler, path string, now time.Time) *httptest.ResponseRecorder {
	t.Helper()
	r := makeSignedGetRequest(t, path, now)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

// putObject is a convenience helper that PUTs an object through the handler
// and fatals if the PUT does not return 200 OK.
func putObject(t *testing.T, handler http.Handler, path, body string, now time.Time) {
	t.Helper()
	r := makeSignedPutRequest(t, path, body, now)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT %s: status=%d body=%s", path, w.Code, w.Body.String())
	}
}

// md5Hex returns the lowercase hex-encoded MD5 digest of s.
func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// insertObjectRow inserts a raw object row for testing paths that bypass PutObject.
func insertObjectRow(t *testing.T, db *metadata.DB, bucketName, objectKey, storagePath, contentType, etag, metaJSON string, size int64, isCorrupt int) {
	t.Helper()
	_, err := db.SQLDB().Exec(`
		INSERT INTO objects
			(bucket_id, object_key, size, etag, content_type, storage_path,
			 last_modified, metadata_json, is_corrupt)
		VALUES (
			(SELECT id FROM buckets WHERE name = ?),
			?, ?, ?, ?, ?, ?, ?, ?
		)
	`, bucketName, objectKey, size, etag, contentType, storagePath,
		time.Now().UTC().Format(time.RFC3339), metaJSON, isCorrupt)
	if err != nil {
		t.Fatalf("insertObjectRow bucket=%q key=%q: %v", bucketName, objectKey, err)
	}
}

// ── 1. GET existing object returns 200 ───────────────────────────────────────

func TestGetObject_Success(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)
	putObject(t, handler, "/my-bucket/hello.txt", "hello, world", now)

	w := doGet(t, handler, "/my-bucket/hello.txt", now)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

// ── 2. Response body matches uploaded content ─────────────────────────────────

func TestGetObject_BodyMatchesUpload(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)

	const body = "the quick brown fox"
	putObject(t, handler, "/my-bucket/fox.txt", body, now)

	w := doGet(t, handler, "/my-bucket/fox.txt", now)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if got := w.Body.String(); got != body {
		t.Errorf("response body = %q, want %q", got, body)
	}
}

// ── 3. Zero-byte object download succeeds ────────────────────────────────────

func TestGetObject_ZeroByteObject(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)
	putObject(t, handler, "/my-bucket/empty.bin", "", now)

	w := doGet(t, handler, "/my-bucket/empty.bin", now)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if n := w.Body.Len(); n != 0 {
		t.Errorf("body length = %d, want 0", n)
	}
}

// ── 4. Missing key returns 404 NoSuchKey ─────────────────────────────────────

func TestGetObject_NoSuchKey(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	insertBucket(t, db, "my-bucket", time.Now())
	// No object inserted.

	w := doGet(t, handler, "/my-bucket/missing-key.txt", time.Now())

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "NoSuchKey" {
		t.Errorf("error code = %q, want NoSuchKey", code)
	}
}

// ── 5. Missing bucket returns 404 NoSuchBucket ───────────────────────────────

func TestGetObject_NoSuchBucket(t *testing.T) {
	handler, _ := setupPutObjectServer(t)
	// No bucket inserted.

	w := doGet(t, handler, "/missing-bucket/key.txt", time.Now())

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "NoSuchBucket" {
		t.Errorf("error code = %q, want NoSuchBucket", code)
	}
}

// ── 6. Unauthenticated GET returns 403 AccessDenied ──────────────────────────

func TestGetObject_Unauthenticated(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	insertBucket(t, db, "my-bucket", time.Now())

	r, _ := http.NewRequest(http.MethodGet, "http://"+testHost+"/my-bucket/key.txt", nil)
	r.Host = testHost

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "AccessDenied" {
		t.Errorf("error code = %q, want AccessDenied", code)
	}
}

// ── 7. Object key with slashes routes correctly ───────────────────────────────

func TestGetObject_KeyWithSlashes(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)

	const body = "deep content"
	putObject(t, handler, "/my-bucket/folder/sub/file.dat", body, now)

	w := doGet(t, handler, "/my-bucket/folder/sub/file.dat", now)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if got := w.Body.String(); got != body {
		t.Errorf("body = %q, want %q", got, body)
	}
}

// ── 8. Content-Type is restored ──────────────────────────────────────────────

func TestGetObject_ContentTypeRestored(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)

	r := makeSignedPutRequest(t, "/my-bucket/page.html", "<html/>", now)
	r.Header.Set("Content-Type", "text/html; charset=utf-8")
	pw := httptest.NewRecorder()
	handler.ServeHTTP(pw, r)
	if pw.Code != http.StatusOK {
		t.Fatalf("PUT: status = %d, want 200", pw.Code)
	}

	w := doGet(t, handler, "/my-bucket/page.html", now)

	if w.Code != http.StatusOK {
		t.Fatalf("GET: status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if ct := w.Result().Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/html; charset=utf-8", ct)
	}
}

// ── 9. ETag is restored and quoted ───────────────────────────────────────────

func TestGetObject_ETagRestoredAndQuoted(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)

	const body = "etag test body"
	putObject(t, handler, "/my-bucket/etag.txt", body, now)

	w := doGet(t, handler, "/my-bucket/etag.txt", now)

	if w.Code != http.StatusOK {
		t.Fatalf("GET: status = %d, want 200", w.Code)
	}
	wantETag := `"` + md5Hex(body) + `"`
	if got := w.Result().Header.Get("ETag"); got != wantETag {
		t.Errorf("ETag = %q, want %q", got, wantETag)
	}
}

// ── 10. Last-Modified header is present ──────────────────────────────────────

func TestGetObject_LastModifiedPresent(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)
	putObject(t, handler, "/my-bucket/dated.txt", "some content", now)

	w := doGet(t, handler, "/my-bucket/dated.txt", now)

	if w.Code != http.StatusOK {
		t.Fatalf("GET: status = %d, want 200", w.Code)
	}
	lm := w.Result().Header.Get("Last-Modified")
	if lm == "" {
		t.Error("Last-Modified header is absent")
	}
	// Must be parseable as an HTTP date (RFC 1123).
	if _, err := http.ParseTime(lm); err != nil {
		t.Errorf("Last-Modified %q is not a valid HTTP date: %v", lm, err)
	}
}

// ── 11. x-amz-meta-* headers restored ────────────────────────────────────────

func TestGetObject_UserMetaRestored(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)

	r := makeSignedPutRequest(t, "/my-bucket/meta.txt", "payload", now)
	r.Header.Set("X-Amz-Meta-Author", "alice")
	r.Header.Set("X-Amz-Meta-Project", "demo")
	pw := httptest.NewRecorder()
	handler.ServeHTTP(pw, r)
	if pw.Code != http.StatusOK {
		t.Fatalf("PUT: status = %d, want 200", pw.Code)
	}

	w := doGet(t, handler, "/my-bucket/meta.txt", now)

	if w.Code != http.StatusOK {
		t.Fatalf("GET: status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	resp := w.Result()
	if got := resp.Header.Get("X-Amz-Meta-Author"); got != "alice" {
		t.Errorf("X-Amz-Meta-Author = %q, want alice", got)
	}
	if got := resp.Header.Get("X-Amz-Meta-Project"); got != "demo" {
		t.Errorf("X-Amz-Meta-Project = %q, want demo", got)
	}
}

// ── 12a. is_corrupt=1 → 500 InternalError, no path leak ─────────────────────

func TestGetObject_CorruptObject_InternalError(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)

	const fakePath = "/tmp/hemmins-test-corrupt-object-abc999/obj.blob"
	insertObjectRow(t, db, "my-bucket", "corrupt.txt",
		fakePath, "text/plain", "aabbccdd", "{}", 42, 1 /* is_corrupt=1 */)

	w := doGet(t, handler, "/my-bucket/corrupt.txt", now)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "InternalError" {
		t.Errorf("error code = %q, want InternalError", code)
	}
	// Raw storage path must not appear in the response.
	if strings.Contains(w.Body.String(), fakePath) {
		t.Error("response leaks internal storage path")
	}
	if strings.Contains(w.Body.String(), "hemmins-test-corrupt") {
		t.Error("response leaks internal path fragment")
	}
}

// ── 12b. Blob file missing (is_corrupt=0) → 500 InternalError, no path leak ─

func TestGetObject_MissingBlob_InternalError(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)

	// A valid metadata row pointing to a path that does not exist on disk.
	// This simulates a blob that was lost after the metadata commit.
	const missingPath = "/tmp/hemmins-test-missing-blob-xyz321/obj.blob"
	insertObjectRow(t, db, "my-bucket", "missing.txt",
		missingPath, "text/plain", "aabbccdd", "{}", 42, 0 /* is_corrupt=0 */)

	w := doGet(t, handler, "/my-bucket/missing.txt", now)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "InternalError" {
		t.Errorf("error code = %q, want InternalError", code)
	}
	// Raw storage path and OS error details must not appear in the response.
	if strings.Contains(w.Body.String(), missingPath) {
		t.Error("response leaks internal storage path")
	}
	if strings.Contains(w.Body.String(), "hemmins-test-missing") {
		t.Error("response leaks internal path fragment")
	}
	if strings.Contains(w.Body.String(), "no such file") {
		t.Error("response leaks OS error details")
	}
}

// ── 13. PutObject → GetObject end-to-end integration test ───────────────────

func TestGetObject_EndToEnd(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "e2e-bucket", now)

	const body = "end-to-end integration test content 123"
	wantETag := `"` + md5Hex(body) + `"`

	// PUT
	pr := makeSignedPutRequest(t, "/e2e-bucket/e2e.txt", body, now)
	pr.Header.Set("Content-Type", "text/plain; charset=utf-8")
	pr.Header.Set("X-Amz-Meta-Source", "e2e-test")
	pw := httptest.NewRecorder()
	handler.ServeHTTP(pw, pr)
	if pw.Code != http.StatusOK {
		t.Fatalf("PUT: status = %d, want 200; body: %s", pw.Code, pw.Body.String())
	}

	// GET
	w := doGet(t, handler, "/e2e-bucket/e2e.txt", now)

	if w.Code != http.StatusOK {
		t.Fatalf("GET: status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	resp := w.Result()

	// Body content
	gotBody, _ := io.ReadAll(resp.Body)
	if string(gotBody) != body {
		t.Errorf("body = %q, want %q", string(gotBody), body)
	}
	// ETag
	if got := resp.Header.Get("ETag"); got != wantETag {
		t.Errorf("ETag = %q, want %q", got, wantETag)
	}
	// Content-Type
	if got := resp.Header.Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/plain; charset=utf-8", got)
	}
	// Last-Modified present and parseable
	if lm := resp.Header.Get("Last-Modified"); lm == "" {
		t.Error("Last-Modified header absent")
	}
	// User metadata
	if got := resp.Header.Get("X-Amz-Meta-Source"); got != "e2e-test" {
		t.Errorf("X-Amz-Meta-Source = %q, want e2e-test", got)
	}
	// Content-Length
	if cl := resp.Header.Get("Content-Length"); cl == "" {
		t.Error("Content-Length header absent")
	}
}

// ── 14. Metadata layer: GetObjectByKey unit tests ───────────────────────────

func TestMetadataGetObjectByKey_NotFound(t *testing.T) {
	db, err := metadata.Open(":memory:")
	if err != nil {
		t.Fatalf("metadata.Open: %v", err)
	}
	defer db.Close()
	insertBucket(t, db, "my-bucket", time.Now())

	_, err = db.GetObjectByKey("my-bucket", "ghost.txt")
	if err == nil {
		t.Fatal("expected ErrObjectNotFound, got nil")
	}
	if !isObjectNotFound(err) {
		t.Errorf("expected ErrObjectNotFound, got %v", err)
	}
}

func TestMetadataGetObjectByKey_CorruptFlag(t *testing.T) {
	db, err := metadata.Open(":memory:")
	if err != nil {
		t.Fatalf("metadata.Open: %v", err)
	}
	defer db.Close()
	insertBucket(t, db, "my-bucket", time.Now())
	insertObjectRow(t, db, "my-bucket", "corrupt.txt",
		"/fake/path", "text/plain", "abc", "{}", 10, 1)

	_, err = db.GetObjectByKey("my-bucket", "corrupt.txt")
	if err == nil {
		t.Fatal("expected ErrCorruptObject, got nil")
	}
	if !isCorruptObject(err) {
		t.Errorf("expected ErrCorruptObject, got %v", err)
	}
}

func TestMetadataGetObjectByKey_Success(t *testing.T) {
	db, err := metadata.Open(":memory:")
	if err != nil {
		t.Fatalf("metadata.Open: %v", err)
	}
	defer db.Close()
	insertBucket(t, db, "my-bucket", time.Now())
	insertObjectRow(t, db, "my-bucket", "ok.txt",
		"/fake/path.blob", "text/plain", "deadbeef", `{"author":"test"}`, 99, 0)

	obj, err := db.GetObjectByKey("my-bucket", "ok.txt")
	if err != nil {
		t.Fatalf("GetObjectByKey: %v", err)
	}
	if obj.Key != "ok.txt" {
		t.Errorf("Key = %q, want ok.txt", obj.Key)
	}
	if obj.Size != 99 {
		t.Errorf("Size = %d, want 99", obj.Size)
	}
	if obj.ETag != "deadbeef" {
		t.Errorf("ETag = %q, want deadbeef", obj.ETag)
	}
	if obj.ContentType != "text/plain" {
		t.Errorf("ContentType = %q, want text/plain", obj.ContentType)
	}
	if obj.StoragePath != "/fake/path.blob" {
		t.Errorf("StoragePath = %q, want /fake/path.blob", obj.StoragePath)
	}
	if obj.MetadataJSON != `{"author":"test"}` {
		t.Errorf("MetadataJSON = %q", obj.MetadataJSON)
	}
}

// ── sentinel helpers ─────────────────────────────────────────────────────────

func isObjectNotFound(err error) bool {
	return errors.Is(err, metadata.ErrObjectNotFound)
}

func isCorruptObject(err error) bool {
	return errors.Is(err, metadata.ErrCorruptObject)
}
