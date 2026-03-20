package s3_test

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lukehemmin/hemmins-s3-api/internal/auth"
	s3 "github.com/lukehemmin/hemmins-s3-api/internal/http/s3"
	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// setupUploadPartServerWithRoot creates a server configured for UploadPart tests
// and returns the multipartRoot directory path so tests can inspect filesystem state.
// All three roots are separate TempDirs under the same OS temp parent, ensuring
// they reside on the same filesystem for atomic rename to work correctly.
func setupUploadPartServerWithRoot(t *testing.T) (http.Handler, *metadata.DB, string) {
	t.Helper()
	db, err := metadata.Open(":memory:")
	if err != nil {
		t.Fatalf("metadata.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	ciphertext, err := auth.EncryptSecret(testMasterKey, testSecretKey)
	if err != nil {
		t.Fatalf("EncryptSecret: %v", err)
	}
	pwHash, err := auth.HashPassword("testpassword123!")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := db.Bootstrap("admin", pwHash, testAccessKey, ciphertext); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	multipartRoot := t.TempDir()
	srv := s3.NewServer(db, testRegion, testMasterKey)
	srv.SetStoragePaths(t.TempDir(), t.TempDir())
	srv.SetMultipartRoot(multipartRoot)
	srv.SetMultipartExpiry(24 * time.Hour)
	return srv.Handler(), db, multipartRoot
}

// setupUploadPartServer is a convenience wrapper for tests that do not need
// direct access to the multipartRoot directory.
func setupUploadPartServer(t *testing.T) (http.Handler, *metadata.DB) {
	h, db, _ := setupUploadPartServerWithRoot(t)
	return h, db
}

// createUpload calls CreateMultipartUpload via POST /{bucket}/{key}?uploads and
// returns the upload_id from the XML response. Fatals if the request does not return 200.
func createUpload(t *testing.T, handler http.Handler, bucket, key string) string {
	t.Helper()
	path := fmt.Sprintf("/%s/%s?uploads", bucket, key)
	r := makeSignedPostRequest(t, path, time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("createUpload(%q, %q): status=%d body=%s", bucket, key, w.Code, w.Body.String())
	}
	_, _, id := parseInitiateResult(t, w.Body.Bytes())
	return id
}

// doUploadPart performs a signed PUT to /{bucket}/{key}?partNumber=N&uploadId=X
// with the given body and returns the response recorder.
func doUploadPart(t *testing.T, handler http.Handler, bucket, key string, partNumber int, uploadID, body string) *httptest.ResponseRecorder {
	t.Helper()
	path := fmt.Sprintf("/%s/%s?partNumber=%d&uploadId=%s", bucket, key, partNumber, uploadID)
	r := makeSignedPutRequest(t, path, body, time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

// queryPartRow retrieves etag, size, and staging_path from multipart_parts
// for a given (uploadID, partNumber) pair. Fatals if the row is not found.
func queryPartRow(t *testing.T, db *metadata.DB, uploadID string, partNumber int) (etag string, size int64, stagingPath string) {
	t.Helper()
	err := db.SQLDB().QueryRow(
		"SELECT etag, size, staging_path FROM multipart_parts WHERE upload_id = ? AND part_number = ?",
		uploadID, partNumber,
	).Scan(&etag, &size, &stagingPath)
	if err != nil {
		t.Fatalf("queryPartRow(%q, %d): %v", uploadID, partNumber, err)
	}
	return etag, size, stagingPath
}

// md5Base64 returns the base64-encoded MD5 digest of s (for Content-MD5 header).
func md5Base64(s string) string {
	sum := md5.Sum([]byte(s))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// ── 1. PUT /bucket/key?partNumber=1&uploadId=X success → 200 OK ──────────────

func TestUploadPart_Success(t *testing.T) {
	handler, db := setupUploadPartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	uploadID := createUpload(t, handler, "test-bucket", "file.bin")

	w := doUploadPart(t, handler, "test-bucket", "file.bin", 1, uploadID, "hello world")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

// ── 2. missing uploadId → 400 InvalidRequest ─────────────────────────────────

func TestUploadPart_MissingUploadId(t *testing.T) {
	handler, db := setupUploadPartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())

	// Build request without uploadId query param.
	r := makeSignedPutRequest(t, "/test-bucket/file.bin?partNumber=1", "data", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "InvalidRequest" {
		t.Errorf("error code = %q, want InvalidRequest", code)
	}
}

// ── 3. missing partNumber → 400 InvalidRequest ───────────────────────────────

func TestUploadPart_MissingPartNumber(t *testing.T) {
	handler, db := setupUploadPartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	uploadID := createUpload(t, handler, "test-bucket", "file.bin")

	path := fmt.Sprintf("/test-bucket/file.bin?uploadId=%s", uploadID)
	r := makeSignedPutRequest(t, path, "data", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "InvalidRequest" {
		t.Errorf("error code = %q, want InvalidRequest", code)
	}
}

// ── 4. invalid partNumber format → 400 InvalidArgument ───────────────────────

func TestUploadPart_InvalidPartNumberFormat(t *testing.T) {
	handler, db := setupUploadPartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	uploadID := createUpload(t, handler, "test-bucket", "file.bin")

	path := fmt.Sprintf("/test-bucket/file.bin?partNumber=abc&uploadId=%s", uploadID)
	r := makeSignedPutRequest(t, path, "data", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "InvalidArgument" {
		t.Errorf("error code = %q, want InvalidArgument", code)
	}
}

// ── 5. partNumber 0 → 400 InvalidArgument ────────────────────────────────────

func TestUploadPart_PartNumberZero(t *testing.T) {
	handler, db := setupUploadPartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	uploadID := createUpload(t, handler, "test-bucket", "file.bin")

	w := doUploadPart(t, handler, "test-bucket", "file.bin", 0, uploadID, "data")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "InvalidArgument" {
		t.Errorf("error code = %q, want InvalidArgument", code)
	}
}

// ── 6. partNumber 10001 → 400 InvalidArgument ────────────────────────────────

func TestUploadPart_PartNumberTooLarge(t *testing.T) {
	handler, db := setupUploadPartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	uploadID := createUpload(t, handler, "test-bucket", "file.bin")

	w := doUploadPart(t, handler, "test-bucket", "file.bin", 10001, uploadID, "data")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "InvalidArgument" {
		t.Errorf("error code = %q, want InvalidArgument", code)
	}
}

// ── 7. non-existent uploadId → 404 NoSuchUpload ──────────────────────────────

func TestUploadPart_NoSuchUpload(t *testing.T) {
	handler, db := setupUploadPartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())

	w := doUploadPart(t, handler, "test-bucket", "file.bin", 1, "00000000-0000-0000-0000-000000000000", "data")

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "NoSuchUpload" {
		t.Errorf("error code = %q, want NoSuchUpload", code)
	}
}

// ── 8. upload session bucket/key mismatch → 404 NoSuchUpload ─────────────────

func TestUploadPart_BucketKeyMismatch(t *testing.T) {
	handler, db := setupUploadPartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	insertBucket(t, db, "other-bucket", time.Now())

	// Create upload for test-bucket/real-key.bin.
	uploadID := createUpload(t, handler, "test-bucket", "real-key.bin")

	// Use the upload ID against a different key — should be NoSuchUpload.
	w := doUploadPart(t, handler, "test-bucket", "WRONG-key.bin", 1, uploadID, "data")

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "NoSuchUpload" {
		t.Errorf("error code = %q, want NoSuchUpload", code)
	}
}

// ── 9. unauthenticated UploadPart → 403 AccessDenied ─────────────────────────

func TestUploadPart_NoAuth(t *testing.T) {
	handler, db := setupUploadPartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	uploadID := createUpload(t, handler, "test-bucket", "file.bin")

	// Build a raw PUT without signing.
	path := fmt.Sprintf("/test-bucket/file.bin?partNumber=1&uploadId=%s", uploadID)
	r, err := http.NewRequest(http.MethodPut, "http://"+testHost+path, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
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

// ── 10. zero-byte part upload → 200 OK ───────────────────────────────────────
//
// The 5 MiB minimum-part-size constraint applies to all parts *except the last*.
// At UploadPart time, we cannot know if this is the last part, so the constraint
// is NOT enforced here. Zero-byte parts are accepted.
// Per s3-compatibility-matrix.md section 8.

func TestUploadPart_ZeroBytePart(t *testing.T) {
	handler, db := setupUploadPartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	uploadID := createUpload(t, handler, "test-bucket", "file.bin")

	// Empty body.
	w := doUploadPart(t, handler, "test-bucket", "file.bin", 1, uploadID, "")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

// ── 11. correct Content-MD5 → 200 OK ─────────────────────────────────────────

func TestUploadPart_ContentMD5Correct(t *testing.T) {
	handler, db := setupUploadPartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	uploadID := createUpload(t, handler, "test-bucket", "file.bin")

	body := "part data here"
	path := fmt.Sprintf("/test-bucket/file.bin?partNumber=1&uploadId=%s", uploadID)
	r := makeSignedPutRequest(t, path, body, time.Now())
	r.Header.Set("Content-MD5", md5Base64(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

// ── 12. malformed Content-MD5 → 400 InvalidDigest ────────────────────────────

func TestUploadPart_ContentMD5Malformed(t *testing.T) {
	handler, db := setupUploadPartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	uploadID := createUpload(t, handler, "test-bucket", "file.bin")

	path := fmt.Sprintf("/test-bucket/file.bin?partNumber=1&uploadId=%s", uploadID)
	r := makeSignedPutRequest(t, path, "data", time.Now())
	r.Header.Set("Content-MD5", "not-valid-base64!!!")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "InvalidDigest" {
		t.Errorf("error code = %q, want InvalidDigest", code)
	}
}

// ── 13. Content-MD5 mismatch → 400 BadDigest ─────────────────────────────────

func TestUploadPart_ContentMD5Mismatch(t *testing.T) {
	handler, db := setupUploadPartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	uploadID := createUpload(t, handler, "test-bucket", "file.bin")

	path := fmt.Sprintf("/test-bucket/file.bin?partNumber=1&uploadId=%s", uploadID)
	r := makeSignedPutRequest(t, path, "actual data", time.Now())
	// Provide MD5 of different content → mismatch.
	r.Header.Set("Content-MD5", md5Base64("different content"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "BadDigest" {
		t.Errorf("error code = %q, want BadDigest", code)
	}
}

// ── 14. multipart_parts row created ──────────────────────────────────────────

func TestUploadPart_RowCreated(t *testing.T) {
	handler, db := setupUploadPartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	uploadID := createUpload(t, handler, "test-bucket", "data.bin")

	body := "part content"
	w := doUploadPart(t, handler, "test-bucket", "data.bin", 3, uploadID, body)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	etag, size, stagingPath := queryPartRow(t, db, uploadID, 3)

	expectedETag := md5Hex(body)
	if etag != expectedETag {
		t.Errorf("etag = %q, want %q", etag, expectedETag)
	}
	if size != int64(len(body)) {
		t.Errorf("size = %d, want %d", size, len(body))
	}
	if stagingPath == "" {
		t.Error("staging_path is empty")
	}
}

// ── 15. re-upload same partNumber overwrites previous row ────────────────────
//
// S3 allows re-uploading the same part number; the new part replaces the old one.
// Per s3-compatibility-matrix.md section 8 (no restriction on re-upload).
//
// With the request-unique staging path design, each upload writes to a distinct
// path. After a successful re-upload:
//   - DB row reflects the new ETag/size/staging_path.
//   - staging_path changes to a new unique path.
//   - Old staging file is deleted (best-effort).
//   - New staging file exists at the new path.

func TestUploadPart_SamePartNumberOverwrite(t *testing.T) {
	handler, db := setupUploadPartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	uploadID := createUpload(t, handler, "test-bucket", "file.bin")

	// Upload part 2 with "first content".
	w1 := doUploadPart(t, handler, "test-bucket", "file.bin", 2, uploadID, "first content")
	if w1.Code != http.StatusOK {
		t.Fatalf("first upload: status=%d body=%s", w1.Code, w1.Body.String())
	}
	etag1 := w1.Header().Get("ETag")
	_, _, stagingPath1 := queryPartRow(t, db, uploadID, 2)

	// Re-upload part 2 with "second content".
	w2 := doUploadPart(t, handler, "test-bucket", "file.bin", 2, uploadID, "second content")
	if w2.Code != http.StatusOK {
		t.Fatalf("second upload: status=%d body=%s", w2.Code, w2.Body.String())
	}
	etag2 := w2.Header().Get("ETag")

	// ETags must differ (different content).
	if etag1 == etag2 {
		t.Errorf("re-upload of same part returned same ETag %q; expected new ETag", etag1)
	}

	// DB row must reflect the second upload.
	dbETag, dbSize, stagingPath2 := queryPartRow(t, db, uploadID, 2)
	if dbETag != hex.EncodeToString(func() []byte {
		sum := md5.Sum([]byte("second content"))
		return sum[:]
	}()) {
		t.Errorf("db etag = %q, want MD5 of %q", dbETag, "second content")
	}
	if dbSize != int64(len("second content")) {
		t.Errorf("db size = %d, want %d", dbSize, len("second content"))
	}

	// Each upload must produce a distinct staging path (request-unique design).
	if stagingPath1 == stagingPath2 {
		t.Errorf("re-upload must produce a new unique staging path, but got same: %q", stagingPath1)
	}

	// Old staging file must have been deleted after the successful re-upload.
	if _, statErr := os.Stat(stagingPath1); !os.IsNotExist(statErr) {
		t.Errorf("old staging file %q still exists after successful re-upload", stagingPath1)
	}

	// New staging file must exist at the new unique path.
	if _, statErr := os.Stat(stagingPath2); os.IsNotExist(statErr) {
		t.Errorf("new staging file %q does not exist after re-upload", stagingPath2)
	}

	// New file must contain the bytes matching the new ETag.
	got, readErr := os.ReadFile(stagingPath2)
	if readErr != nil {
		t.Fatalf("reading new staging file %q: %v", stagingPath2, readErr)
	}
	if string(got) != "second content" {
		t.Errorf("new staging file content = %q, want %q", string(got), "second content")
	}
}

// ── 16. ETag header is quoted ─────────────────────────────────────────────────
//
// Per s3-compatibility-matrix.md section 6.2: ETag is returned as a quoted string.

func TestUploadPart_ETagQuoted(t *testing.T) {
	handler, db := setupUploadPartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	uploadID := createUpload(t, handler, "test-bucket", "file.bin")

	body := "etag test data"
	w := doUploadPart(t, handler, "test-bucket", "file.bin", 1, uploadID, body)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	etag := w.Header().Get("ETag")
	if len(etag) < 2 || etag[0] != '"' || etag[len(etag)-1] != '"' {
		t.Errorf("ETag = %q; want a double-quoted string", etag)
	}

	// The inner value must be the MD5 hex of the body.
	inner := etag[1 : len(etag)-1]
	expected := md5Hex(body)
	if inner != expected {
		t.Errorf("ETag inner = %q, want MD5 of body %q", inner, expected)
	}
}

// ── 17. existing CreateMultipartUpload / PutObject / CopyObject / GetObject /
//
//	DeleteObject tests remain green (router smoke test)
//
// ─────────────────────────────────────────────────────────────────────────────

func TestUploadPart_RouterSmokeTest(t *testing.T) {
	handler, db := setupUploadPartServer(t)
	insertBucket(t, db, "smoke-bucket", time.Now())

	// PutObject still works.
	putObject(t, handler, "/smoke-bucket/file.txt", "hello", time.Now())

	// GetObject still works.
	w := doGet(t, handler, "/smoke-bucket/file.txt", time.Now())
	if w.Code != http.StatusOK {
		t.Fatalf("GetObject: status=%d body=%s", w.Code, w.Body.String())
	}

	// DeleteObject still works.
	rDel := makeSignedRequest(t, http.MethodDelete, "/smoke-bucket/file.txt", time.Now())
	wDel := httptest.NewRecorder()
	handler.ServeHTTP(wDel, rDel)
	if wDel.Code != http.StatusNoContent {
		t.Fatalf("DeleteObject: status=%d body=%s", wDel.Code, wDel.Body.String())
	}

	// CreateMultipartUpload still works.
	uploadID := createUpload(t, handler, "smoke-bucket", "upload.bin")
	if uploadID == "" {
		t.Fatal("CreateMultipartUpload returned empty uploadId")
	}

	// UploadPart works alongside existing ops.
	wPart := doUploadPart(t, handler, "smoke-bucket", "upload.bin", 1, uploadID, "part data")
	if wPart.Code != http.StatusOK {
		t.Fatalf("UploadPart: status=%d body=%s", wPart.Code, wPart.Body.String())
	}

	// PutObject with partNumber + uploadId query should go to UploadPart, NOT PutObject.
	// PutObject without these params should still work.
	putObject(t, handler, "/smoke-bucket/another.txt", "world", time.Now())
	wGet2 := doGet(t, handler, "/smoke-bucket/another.txt", time.Now())
	if wGet2.Code != http.StatusOK {
		t.Fatalf("GetObject second: status=%d body=%s", wGet2.Code, wGet2.Body.String())
	}

	// CopyObject still works: put source, then copy.
	putObject(t, handler, "/smoke-bucket/src.txt", "source content", time.Now())
	rCopy := makeSignedPutRequest(t, "/smoke-bucket/dst.txt", "", time.Now())
	rCopy.Header.Set("X-Amz-Copy-Source", "/smoke-bucket/src.txt")
	wCopy := httptest.NewRecorder()
	handler.ServeHTTP(wCopy, rCopy)
	if wCopy.Code != http.StatusOK {
		t.Fatalf("CopyObject: status=%d body=%s", wCopy.Code, wCopy.Body.String())
	}
}

// ── 18. failed re-upload (Content-MD5 mismatch) preserves original part ───────
//
// A re-upload that fails Content-MD5 verification must leave the previously
// uploaded part's file content and DB row (etag, size, staging_path) intact.
// The new unique staging file created for the failed attempt must be cleaned up.

func TestUploadPart_ReuploadFailedMD5_PreservesOriginalPart(t *testing.T) {
	handler, db := setupUploadPartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	uploadID := createUpload(t, handler, "test-bucket", "file.bin")

	// First upload: succeeds.
	origBody := "original content"
	w1 := doUploadPart(t, handler, "test-bucket", "file.bin", 1, uploadID, origBody)
	if w1.Code != http.StatusOK {
		t.Fatalf("first upload: status=%d body=%s", w1.Code, w1.Body.String())
	}

	// Record original DB row.
	origETag, origSize, origStagingPath := queryPartRow(t, db, uploadID, 1)

	// Count files in the staging directory before the failed re-upload.
	partDir := filepath.Dir(origStagingPath)
	entriesBefore, rdErr := os.ReadDir(partDir)
	if rdErr != nil {
		t.Fatalf("ReadDir(%q) before re-upload: %v", partDir, rdErr)
	}

	// Second upload: Content-MD5 does not match body → must fail.
	path := fmt.Sprintf("/test-bucket/file.bin?partNumber=1&uploadId=%s", uploadID)
	r := makeSignedPutRequest(t, path, "new content", time.Now())
	r.Header.Set("Content-MD5", md5Base64("wrong content")) // intentional mismatch
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, r)

	if w2.Code != http.StatusBadRequest {
		t.Fatalf("re-upload: status=%d (want 400 BadDigest); body=%s", w2.Code, w2.Body.String())
	}
	if code := xmlErrorCode(t, w2.Body.Bytes()); code != "BadDigest" {
		t.Errorf("error code = %q, want BadDigest", code)
	}

	// DB row must be unchanged.
	newETag, newSize, newStagingPath := queryPartRow(t, db, uploadID, 1)
	if newETag != origETag {
		t.Errorf("etag changed after failed re-upload: %q → %q", origETag, newETag)
	}
	if newSize != origSize {
		t.Errorf("size changed after failed re-upload: %d → %d", origSize, newSize)
	}
	if newStagingPath != origStagingPath {
		t.Errorf("staging_path changed after failed re-upload: %q → %q", origStagingPath, newStagingPath)
	}

	// Original staging file must still contain the original bytes.
	got, err := os.ReadFile(origStagingPath)
	if err != nil {
		t.Fatalf("reading staging file %q: %v", origStagingPath, err)
	}
	if string(got) != origBody {
		t.Errorf("staging file content = %q, want %q", string(got), origBody)
	}

	// The staging directory must have the same number of files as before the failed
	// re-upload. The new unique file created for the failed attempt must have been
	// deleted; no orphan files may remain.
	entriesAfter, rdErr2 := os.ReadDir(partDir)
	if rdErr2 != nil {
		t.Fatalf("ReadDir(%q) after re-upload: %v", partDir, rdErr2)
	}
	if len(entriesAfter) != len(entriesBefore) {
		t.Errorf("staging dir has %d file(s) after failed re-upload, want %d (no orphan files)",
			len(entriesAfter), len(entriesBefore))
	}
}

// ── 19. first upload failure leaves no orphan file ────────────────────────────
//
// When the very first UploadPart for a (upload_id, part_number) pair fails
// (e.g. Content-MD5 mismatch), no DB row and no orphan file must remain.
// AtomicWrite creates the staging directory before writing; it must be empty
// after the failed attempt's unique file is cleaned up.

func TestUploadPart_FailedUpload_NoOrphanFile(t *testing.T) {
	handler, db, multipartRoot := setupUploadPartServerWithRoot(t)
	insertBucket(t, db, "test-bucket", time.Now())
	uploadID := createUpload(t, handler, "test-bucket", "file.bin")

	// Upload part 1 with a Content-MD5 that does not match the body.
	path := fmt.Sprintf("/test-bucket/file.bin?partNumber=1&uploadId=%s", uploadID)
	r := makeSignedPutRequest(t, path, "some data", time.Now())
	r.Header.Set("Content-MD5", md5Base64("different data")) // intentional mismatch
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", w.Code, w.Body.String())
	}

	// No DB row must exist for (uploadID, partNumber=1).
	var count int
	if err := db.SQLDB().QueryRow(
		"SELECT COUNT(*) FROM multipart_parts WHERE upload_id = ? AND part_number = 1",
		uploadID,
	).Scan(&count); err != nil {
		t.Fatalf("querying part count: %v", err)
	}
	if count != 0 {
		t.Errorf("multipart_parts row was created for a failed first upload (want 0, got %d)", count)
	}

	// The staging directory for this upload (multipartRoot/<upload_id>/) is created
	// by AtomicWrite before the file is written. After the failed attempt's unique
	// file is cleaned up, the directory must be empty — no orphan files.
	partDir := filepath.Join(multipartRoot, uploadID)
	entries, rdErr := os.ReadDir(partDir)
	if rdErr != nil {
		// Directory may not exist if AtomicWrite failed before MkdirAll — that is also fine.
		if !os.IsNotExist(rdErr) {
			t.Fatalf("ReadDir(%q): %v", partDir, rdErr)
		}
	} else if len(entries) != 0 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("staging dir %q has %d orphan file(s) after failed first upload: %v",
			partDir, len(entries), names)
	}
}

// ── 20. each UploadPart call produces a distinct staging path ─────────────────
//
// Two successful uploads of the same (upload_id, part_number) must each write
// to a different file path. This is the core invariant of the request-unique
// staging path design: concurrent requests cannot share a path and thus cannot
// clobber each other's in-flight data.

func TestUploadPart_EachCallUsesUniquePath(t *testing.T) {
	handler, db := setupUploadPartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	uploadID := createUpload(t, handler, "test-bucket", "file.bin")

	// First successful upload.
	w1 := doUploadPart(t, handler, "test-bucket", "file.bin", 5, uploadID, "alpha")
	if w1.Code != http.StatusOK {
		t.Fatalf("first upload: status=%d body=%s", w1.Code, w1.Body.String())
	}
	_, _, path1 := queryPartRow(t, db, uploadID, 5)

	// Second successful upload of the same part.
	w2 := doUploadPart(t, handler, "test-bucket", "file.bin", 5, uploadID, "beta")
	if w2.Code != http.StatusOK {
		t.Fatalf("second upload: status=%d body=%s", w2.Code, w2.Body.String())
	}
	_, _, path2 := queryPartRow(t, db, uploadID, 5)

	// Third successful upload — path must again differ from both prior paths.
	w3 := doUploadPart(t, handler, "test-bucket", "file.bin", 5, uploadID, "gamma")
	if w3.Code != http.StatusOK {
		t.Fatalf("third upload: status=%d body=%s", w3.Code, w3.Body.String())
	}
	_, _, path3 := queryPartRow(t, db, uploadID, 5)

	if path1 == path2 {
		t.Errorf("first and second uploads share staging path %q", path1)
	}
	if path2 == path3 {
		t.Errorf("second and third uploads share staging path %q", path2)
	}
	if path1 == path3 {
		t.Errorf("first and third uploads share staging path %q", path1)
	}
}
