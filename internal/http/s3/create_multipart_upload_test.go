package s3_test

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/lukehemmin/hemmins-s3-api/internal/auth"
	s3 "github.com/lukehemmin/hemmins-s3-api/internal/http/s3"
	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// makeSignedPostRequest builds a correctly-signed POST request with no body.
// Multipart initiation sends no body; the ?uploads parameter is in the URL.
// Follows the same signing pattern as makeSignedPutRequest.
func makeSignedPostRequest(t *testing.T, path string, now time.Time) *http.Request {
	t.Helper()

	r, err := http.NewRequest(http.MethodPost, "http://"+testHost+path, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	r.Host = testHost

	// Empty body hash.
	payloadHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	date := now.UTC().Format("20060102")
	dateTime := now.UTC().Format("20060102T150405Z")
	r.Header.Set("X-Amz-Date", dateTime)
	r.Header.Set("X-Amz-Content-Sha256", payloadHash)

	signedHeaderNames := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	sort.Strings(signedHeaderNames)

	canonHdrs, signedHdrsStr, err := auth.CanonicalHeaders(r, signedHeaderNames)
	if err != nil {
		t.Fatalf("CanonicalHeaders: %v", err)
	}

	escapedPath := r.URL.EscapedPath()
	if escapedPath == "" {
		escapedPath = "/"
	}
	canonQuery := auth.CanonicalQueryString(r.URL.Query())
	canonReq := auth.CanonicalRequest(r.Method, escapedPath, canonQuery, canonHdrs, signedHdrsStr, payloadHash)

	scope := auth.CredentialScope(date, testRegion, "s3")
	sts := auth.StringToSign(dateTime, scope, auth.HashSHA256Hex([]byte(canonReq)))

	signingKey := auth.DeriveSigningKey(testSecretKey, date, testRegion, "s3")
	sig := auth.ComputeSignature(signingKey, sts)

	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+testAccessKey+"/"+scope+
		", SignedHeaders="+signedHdrsStr+", Signature="+sig)

	return r
}

// setupMultipartServer creates a server configured for multipart upload tests.
// It returns the handler and the open metadata DB.
func setupMultipartServer(t *testing.T) (http.Handler, *metadata.DB) {
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

	srv := s3.NewServer(db, testRegion, testMasterKey)
	srv.SetStoragePaths(t.TempDir(), t.TempDir())
	// Use a short expiry so the test is deterministic; zero falls back to 24h in the handler.
	srv.SetMultipartExpiry(24 * time.Hour)
	return srv.Handler(), db
}

// parseInitiateResult decodes an InitiateMultipartUploadResult XML body.
func parseInitiateResult(t *testing.T, body []byte) (bucket, key, uploadID string) {
	t.Helper()
	var result struct {
		Bucket   string `xml:"Bucket"`
		Key      string `xml:"Key"`
		UploadId string `xml:"UploadId"`
	}
	if err := xml.Unmarshal(body, &result); err != nil {
		t.Fatalf("xml.Unmarshal InitiateMultipartUploadResult: %v\nbody: %s", err, body)
	}
	return result.Bucket, result.Key, result.UploadId
}

// queryMultipartRow retrieves a multipart_uploads row by upload_id for inspection.
func queryMultipartRow(t *testing.T, db *metadata.DB, uploadID string) (objectKey, metaJSON string) {
	t.Helper()
	err := db.SQLDB().QueryRow(
		"SELECT object_key, metadata_json FROM multipart_uploads WHERE id = ?",
		uploadID,
	).Scan(&objectKey, &metaJSON)
	if err != nil {
		t.Fatalf("queryMultipartRow(%q): %v", uploadID, err)
	}
	return objectKey, metaJSON
}

// ── 1. POST /bucket/key?uploads success → 200 OK ─────────────────────────────

func TestCreateMultipartUpload_Success(t *testing.T) {
	handler, db := setupMultipartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())

	r := makeSignedPostRequest(t, "/test-bucket/mykey.bin?uploads", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

// ── 2. missing bucket → NoSuchBucket ─────────────────────────────────────────

func TestCreateMultipartUpload_NoSuchBucket(t *testing.T) {
	handler, _ := setupMultipartServer(t)

	r := makeSignedPostRequest(t, "/ghost-bucket/key.bin?uploads", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "NoSuchBucket" {
		t.Errorf("error code = %q, want NoSuchBucket", code)
	}
}

// ── 3. empty key → InvalidRequest ────────────────────────────────────────────

func TestCreateMultipartUpload_EmptyKey(t *testing.T) {
	handler, db := setupMultipartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())

	// Path ends in "/" so objectKey is empty after routing.
	r := makeSignedPostRequest(t, "/test-bucket/?uploads", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "InvalidRequest" {
		t.Errorf("error code = %q, want InvalidRequest", code)
	}
}

// ── 4. unauthenticated request → AccessDenied ────────────────────────────────

func TestCreateMultipartUpload_NoAuth(t *testing.T) {
	handler, db := setupMultipartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())

	// Build a raw POST without signing.
	r, err := http.NewRequest(http.MethodPost,
		"http://"+testHost+"/test-bucket/key.bin?uploads", nil)
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

// ── 5. key with slashes works ─────────────────────────────────────────────────

func TestCreateMultipartUpload_KeyWithSlashes(t *testing.T) {
	handler, db := setupMultipartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())

	r := makeSignedPostRequest(t, "/test-bucket/folder/sub/file.bin?uploads", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	_, key, _ := parseInitiateResult(t, w.Body.Bytes())
	if key != "folder/sub/file.bin" {
		t.Errorf("Key = %q, want folder/sub/file.bin", key)
	}
}

// ── 6. XML response contains Bucket, Key, UploadId ───────────────────────────

func TestCreateMultipartUpload_XMLFields(t *testing.T) {
	handler, db := setupMultipartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())

	r := makeSignedPostRequest(t, "/test-bucket/object.tar.gz?uploads", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	bucket, key, uploadID := parseInitiateResult(t, w.Body.Bytes())

	if bucket != "test-bucket" {
		t.Errorf("Bucket = %q, want test-bucket", bucket)
	}
	if key != "object.tar.gz" {
		t.Errorf("Key = %q, want object.tar.gz", key)
	}
	if uploadID == "" {
		t.Error("UploadId is empty")
	}
	// Verify the XML namespace is present (required by S3 SDKs).
	if !strings.Contains(w.Body.String(), "http://s3.amazonaws.com/doc/2006-03-01/") {
		t.Error("XML namespace not found in response body")
	}
}

// ── 7. multipart_uploads row actually created ─────────────────────────────────

func TestCreateMultipartUpload_RowCreated(t *testing.T) {
	handler, db := setupMultipartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())

	r := makeSignedPostRequest(t, "/test-bucket/data.bin?uploads", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	_, _, uploadID := parseInitiateResult(t, w.Body.Bytes())

	// Verify the row exists in the DB.
	objectKey, _ := queryMultipartRow(t, db, uploadID)
	if objectKey != "data.bin" {
		t.Errorf("object_key = %q, want data.bin", objectKey)
	}

	// Verify expires_at is set (non-empty).
	var expiresAt string
	if err := db.SQLDB().QueryRow(
		"SELECT expires_at FROM multipart_uploads WHERE id = ?", uploadID,
	).Scan(&expiresAt); err != nil {
		t.Fatalf("querying expires_at: %v", err)
	}
	if expiresAt == "" {
		t.Error("expires_at is empty")
	}
}

// ── 8. x-amz-meta-* stored in metadata_json ──────────────────────────────────

func TestCreateMultipartUpload_UserMetadata(t *testing.T) {
	handler, db := setupMultipartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())

	r := makeSignedPostRequest(t, "/test-bucket/archive.tar?uploads", time.Now())
	r.Header.Set("X-Amz-Meta-Author", "alice")
	r.Header.Set("X-Amz-Meta-Project", "demo")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	_, _, uploadID := parseInitiateResult(t, w.Body.Bytes())
	_, metaJSON := queryMultipartRow(t, db, uploadID)

	// metadata_json must contain the x-amz-meta-* headers.
	if !strings.Contains(metaJSON, "alice") {
		t.Errorf("metadata_json = %q; want it to contain author=alice", metaJSON)
	}
	if !strings.Contains(metaJSON, "demo") {
		t.Errorf("metadata_json = %q; want it to contain project=demo", metaJSON)
	}
}

// ── 9. same key → two calls produce different upload IDs ─────────────────────

func TestCreateMultipartUpload_UniqueUploadID(t *testing.T) {
	handler, db := setupMultipartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())

	do := func() string {
		r := makeSignedPostRequest(t, "/test-bucket/same-key.bin?uploads", time.Now())
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
		}
		_, _, id := parseInitiateResult(t, w.Body.Bytes())
		return id
	}

	id1 := do()
	id2 := do()

	if id1 == "" || id2 == "" {
		t.Fatal("upload IDs must not be empty")
	}
	if id1 == id2 {
		t.Errorf("consecutive calls returned the same upload_id %q", id1)
	}
}

// ── 10. existing Put/Get/Head/Delete/Copy/ListObjectsV2 remain green ──────────
// (covered by running all tests together with go test ./..., this case
// acts as a smoke-test of a round-trip through the router to ensure
// the new POST case does not break existing routing.)

func TestCreateMultipartUpload_RouterSmokeTest(t *testing.T) {
	handler, db := setupMultipartServer(t)
	insertBucket(t, db, "smoke-bucket", time.Now())

	// Verify PutObject still works.
	putObject(t, handler, "/smoke-bucket/file.txt", "hello", time.Now())

	// Verify GetObject still works.
	w := doGet(t, handler, "/smoke-bucket/file.txt", time.Now())
	if w.Code != http.StatusOK {
		t.Fatalf("GetObject after multipart server setup: status=%d body=%s", w.Code, w.Body.String())
	}
	body, _ := io.ReadAll(w.Result().Body)
	if string(body) != "hello" {
		t.Errorf("GetObject body = %q, want hello", string(body))
	}

	// Verify CreateMultipartUpload works alongside existing object ops.
	r := makeSignedPostRequest(t, "/smoke-bucket/upload.bin?uploads", time.Now())
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, r)
	if w2.Code != http.StatusOK {
		t.Fatalf("CreateMultipartUpload: status=%d body=%s", w2.Code, w2.Body.String())
	}

	// POST without ?uploads must return 501 NotImplemented.
	r3, _ := http.NewRequest(http.MethodPost, "http://"+testHost+"/smoke-bucket/upload.bin", nil)
	r3.Host = testHost
	signRequest(t, r3, time.Now())
	w3 := httptest.NewRecorder()
	handler.ServeHTTP(w3, r3)
	if w3.Code != http.StatusNotImplemented {
		t.Fatalf("POST without ?uploads: status=%d want 501; body=%s", w3.Code, w3.Body.String())
	}
}
