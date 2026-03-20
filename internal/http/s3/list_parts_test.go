package s3_test

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	s3 "github.com/lukehemmin/hemmins-s3-api/internal/http/s3"
	"github.com/lukehemmin/hemmins-s3-api/internal/auth"
	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// setupListPartsServer creates a server configured for ListParts tests.
// It bootstraps auth credentials, configures storage and multipart roots.
func setupListPartsServer(t *testing.T) (http.Handler, *metadata.DB) {
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
	srv.SetMultipartRoot(t.TempDir())
	srv.SetMultipartExpiry(24 * time.Hour)
	return srv.Handler(), db
}

// insertSession inserts a multipart_uploads row directly into the DB.
// expiresAt controls whether the session appears expired to the handler.
func insertSession(t *testing.T, db *metadata.DB, uploadID, bucket, key string, expiresAt time.Time) {
	t.Helper()
	_, err := db.SQLDB().Exec(`
		INSERT INTO multipart_uploads (id, bucket_id, object_key, initiated_at, expires_at, metadata_json)
		VALUES (?, (SELECT id FROM buckets WHERE name = ?), ?, ?, ?, '{}')
	`, uploadID, bucket, key,
		time.Now().UTC().Format(time.RFC3339),
		expiresAt.UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("insertSession: %v", err)
	}
}

// insertPart inserts a multipart_parts row directly into the DB.
// staging_path may be empty for ListParts tests (no file I/O needed).
func insertPart(t *testing.T, db *metadata.DB, uploadID string, partNum int, etag string, size int64, createdAt time.Time) {
	t.Helper()
	_, err := db.SQLDB().Exec(`
		INSERT INTO multipart_parts (upload_id, part_number, etag, size, staging_path, created_at)
		VALUES (?, ?, ?, ?, '', ?)
	`, uploadID, partNum, etag, size, createdAt.UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("insertPart(partNum=%d): %v", partNum, err)
	}
}

// doListParts issues a signed GET /{bucket}/{key}?uploadId=X and returns the recorder.
func doListParts(t *testing.T, handler http.Handler, bucket, key, uploadID string, now time.Time) *httptest.ResponseRecorder {
	t.Helper()
	path := fmt.Sprintf("/%s/%s?uploadId=%s", bucket, key, uploadID)
	r := makeSignedGetRequest(t, path, now)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

// parseListPartsResult decodes a ListPartsResult XML body into a minimal struct.
func parseListPartsResult(t *testing.T, body []byte) (bucket, key, uploadID string, parts []struct {
	PartNumber   int    `xml:"PartNumber"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
}) {
	t.Helper()
	var result struct {
		Bucket   string `xml:"Bucket"`
		Key      string `xml:"Key"`
		UploadId string `xml:"UploadId"`
		Parts    []struct {
			PartNumber   int    `xml:"PartNumber"`
			LastModified string `xml:"LastModified"`
			ETag         string `xml:"ETag"`
			Size         int64  `xml:"Size"`
		} `xml:"Part"`
	}
	if err := xml.Unmarshal(body, &result); err != nil {
		t.Fatalf("xml.Unmarshal ListPartsResult: %v\nbody: %s", err, body)
	}
	return result.Bucket, result.Key, result.UploadId, result.Parts
}

// ── 1. session exists, 0 parts → 200 + empty parts list ─────────────────────

func TestListParts_EmptyPartsList(t *testing.T) {
	handler, db := setupListPartsServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	insertSession(t, db, "upload-1", "test-bucket", "mykey.bin", time.Now().Add(24*time.Hour))

	w := doListParts(t, handler, "test-bucket", "mykey.bin", "upload-1", time.Now())

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	bucket, key, uploadID, parts := parseListPartsResult(t, w.Body.Bytes())
	if bucket != "test-bucket" {
		t.Errorf("Bucket = %q, want test-bucket", bucket)
	}
	if key != "mykey.bin" {
		t.Errorf("Key = %q, want mykey.bin", key)
	}
	if uploadID != "upload-1" {
		t.Errorf("UploadId = %q, want upload-1", uploadID)
	}
	if len(parts) != 0 {
		t.Errorf("got %d parts, want 0", len(parts))
	}
}

// ── 2. multiple parts → partNumber ascending ─────────────────────────────────

func TestListParts_PartsOrderedAscending(t *testing.T) {
	handler, db := setupListPartsServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	insertSession(t, db, "upload-2", "test-bucket", "file.tar", time.Now().Add(24*time.Hour))

	base := time.Now().UTC().Truncate(time.Second)
	// Insert in non-ascending order to verify ordering.
	insertPart(t, db, "upload-2", 3, "etag3", 300, base.Add(3*time.Second))
	insertPart(t, db, "upload-2", 1, "etag1", 100, base.Add(1*time.Second))
	insertPart(t, db, "upload-2", 2, "etag2", 200, base.Add(2*time.Second))

	w := doListParts(t, handler, "test-bucket", "file.tar", "upload-2", time.Now())

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	_, _, _, parts := parseListPartsResult(t, w.Body.Bytes())
	if len(parts) != 3 {
		t.Fatalf("got %d parts, want 3", len(parts))
	}
	for i, want := range []int{1, 2, 3} {
		if parts[i].PartNumber != want {
			t.Errorf("parts[%d].PartNumber = %d, want %d", i, parts[i].PartNumber, want)
		}
	}
	// Verify sizes match.
	wantSizes := []int64{100, 200, 300}
	for i, want := range wantSizes {
		if parts[i].Size != want {
			t.Errorf("parts[%d].Size = %d, want %d", i, parts[i].Size, want)
		}
	}
}

// ── 3. ETag is quoted string in XML ──────────────────────────────────────────

func TestListParts_ETagQuoted(t *testing.T) {
	handler, db := setupListPartsServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	insertSession(t, db, "upload-3", "test-bucket", "data.bin", time.Now().Add(24*time.Hour))
	insertPart(t, db, "upload-3", 1, "deadbeefdeadbeef", 512, time.Now())

	w := doListParts(t, handler, "test-bucket", "data.bin", "upload-3", time.Now())

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	_, _, _, parts := parseListPartsResult(t, w.Body.Bytes())
	if len(parts) != 1 {
		t.Fatalf("got %d parts, want 1", len(parts))
	}
	// ETag must be a quoted string: "deadbeefdeadbeef"
	if parts[0].ETag != `"deadbeefdeadbeef"` {
		t.Errorf("ETag = %q, want %q", parts[0].ETag, `"deadbeefdeadbeef"`)
	}
}

// ── 4. bucket/key mismatch → NoSuchUpload ────────────────────────────────────

func TestListParts_BucketKeyMismatch(t *testing.T) {
	handler, db := setupListPartsServer(t)
	insertBucket(t, db, "bucket-a", time.Now())
	insertBucket(t, db, "bucket-b", time.Now())
	// Session is scoped to bucket-a/key.bin
	insertSession(t, db, "upload-4", "bucket-a", "key.bin", time.Now().Add(24*time.Hour))

	// Request uses bucket-b → mismatch
	w := doListParts(t, handler, "bucket-b", "key.bin", "upload-4", time.Now())

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "NoSuchUpload" {
		t.Errorf("error code = %q, want NoSuchUpload", code)
	}
}

// ── 5. missing uploadId → not ListParts; falls through to GetObject ──────────

func TestListParts_MissingUploadId_FallsToGetObject(t *testing.T) {
	handler, db := setupListPartsServer(t)
	insertBucket(t, db, "test-bucket", time.Now())

	// GET without uploadId → GetObject path → NoSuchKey (object doesn't exist)
	r := makeSignedGetRequest(t, "/test-bucket/no-such-key.bin", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	// Should hit GetObject → 404 NoSuchKey, not ListParts
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "NoSuchKey" {
		t.Errorf("error code = %q, want NoSuchKey (GetObject path)", code)
	}
}

// ── 6. expired upload → NoSuchUpload ─────────────────────────────────────────

func TestListParts_ExpiredSession(t *testing.T) {
	handler, db := setupListPartsServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	// Set expires_at in the past.
	insertSession(t, db, "upload-6", "test-bucket", "old.bin", time.Now().Add(-1*time.Hour))

	w := doListParts(t, handler, "test-bucket", "old.bin", "upload-6", time.Now())

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "NoSuchUpload" {
		t.Errorf("error code = %q, want NoSuchUpload", code)
	}
}

// ── 7. unauthenticated request → AccessDenied ────────────────────────────────

func TestListParts_NoAuth(t *testing.T) {
	handler, db := setupListPartsServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	insertSession(t, db, "upload-7", "test-bucket", "key.bin", time.Now().Add(24*time.Hour))

	// Build a raw GET without signing.
	r, err := http.NewRequest(http.MethodGet,
		"http://"+testHost+"/test-bucket/key.bin?uploadId=upload-7", nil)
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

// ── 8. key with slashes works ─────────────────────────────────────────────────

func TestListParts_KeyWithSlashes(t *testing.T) {
	handler, db := setupListPartsServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	insertSession(t, db, "upload-8", "test-bucket", "folder/sub/file.bin", time.Now().Add(24*time.Hour))
	insertPart(t, db, "upload-8", 1, "aabbcc", 100, time.Now())

	w := doListParts(t, handler, "test-bucket", "folder/sub/file.bin", "upload-8", time.Now())

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	_, key, _, parts := parseListPartsResult(t, w.Body.Bytes())
	if key != "folder/sub/file.bin" {
		t.Errorf("Key = %q, want folder/sub/file.bin", key)
	}
	if len(parts) != 1 {
		t.Errorf("got %d parts, want 1", len(parts))
	}
}

// ── 9. XML namespace present ──────────────────────────────────────────────────

func TestListParts_XMLNamespace(t *testing.T) {
	handler, db := setupListPartsServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	insertSession(t, db, "upload-9", "test-bucket", "obj.bin", time.Now().Add(24*time.Hour))

	w := doListParts(t, handler, "test-bucket", "obj.bin", "upload-9", time.Now())

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "http://s3.amazonaws.com/doc/2006-03-01/") {
		t.Error("XML namespace not found in response body")
	}
}

// ── 10. GetObject with no uploadId still works (routing regression guard) ────

func TestListParts_GetObjectUnaffected(t *testing.T) {
	handler, db := setupListPartsServer(t)
	insertBucket(t, db, "test-bucket", time.Now())

	// Put an object, then GET it — must not be intercepted by ListParts routing.
	putObject(t, handler, "/test-bucket/hello.txt", "hello world", time.Now())

	w := doGet(t, handler, "/test-bucket/hello.txt", time.Now())
	if w.Code != http.StatusOK {
		t.Fatalf("GetObject status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if w.Body.String() != "hello world" {
		t.Errorf("GetObject body = %q, want %q", w.Body.String(), "hello world")
	}
}

// ── 11. nonexistent uploadId → NoSuchUpload ───────────────────────────────────

func TestListParts_NonexistentUploadId(t *testing.T) {
	handler, db := setupListPartsServer(t)
	insertBucket(t, db, "test-bucket", time.Now())

	w := doListParts(t, handler, "test-bucket", "key.bin", "does-not-exist", time.Now())

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "NoSuchUpload" {
		t.Errorf("error code = %q, want NoSuchUpload", code)
	}
}
