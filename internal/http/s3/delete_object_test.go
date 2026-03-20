package s3_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// doDelete performs a signed DELETE request and returns the recorder result.
func doDelete(t *testing.T, handler http.Handler, path string, now time.Time) *httptest.ResponseRecorder {
	t.Helper()
	r := makeSignedRequest(t, http.MethodDelete, path, now)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

// objectRowExists reports whether an object row is present in the metadata DB.
// Used to verify that the metadata row is cleaned up after DELETE.
func objectRowExists(t *testing.T, db *metadata.DB, bucketName, objectKey string) bool {
	t.Helper()
	var count int
	err := db.SQLDB().QueryRow(`
		SELECT COUNT(*) FROM objects o
		JOIN buckets b ON o.bucket_id = b.id
		WHERE b.name = ? AND o.object_key = ?
	`, bucketName, objectKey).Scan(&count)
	if err != nil {
		t.Fatalf("objectRowExists query bucket=%q key=%q: %v", bucketName, objectKey, err)
	}
	return count > 0
}

// ── 1. DELETE existing object returns 204 ────────────────────────────────────

func TestDeleteObject_Success(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)
	putObject(t, handler, "/my-bucket/hello.txt", "hello, world", now)

	w := doDelete(t, handler, "/my-bucket/hello.txt", now)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", w.Code, w.Body.String())
	}
	// Response body must be empty on success.
	if w.Body.Len() != 0 {
		t.Errorf("response body must be empty, got %d bytes: %q", w.Body.Len(), w.Body.String())
	}
}

// ── 2. Missing key → 204 No Content (idempotent) ─────────────────────────────
//
// Per s3-compatibility-matrix.md section 3: "없는 키 삭제는 멱등 처리".
// Deleting a key that does not exist must succeed silently with 204 No Content,
// matching real AWS S3 behaviour.

func TestDeleteObject_MissingKey_Idempotent(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	insertBucket(t, db, "my-bucket", time.Now())
	// No object inserted.

	w := doDelete(t, handler, "/my-bucket/missing-key.txt", time.Now())

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", w.Code, w.Body.String())
	}
	// Body must be empty — idempotent success has no XML error payload.
	if w.Body.Len() != 0 {
		t.Errorf("response body must be empty for idempotent delete, got %d bytes: %q",
			w.Body.Len(), w.Body.String())
	}
}

// ── 3. Missing bucket returns 404 NoSuchBucket ───────────────────────────────

func TestDeleteObject_NoSuchBucket(t *testing.T) {
	handler, _ := setupPutObjectServer(t)
	// No bucket inserted.

	w := doDelete(t, handler, "/missing-bucket/key.txt", time.Now())

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "NoSuchBucket" {
		t.Errorf("error code = %q, want NoSuchBucket", code)
	}
}

// ── 4. Unauthenticated DELETE returns 403 AccessDenied ───────────────────────

func TestDeleteObject_Unauthenticated(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	insertBucket(t, db, "my-bucket", time.Now())

	r, _ := http.NewRequest(http.MethodDelete, "http://"+testHost+"/my-bucket/key.txt", nil)
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

// ── 5. Object key with slashes routes correctly ───────────────────────────────

func TestDeleteObject_KeyWithSlashes(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)
	putObject(t, handler, "/my-bucket/folder/sub/file.dat", "content", now)

	w := doDelete(t, handler, "/my-bucket/folder/sub/file.dat", now)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", w.Code, w.Body.String())
	}
}

// ── 6. Zero-byte object delete success ───────────────────────────────────────

func TestDeleteObject_ZeroByteObject(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)
	putObject(t, handler, "/my-bucket/empty.bin", "", now)

	w := doDelete(t, handler, "/my-bucket/empty.bin", now)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", w.Code, w.Body.String())
	}
}

// ── 7. After DELETE, GetObject returns NoSuchKey ─────────────────────────────

func TestDeleteObject_AfterDelete_GetReturnsNoSuchKey(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)
	putObject(t, handler, "/my-bucket/gone.txt", "will be deleted", now)

	// Confirm object is accessible before delete.
	if w := doGet(t, handler, "/my-bucket/gone.txt", now); w.Code != http.StatusOK {
		t.Fatalf("pre-delete GET: status = %d, want 200", w.Code)
	}

	// Delete the object.
	if w := doDelete(t, handler, "/my-bucket/gone.txt", now); w.Code != http.StatusNoContent {
		t.Fatalf("DELETE: status = %d, want 204; body: %s", w.Code, w.Body.String())
	}

	// GET after delete must return 404 NoSuchKey.
	w := doGet(t, handler, "/my-bucket/gone.txt", now)
	if w.Code != http.StatusNotFound {
		t.Fatalf("post-delete GET: status = %d, want 404", w.Code)
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "NoSuchKey" {
		t.Errorf("post-delete GET error code = %q, want NoSuchKey", code)
	}
}

// ── 8. After DELETE, metadata row is removed ─────────────────────────────────

func TestDeleteObject_MetadataRowRemoved(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)
	putObject(t, handler, "/my-bucket/tracked.txt", "data", now)

	if !objectRowExists(t, db, "my-bucket", "tracked.txt") {
		t.Fatal("expected object row before delete")
	}

	doDelete(t, handler, "/my-bucket/tracked.txt", now)

	if objectRowExists(t, db, "my-bucket", "tracked.txt") {
		t.Error("object row still present after DELETE")
	}
}

// ── 9. After DELETE, blob file is removed from filesystem ────────────────────

func TestDeleteObject_BlobFileRemoved(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)
	putObject(t, handler, "/my-bucket/blobcheck.txt", "blob content", now)

	// Retrieve the blob storage path from the DB before deletion.
	var storagePath string
	err := db.SQLDB().QueryRow(`
		SELECT o.storage_path FROM objects o
		JOIN buckets b ON o.bucket_id = b.id
		WHERE b.name = 'my-bucket' AND o.object_key = 'blobcheck.txt'
	`).Scan(&storagePath)
	if err != nil {
		t.Fatalf("querying storage path: %v", err)
	}

	// Confirm blob exists on disk before delete.
	if _, statErr := os.Stat(storagePath); statErr != nil {
		t.Fatalf("blob not found before delete: %v", statErr)
	}

	w := doDelete(t, handler, "/my-bucket/blobcheck.txt", now)
	if w.Code != http.StatusNoContent {
		t.Fatalf("DELETE: status = %d, want 204; body: %s", w.Code, w.Body.String())
	}

	// Blob must be gone after delete.
	if _, statErr := os.Stat(storagePath); !os.IsNotExist(statErr) {
		t.Errorf("blob still exists after DELETE (stat err: %v)", statErr)
	}
}

// ── 10a. Corrupt object (is_corrupt=1) is cleaned up successfully ─────────────
//
// DELETE must succeed even for rows flagged is_corrupt=1. The corruption that
// prevents Get/Head from serving the object must not block DELETE from cleaning
// it up. Per operations-runbook.md section 5.1.

func TestDeleteObject_CorruptObject_Succeeds(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)

	const fakePath = "/tmp/hemmins-test-del-corrupt-abc999/obj.blob"
	insertObjectRow(t, db, "my-bucket", "corrupt.txt",
		fakePath, "text/plain", "aabbccdd", "{}", 42, 1 /* is_corrupt=1 */)

	w := doDelete(t, handler, "/my-bucket/corrupt.txt", now)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", w.Code, w.Body.String())
	}
	// Metadata row must be gone.
	if objectRowExists(t, db, "my-bucket", "corrupt.txt") {
		t.Error("corrupt object row still present after DELETE")
	}
}

// ── 10b. Missing blob (blob file gone, row present) → 204, no path leak ──────
//
// If the blob is already absent at DELETE time (e.g. crashed mid-delete previously
// or startup recovery removed it), the handler must still return 204 after cleaning
// up the metadata row. No raw filesystem path must appear in the response.

func TestDeleteObject_MissingBlob_Succeeds(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)

	const missingPath = "/tmp/hemmins-test-del-missing-xyz321/obj.blob"
	insertObjectRow(t, db, "my-bucket", "missing.txt",
		missingPath, "text/plain", "aabbccdd", "{}", 42, 0 /* is_corrupt=0 */)

	w := doDelete(t, handler, "/my-bucket/missing.txt", now)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", w.Code, w.Body.String())
	}
	// Metadata row must be gone.
	if objectRowExists(t, db, "my-bucket", "missing.txt") {
		t.Error("object row still present after DELETE of missing-blob object")
	}
	// Response must not leak filesystem path or OS error text.
	body := w.Body.String()
	if strings.Contains(body, missingPath) {
		t.Error("response leaks internal storage path")
	}
	if strings.Contains(body, "no such file") {
		t.Error("response leaks OS error message")
	}
}

// ── 11. No internal path leak in error responses ──────────────────────────────

func TestDeleteObject_NoPathLeakOnInternalError(t *testing.T) {
	// This test verifies that even when the DB row has a sensitive path,
	// any error responses produced before or during deletion do not expose it.
	// We use a NoSuchBucket error path which is guaranteed not to touch the blob.
	handler, _ := setupPutObjectServer(t)

	const sensitivePath = "/var/data/sensitive/secret/obj.blob"
	w := doDelete(t, handler, "/no-such-bucket/key.txt", time.Now())

	if strings.Contains(w.Body.String(), sensitivePath) {
		t.Error("response leaks internal storage path")
	}
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ── 12. Router: DELETE /{bucket}/{key...} routes to DeleteObject ──────────────

func TestRouter_DeleteObject_PathMapping(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)
	putObject(t, handler, "/my-bucket/routed.txt", "data", now)

	cases := []struct {
		path       string
		wantStatus int
		desc       string
	}{
		// DELETE /{bucket}/{key} existing object → 204
		{"/my-bucket/routed.txt", http.StatusNoContent, "DELETE /bucket/key → 204"},
		// DELETE /{bucket}/{key} missing key → 204 (idempotent, per s3-compatibility-matrix.md §3)
		{"/my-bucket/no-such-key", http.StatusNoContent, "DELETE /bucket/missing-key → 204 idempotent"},
		// DELETE /{missing-bucket}/{key} → 404 NoSuchBucket
		{"/no-such-bucket/key", http.StatusNotFound, "DELETE /missing-bucket/key → 404"},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			r := makeSignedRequest(t, http.MethodDelete, tc.path, now)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)

			if got := w.Result().StatusCode; got != tc.wantStatus {
				t.Errorf("%s: status = %d, want %d; body: %s",
					tc.desc, got, tc.wantStatus, w.Body.String())
			}
		})
	}
}

// ── 13. Metadata DeleteObject unit test ──────────────────────────────────────

func TestMetadataDeleteObject_NotFound(t *testing.T) {
	db, err := metadata.Open(":memory:")
	if err != nil {
		t.Fatalf("metadata.Open: %v", err)
	}
	defer db.Close()

	_, err = db.SQLDB().Exec(
		"INSERT INTO buckets (name, created_at) VALUES (?, ?)",
		"test-bucket", time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		t.Fatalf("insert bucket: %v", err)
	}

	_, err = db.DeleteObject("test-bucket", "nonexistent-key")
	if !errors.Is(err, metadata.ErrObjectNotFound) {
		t.Errorf("DeleteObject on missing key: got %v, want ErrObjectNotFound", err)
	}
}

func TestMetadataDeleteObject_RemovesRow(t *testing.T) {
	db, err := metadata.Open(":memory:")
	if err != nil {
		t.Fatalf("metadata.Open: %v", err)
	}
	defer db.Close()

	now := time.Now()
	_, err = db.SQLDB().Exec(
		"INSERT INTO buckets (name, created_at) VALUES (?, ?)",
		"test-bucket", now.UTC().Format(time.RFC3339),
	)
	if err != nil {
		t.Fatalf("insert bucket: %v", err)
	}
	_, err = db.SQLDB().Exec(`
		INSERT INTO objects (bucket_id, object_key, size, etag, content_type, storage_path, last_modified, metadata_json)
		VALUES ((SELECT id FROM buckets WHERE name = 'test-bucket'), 'my-key', 42, 'etag', 'text/plain', '/fake/path/obj.blob', ?, '{}')
	`, now.UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("insert object: %v", err)
	}

	storagePath, err := db.DeleteObject("test-bucket", "my-key")
	if err != nil {
		t.Fatalf("DeleteObject: %v", err)
	}
	if storagePath != "/fake/path/obj.blob" {
		t.Errorf("storagePath = %q, want /fake/path/obj.blob", storagePath)
	}

	// Row must be gone.
	var count int
	_ = db.SQLDB().QueryRow(
		"SELECT COUNT(*) FROM objects WHERE object_key = 'my-key'",
	).Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 rows after DeleteObject, got %d", count)
	}
}

func TestMetadataDeleteObject_IgnoresCorruptFlag(t *testing.T) {
	db, err := metadata.Open(":memory:")
	if err != nil {
		t.Fatalf("metadata.Open: %v", err)
	}
	defer db.Close()

	now := time.Now()
	_, err = db.SQLDB().Exec(
		"INSERT INTO buckets (name, created_at) VALUES (?, ?)",
		"test-bucket", now.UTC().Format(time.RFC3339),
	)
	if err != nil {
		t.Fatalf("insert bucket: %v", err)
	}
	_, err = db.SQLDB().Exec(`
		INSERT INTO objects (bucket_id, object_key, size, etag, content_type, storage_path, last_modified, metadata_json, is_corrupt)
		VALUES ((SELECT id FROM buckets WHERE name = 'test-bucket'), 'corrupt-key', 0, 'etag', 'text/plain', '/fake/corrupt.blob', ?, '{}', 1)
	`, now.UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("insert corrupt object: %v", err)
	}

	// DeleteObject must succeed even for is_corrupt=1 rows.
	storagePath, err := db.DeleteObject("test-bucket", "corrupt-key")
	if err != nil {
		t.Fatalf("DeleteObject on corrupt row: %v", err)
	}
	if storagePath != "/fake/corrupt.blob" {
		t.Errorf("storagePath = %q, want /fake/corrupt.blob", storagePath)
	}

	// Row must be removed.
	var count int
	_ = db.SQLDB().QueryRow(
		"SELECT COUNT(*) FROM objects WHERE object_key = 'corrupt-key'",
	).Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 rows after DeleteObject on corrupt row, got %d", count)
	}
}
