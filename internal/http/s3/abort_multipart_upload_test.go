package s3_test

import (
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

// setupAbortServer creates a server configured for AbortMultipartUpload tests.
// All three storage roots are separate TempDirs on the same filesystem.
// Returns the handler, metadata DB, and multipartRoot path.
func setupAbortServer(t *testing.T) (http.Handler, *metadata.DB, string) {
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

// doAbort issues a signed DELETE /{bucket}/{key}?uploadId=X and returns the recorder.
func doAbort(t *testing.T, handler http.Handler, bucket, key, uploadID string, now time.Time) *httptest.ResponseRecorder {
	t.Helper()
	path := fmt.Sprintf("/%s/%s?uploadId=%s", bucket, key, uploadID)
	r := makeSignedRequest(t, http.MethodDelete, path, now)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

// ── 1. abort success → 204 ───────────────────────────────────────────────────

func TestAbortMultipartUpload_Success(t *testing.T) {
	handler, db, multipartRoot := setupAbortServer(t)
	insertBucket(t, db, "test-bucket", time.Now())

	uploadID := createUpload(t, handler, "test-bucket", "to-abort.bin")
	uploadPartBody(t, handler, "test-bucket", "to-abort.bin", 1, uploadID, "part data")

	// Verify staging file exists before abort.
	uploadDir := filepath.Join(multipartRoot, uploadID)
	entries, err := os.ReadDir(uploadDir)
	if err != nil {
		t.Fatalf("ReadDir before abort: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one staging file before abort")
	}

	w := doAbort(t, handler, "test-bucket", "to-abort.bin", uploadID, time.Now())
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", w.Code, w.Body.String())
	}
	// 204 must have no body.
	if w.Body.Len() != 0 {
		t.Errorf("body is not empty: %q", w.Body.String())
	}
}

// ── 2. session row deleted after abort ───────────────────────────────────────

func TestAbortMultipartUpload_SessionRowDeleted(t *testing.T) {
	handler, db, _ := setupAbortServer(t)
	insertBucket(t, db, "test-bucket", time.Now())

	uploadID := createUpload(t, handler, "test-bucket", "row-del.bin")
	w := doAbort(t, handler, "test-bucket", "row-del.bin", uploadID, time.Now())
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", w.Code, w.Body.String())
	}

	var count int
	if err := db.SQLDB().QueryRow(
		"SELECT COUNT(*) FROM multipart_uploads WHERE id = ?", uploadID,
	).Scan(&count); err != nil {
		t.Fatalf("querying multipart_uploads: %v", err)
	}
	if count != 0 {
		t.Errorf("multipart_uploads row count = %d, want 0 after abort", count)
	}
}

// ── 3. multipart_parts rows deleted (CASCADE) after abort ────────────────────

func TestAbortMultipartUpload_PartsRowsDeleted(t *testing.T) {
	handler, db, _ := setupAbortServer(t)
	insertBucket(t, db, "test-bucket", time.Now())

	uploadID := createUpload(t, handler, "test-bucket", "parts-del.bin")
	uploadPartBody(t, handler, "test-bucket", "parts-del.bin", 1, uploadID, "part 1")
	uploadPartBody(t, handler, "test-bucket", "parts-del.bin", 2, uploadID, "part 2")

	w := doAbort(t, handler, "test-bucket", "parts-del.bin", uploadID, time.Now())
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", w.Code, w.Body.String())
	}

	var count int
	if err := db.SQLDB().QueryRow(
		"SELECT COUNT(*) FROM multipart_parts WHERE upload_id = ?", uploadID,
	).Scan(&count); err != nil {
		t.Fatalf("querying multipart_parts: %v", err)
	}
	if count != 0 {
		t.Errorf("multipart_parts row count = %d, want 0 after abort (CASCADE)", count)
	}
}

// ── 4+5. staging files and upload directory cleaned up after abort ────────────

func TestAbortMultipartUpload_StagingFilesCleanup(t *testing.T) {
	handler, db, multipartRoot := setupAbortServer(t)
	insertBucket(t, db, "test-bucket", time.Now())

	uploadID := createUpload(t, handler, "test-bucket", "stage-clean.bin")
	uploadPartBody(t, handler, "test-bucket", "stage-clean.bin", 1, uploadID, "content")

	// Both staging file and upload dir must exist before abort.
	uploadDir := filepath.Join(multipartRoot, uploadID)
	entries, err := os.ReadDir(uploadDir)
	if err != nil {
		t.Fatalf("ReadDir before abort: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one staging file before abort")
	}

	w := doAbort(t, handler, "test-bucket", "stage-clean.bin", uploadID, time.Now())
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", w.Code, w.Body.String())
	}

	// After abort: upload directory must be empty or not exist.
	entries2, err2 := os.ReadDir(uploadDir)
	if err2 != nil && !os.IsNotExist(err2) {
		t.Fatalf("ReadDir after abort: %v", err2)
	}
	if err2 == nil && len(entries2) > 0 {
		t.Errorf("upload dir %q still has %d entries after abort; staging files not cleaned",
			uploadDir, len(entries2))
	}
}

// ── 6. empty uploadId in query string → 400 InvalidRequest ───────────────────
//
// When ?uploadId= (empty value) is present, the router dispatches to
// AbortMultipartUpload (Has("uploadId") == true) but the handler returns 400
// because the value is empty. Note: a completely absent ?uploadId routes to
// DeleteObject instead (tested in test 11).

func TestAbortMultipartUpload_EmptyUploadID(t *testing.T) {
	handler, db, _ := setupAbortServer(t)
	insertBucket(t, db, "test-bucket", time.Now())

	r := makeSignedRequest(t, http.MethodDelete, "/test-bucket/key.bin?uploadId=", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "InvalidRequest" {
		t.Errorf("error code = %q, want InvalidRequest", code)
	}
}

// ── 7. nonexistent uploadId → 404 NoSuchUpload ───────────────────────────────

func TestAbortMultipartUpload_NonexistentUploadID(t *testing.T) {
	handler, db, _ := setupAbortServer(t)
	insertBucket(t, db, "test-bucket", time.Now())

	w := doAbort(t, handler, "test-bucket", "key.bin", "nonexistent-upload-id", time.Now())
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "NoSuchUpload" {
		t.Errorf("error code = %q, want NoSuchUpload", code)
	}
}

// ── 8. bucket/key mismatch → 404 NoSuchUpload ────────────────────────────────

func TestAbortMultipartUpload_BucketKeyMismatch(t *testing.T) {
	handler, db, _ := setupAbortServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	// Session is for test-bucket/real-key.bin; request uses wrong-bucket.
	insertSession(t, db, "upload-mismatch", "test-bucket", "real-key.bin",
		time.Now().Add(24*time.Hour))

	w := doAbort(t, handler, "test-bucket", "wrong-key.bin", "upload-mismatch", time.Now())
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "NoSuchUpload" {
		t.Errorf("error code = %q, want NoSuchUpload", code)
	}
}

// ── 9. unauthenticated → 403 AccessDenied ────────────────────────────────────

func TestAbortMultipartUpload_NoAuth(t *testing.T) {
	handler, db, _ := setupAbortServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	insertSession(t, db, "upload-noauth", "test-bucket", "key.bin",
		time.Now().Add(24*time.Hour))

	r, err := http.NewRequest(http.MethodDelete,
		"http://"+testHost+"/test-bucket/key.bin?uploadId=upload-noauth", nil)
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

// ── 10. key with slashes works ────────────────────────────────────────────────

func TestAbortMultipartUpload_KeyWithSlashes(t *testing.T) {
	handler, db, _ := setupAbortServer(t)
	insertBucket(t, db, "test-bucket", time.Now())

	// Multi-segment key: router must parse a/b/c/file.bin as a single objectKey.
	uploadID := createUpload(t, handler, "test-bucket", "a/b/c/file.bin")
	w := doAbort(t, handler, "test-bucket", "a/b/c/file.bin", uploadID, time.Now())
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", w.Code, w.Body.String())
	}
}

// ── 11. DELETE without ?uploadId still routes to DeleteObject ────────────────

func TestAbortMultipartUpload_DeleteObjectRoutingUnaffected(t *testing.T) {
	handler, db, _ := setupAbortServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	now := time.Now()

	// Write an object so there is something to delete.
	putObject(t, handler, "/test-bucket/existing.txt", "hello", now)

	// DELETE without ?uploadId must route to DeleteObject and return 204.
	w := doDelete(t, handler, "/test-bucket/existing.txt", now)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", w.Code, w.Body.String())
	}
}

// ── 12. expired session → 204 (cleanup policy) ───────────────────────────────
//
// Policy: expired sessions that still exist in the DB are treated as valid abort
// targets. Per operations-runbook.md §4.1: expired sessions are cleaned up via
// the same mechanism as AbortMultipartUpload. Rejecting them with NoSuchUpload
// would prevent cleanup by callers who catch exceptions after session expiry.

func TestAbortMultipartUpload_ExpiredSession(t *testing.T) {
	handler, db, _ := setupAbortServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	// Session expired 1 hour ago; it still exists in the DB.
	insertSession(t, db, "upload-expired", "test-bucket", "expire.bin",
		time.Now().Add(-1*time.Hour))

	// Abort must succeed even though the session is past its expiry.
	w := doAbort(t, handler, "test-bucket", "expire.bin", "upload-expired", time.Now())
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 for expired session; body: %s", w.Code, w.Body.String())
	}

	// Verify the expired session row is now gone.
	var count int
	if err := db.SQLDB().QueryRow(
		"SELECT COUNT(*) FROM multipart_uploads WHERE id = ?", "upload-expired",
	).Scan(&count); err != nil {
		t.Fatalf("querying multipart_uploads: %v", err)
	}
	if count != 0 {
		t.Errorf("expired session row count = %d, want 0 after abort", count)
	}
}

// ── 13. existing multipart handlers remain unaffected ────────────────────────

func TestAbortMultipartUpload_ExistingHandlersUnaffected(t *testing.T) {
	handler, db, _ := setupAbortServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	now := time.Now()

	// CreateMultipartUpload still works.
	uploadID := createUpload(t, handler, "test-bucket", "mp-obj.bin")
	if uploadID == "" {
		t.Fatal("createUpload returned empty uploadID")
	}

	// UploadPart still works.
	etag1 := uploadPartBody(t, handler, "test-bucket", "mp-obj.bin", 1, uploadID, "part data")
	if etag1 == "" {
		t.Fatal("uploadPartBody returned empty ETag")
	}

	// ListParts still works.
	wl := doListParts(t, handler, "test-bucket", "mp-obj.bin", uploadID, now)
	if wl.Code != http.StatusOK {
		t.Fatalf("ListParts status = %d, want 200; body: %s", wl.Code, wl.Body.String())
	}

	// CompleteMultipartUpload with nonexistent uploadId still returns 404 NoSuchUpload.
	wne := doComplete(t, handler, "test-bucket", "mp-obj.bin", "nonexistent-id",
		[]completePartSpec{{1, `"abc"`}}, now)
	if wne.Code != http.StatusNotFound {
		t.Errorf("nonexistent uploadId: status = %d, want 404; body: %s", wne.Code, wne.Body.String())
	}
	if code := xmlErrorCode(t, wne.Body.Bytes()); code != "NoSuchUpload" {
		t.Errorf("error code = %q, want NoSuchUpload", code)
	}

	// AbortMultipartUpload on the session just created must return 204.
	wa := doAbort(t, handler, "test-bucket", "mp-obj.bin", uploadID, now)
	if wa.Code != http.StatusNoContent {
		t.Fatalf("Abort status = %d, want 204; body: %s", wa.Code, wa.Body.String())
	}

	// After abort, another ListParts on the same uploadId must return 404 NoSuchUpload.
	wla := doListParts(t, handler, "test-bucket", "mp-obj.bin", uploadID, now)
	if wla.Code != http.StatusNotFound {
		t.Errorf("ListParts after abort: status = %d, want 404; body: %s", wla.Code, wla.Body.String())
	}
	if code := xmlErrorCode(t, wla.Body.Bytes()); code != "NoSuchUpload" {
		t.Errorf("error code = %q, want NoSuchUpload", code)
	}
}
