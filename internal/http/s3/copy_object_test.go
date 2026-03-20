package s3_test

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// doCopy performs a signed PUT request with X-Amz-Copy-Source set, and any
// additional headers supplied via the headers map. This is the minimal helper
// for CopyObject; callers that need metadata-directive or x-amz-meta-* headers
// pass them through headers.
func doCopy(t *testing.T, handler http.Handler, dstPath, srcPath string, headers map[string]string, now time.Time) *httptest.ResponseRecorder {
	t.Helper()
	r := makeSignedRequest(t, http.MethodPut, dstPath, now)
	r.Header.Set("X-Amz-Copy-Source", srcPath)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

// parseCopyResult unmarshals a CopyObjectResult XML body.
func parseCopyResult(t *testing.T, body []byte) (etag, lastModified string) {
	t.Helper()
	var result struct {
		ETag         string `xml:"ETag"`
		LastModified string `xml:"LastModified"`
	}
	if err := xml.Unmarshal(body, &result); err != nil {
		t.Fatalf("xml.Unmarshal CopyObjectResult: %v\nbody: %s", err, body)
	}
	return result.ETag, result.LastModified
}

// ── 1. Same-bucket different-key copy success ─────────────────────────────────

func TestCopyObject_SameBucket_Success(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)
	putObject(t, handler, "/my-bucket/src.txt", "copy me", now)

	w := doCopy(t, handler, "/my-bucket/dst.txt", "/my-bucket/src.txt", nil, now)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

// ── 2. Cross-bucket copy success ─────────────────────────────────────────────

func TestCopyObject_CrossBucket_Success(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "src-bucket", now)
	insertBucket(t, db, "dst-bucket", now)
	putObject(t, handler, "/src-bucket/file.txt", "cross-bucket content", now)

	w := doCopy(t, handler, "/dst-bucket/file.txt", "/src-bucket/file.txt", nil, now)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

// ── 3. Source bucket missing → 404 NoSuchBucket ───────────────────────────────

func TestCopyObject_SourceBucketMissing(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "dst-bucket", now)
	// Source bucket "ghost-bucket" does not exist.

	w := doCopy(t, handler, "/dst-bucket/dst.txt", "/ghost-bucket/src.txt", nil, now)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "NoSuchBucket" {
		t.Errorf("error code = %q, want NoSuchBucket", code)
	}
}

// ── 4. Source key missing → 404 NoSuchKey ────────────────────────────────────

func TestCopyObject_SourceKeyMissing(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "src-bucket", now)
	insertBucket(t, db, "dst-bucket", now)
	// No object inserted in src-bucket.

	w := doCopy(t, handler, "/dst-bucket/dst.txt", "/src-bucket/ghost.txt", nil, now)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "NoSuchKey" {
		t.Errorf("error code = %q, want NoSuchKey", code)
	}
}

// ── 5. Destination bucket missing → 404 NoSuchBucket ─────────────────────────

func TestCopyObject_DestBucketMissing(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "src-bucket", now)
	putObject(t, handler, "/src-bucket/file.txt", "content", now)
	// Destination bucket "ghost-dst" does not exist.

	w := doCopy(t, handler, "/ghost-dst/dst.txt", "/src-bucket/file.txt", nil, now)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "NoSuchBucket" {
		t.Errorf("error code = %q, want NoSuchBucket", code)
	}
}

// ── 6. Unauthenticated copy → 403 AccessDenied ───────────────────────────────

func TestCopyObject_Unauthenticated(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)
	putObject(t, handler, "/my-bucket/src.txt", "content", now)

	// Build an unsigned PUT request with X-Amz-Copy-Source.
	r, _ := http.NewRequest(http.MethodPut, "http://"+testHost+"/my-bucket/dst.txt", nil)
	r.Host = testHost
	r.Header.Set("X-Amz-Copy-Source", "/my-bucket/src.txt")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "AccessDenied" {
		t.Errorf("error code = %q, want AccessDenied", code)
	}
}

// ── 7. Object key with slashes copies correctly ───────────────────────────────

func TestCopyObject_KeyWithSlashes(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)
	const body = "deep nested content"
	putObject(t, handler, "/my-bucket/folder/sub/file.dat", body, now)

	w := doCopy(t, handler, "/my-bucket/copy/of/file.dat",
		"/my-bucket/folder/sub/file.dat", nil, now)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	// Verify the copy is retrievable.
	gw := doGet(t, handler, "/my-bucket/copy/of/file.dat", now)
	if gw.Code != http.StatusOK {
		t.Fatalf("GET copy: status = %d, want 200; body: %s", gw.Code, gw.Body.String())
	}
	if got := gw.Body.String(); got != body {
		t.Errorf("GET copy body = %q, want %q", got, body)
	}
}

// ── 8. Copied body matches source ────────────────────────────────────────────

func TestCopyObject_BodyMatchesSource(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)

	const body = "the quick brown fox jumps over the lazy dog"
	putObject(t, handler, "/my-bucket/src.txt", body, now)

	doCopy(t, handler, "/my-bucket/dst.txt", "/my-bucket/src.txt", nil, now)

	gw := doGet(t, handler, "/my-bucket/dst.txt", now)
	if gw.Code != http.StatusOK {
		t.Fatalf("GET copy: status = %d, want 200; body: %s", gw.Code, gw.Body.String())
	}
	if got := gw.Body.String(); got != body {
		t.Errorf("GET copy body = %q, want %q", got, body)
	}
}

// ── 9. Copied object GET works end-to-end ────────────────────────────────────

func TestCopyObject_EndToEnd(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "src-bucket", now)
	insertBucket(t, db, "dst-bucket", now)

	const body = "end-to-end copy test"
	wantETag := `"` + md5Hex(body) + `"`

	// PUT source with custom Content-Type.
	pr := makeSignedPutRequest(t, "/src-bucket/orig.txt", body, now)
	pr.Header.Set("Content-Type", "text/plain; charset=utf-8")
	pw := httptest.NewRecorder()
	handler.ServeHTTP(pw, pr)
	if pw.Code != http.StatusOK {
		t.Fatalf("PUT: status = %d, want 200", pw.Code)
	}

	// COPY.
	cw := doCopy(t, handler, "/dst-bucket/copy.txt", "/src-bucket/orig.txt", nil, now)
	if cw.Code != http.StatusOK {
		t.Fatalf("COPY: status = %d, want 200; body: %s", cw.Code, cw.Body.String())
	}

	// GET the copy.
	gw := doGet(t, handler, "/dst-bucket/copy.txt", now)
	if gw.Code != http.StatusOK {
		t.Fatalf("GET copy: status = %d, want 200; body: %s", gw.Code, gw.Body.String())
	}
	resp := gw.Result()
	gotBody, _ := io.ReadAll(resp.Body)
	if string(gotBody) != body {
		t.Errorf("body = %q, want %q", string(gotBody), body)
	}
	if got := resp.Header.Get("ETag"); got != wantETag {
		t.Errorf("ETag = %q, want %q", got, wantETag)
	}
}

// ── 10. Success response XML contains quoted ETag and LastModified ────────────

func TestCopyObject_SuccessResponse_XML(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)

	const body = "xml response test"
	wantETag := `"` + md5Hex(body) + `"`
	putObject(t, handler, "/my-bucket/src.txt", body, now)

	w := doCopy(t, handler, "/my-bucket/dst.txt", "/my-bucket/src.txt", nil, now)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if ct := w.Result().Header.Get("Content-Type"); ct != "application/xml" {
		t.Errorf("Content-Type = %q, want application/xml", ct)
	}

	etag, lastMod := parseCopyResult(t, w.Body.Bytes())
	if etag != wantETag {
		t.Errorf("XML ETag = %q, want %q", etag, wantETag)
	}
	if lastMod == "" {
		t.Error("XML LastModified is empty")
	}
	// LastModified must be in S3 ISO 8601 format (e.g., "2024-01-01T00:00:00.000Z").
	if !strings.HasSuffix(lastMod, "Z") {
		t.Errorf("XML LastModified %q does not end with Z", lastMod)
	}
}

// ── 11. Metadata-directive COPY preserves Content-Type and x-amz-meta-* ───────

func TestCopyObject_MetadataDirective_COPY(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)

	// PUT with custom Content-Type and user metadata.
	pr := makeSignedPutRequest(t, "/my-bucket/src.txt", "content", now)
	pr.Header.Set("Content-Type", "text/html; charset=utf-8")
	pr.Header.Set("X-Amz-Meta-Author", "alice")
	pr.Header.Set("X-Amz-Meta-Project", "test")
	pw := httptest.NewRecorder()
	handler.ServeHTTP(pw, pr)
	if pw.Code != http.StatusOK {
		t.Fatalf("PUT: status = %d, want 200", pw.Code)
	}

	// COPY with directive COPY (default — also test explicit header).
	w := doCopy(t, handler, "/my-bucket/dst.txt", "/my-bucket/src.txt",
		map[string]string{"X-Amz-Metadata-Directive": "COPY"}, now)
	if w.Code != http.StatusOK {
		t.Fatalf("COPY: status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	// GET the copy and verify preserved metadata.
	gw := doGet(t, handler, "/my-bucket/dst.txt", now)
	if gw.Code != http.StatusOK {
		t.Fatalf("GET copy: status = %d, want 200", gw.Code)
	}
	resp := gw.Result()
	if ct := resp.Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/html; charset=utf-8", ct)
	}
	if got := resp.Header.Get("X-Amz-Meta-Author"); got != "alice" {
		t.Errorf("X-Amz-Meta-Author = %q, want alice", got)
	}
	if got := resp.Header.Get("X-Amz-Meta-Project"); got != "test" {
		t.Errorf("X-Amz-Meta-Project = %q, want test", got)
	}
}

// ── 12. Metadata-directive REPLACE replaces Content-Type and x-amz-meta-* ────

func TestCopyObject_MetadataDirective_REPLACE(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)

	// PUT with original metadata.
	pr := makeSignedPutRequest(t, "/my-bucket/src.txt", "content", now)
	pr.Header.Set("Content-Type", "text/html; charset=utf-8")
	pr.Header.Set("X-Amz-Meta-Author", "alice")
	pw := httptest.NewRecorder()
	handler.ServeHTTP(pw, pr)
	if pw.Code != http.StatusOK {
		t.Fatalf("PUT: status = %d, want 200", pw.Code)
	}

	// COPY with REPLACE directive: provide new Content-Type and metadata.
	w := doCopy(t, handler, "/my-bucket/dst.txt", "/my-bucket/src.txt",
		map[string]string{
			"X-Amz-Metadata-Directive": "REPLACE",
			"Content-Type":             "application/json",
			"X-Amz-Meta-Author":        "bob",
		}, now)
	if w.Code != http.StatusOK {
		t.Fatalf("COPY REPLACE: status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	// GET the copy and verify new metadata.
	gw := doGet(t, handler, "/my-bucket/dst.txt", now)
	if gw.Code != http.StatusOK {
		t.Fatalf("GET copy: status = %d, want 200", gw.Code)
	}
	resp := gw.Result()
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if got := resp.Header.Get("X-Amz-Meta-Author"); got != "bob" {
		t.Errorf("X-Amz-Meta-Author = %q, want bob (REPLACE should override)", got)
	}

	// Body content must still match the source blob.
	gotBody, _ := io.ReadAll(resp.Body)
	if string(gotBody) != "content" {
		t.Errorf("body = %q, want \"content\"", string(gotBody))
	}

	// ETag must match source since blob is identical.
	wantETag := `"` + md5Hex("content") + `"`
	if got := resp.Header.Get("ETag"); got != wantETag {
		t.Errorf("ETag = %q, want %q", got, wantETag)
	}
}

// ── 13. Invalid metadata-directive value → 400 InvalidArgument ────────────────

func TestCopyObject_InvalidMetadataDirective(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)
	putObject(t, handler, "/my-bucket/src.txt", "content", now)

	cases := []string{"MERGE", "DELETE", "copy", "replace", ""}
	for _, directive := range cases {
		if directive == "" {
			continue // empty is valid (defaults to COPY)
		}
		t.Run(directive, func(t *testing.T) {
			w := doCopy(t, handler, "/my-bucket/dst.txt", "/my-bucket/src.txt",
				map[string]string{"X-Amz-Metadata-Directive": directive}, now)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("directive=%q: status = %d, want 400; body: %s",
					directive, w.Code, w.Body.String())
			}
			if code := xmlErrorCode(t, w.Body.Bytes()); code != "InvalidArgument" {
				t.Errorf("directive=%q: error code = %q, want InvalidArgument", directive, code)
			}
		})
	}
}

// ── 14a. Corrupt source (is_corrupt=1) → 500 InternalError, no path leak ─────

func TestCopyObject_CorruptSource_InternalError(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "src-bucket", now)
	insertBucket(t, db, "dst-bucket", now)

	const fakePath = "/tmp/hemmins-copy-test-corrupt-xyz/obj.blob"
	insertObjectRow(t, db, "src-bucket", "corrupt.txt",
		fakePath, "text/plain", "aabbccdd", "{}", 42, 1 /* is_corrupt=1 */)

	w := doCopy(t, handler, "/dst-bucket/dst.txt", "/src-bucket/corrupt.txt", nil, now)

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
	if strings.Contains(w.Body.String(), "hemmins-copy-test-corrupt") {
		t.Error("response leaks internal path fragment")
	}
}

// ── 14b. Missing source blob (is_corrupt=0, file absent) → 500 InternalError ──

func TestCopyObject_MissingSourceBlob_InternalError(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "src-bucket", now)
	insertBucket(t, db, "dst-bucket", now)

	// Valid metadata row but the blob file does not exist on disk.
	const missingPath = "/tmp/hemmins-copy-test-missing-blob-abc/obj.blob"
	insertObjectRow(t, db, "src-bucket", "missing.txt",
		missingPath, "text/plain", "aabbccdd", "{}", 42, 0 /* is_corrupt=0 */)

	w := doCopy(t, handler, "/dst-bucket/dst.txt", "/src-bucket/missing.txt", nil, now)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "InternalError" {
		t.Errorf("error code = %q, want InternalError", code)
	}
	if strings.Contains(w.Body.String(), missingPath) {
		t.Error("response leaks internal storage path")
	}
	if strings.Contains(w.Body.String(), "no such file") {
		t.Error("response leaks OS error details")
	}
}

// ── 15. Existing PutObject remains unaffected (PUT without copy-source header) ─

func TestCopyObject_PutObjectUnaffected(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)

	// Regular PUT without X-Amz-Copy-Source must still work as PutObject.
	r := makeSignedPutRequest(t, "/my-bucket/regular.txt", "plain upload", now)
	// Explicitly do NOT set X-Amz-Copy-Source.
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("regular PUT: status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	// Verify the object is retrievable.
	gw := doGet(t, handler, "/my-bucket/regular.txt", now)
	if gw.Code != http.StatusOK {
		t.Fatalf("GET after PUT: status = %d, want 200", gw.Code)
	}
	if got := gw.Body.String(); got != "plain upload" {
		t.Errorf("GET body = %q, want \"plain upload\"", got)
	}
}

// ── 16. CopyObject with metadata DB: source and destination are independent ───
// After copy, deleting the source does not affect the copy's blob.

func TestCopyObject_Independence(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)
	putObject(t, handler, "/my-bucket/src.txt", "original content", now)

	// Copy.
	cw := doCopy(t, handler, "/my-bucket/dst.txt", "/my-bucket/src.txt", nil, now)
	if cw.Code != http.StatusOK {
		t.Fatalf("COPY: status = %d, want 200", cw.Code)
	}

	// Delete the source.
	dr := makeSignedRequest(t, http.MethodDelete, "/my-bucket/src.txt", now)
	dw := httptest.NewRecorder()
	handler.ServeHTTP(dw, dr)
	if dw.Code != http.StatusNoContent {
		t.Fatalf("DELETE src: status = %d, want 204", dw.Code)
	}

	// Source should be gone.
	gw := doGet(t, handler, "/my-bucket/src.txt", now)
	if gw.Code != http.StatusNotFound {
		t.Fatalf("GET src after DELETE: status = %d, want 404", gw.Code)
	}

	// Copy should still be accessible with correct content.
	gw2 := doGet(t, handler, "/my-bucket/dst.txt", now)
	if gw2.Code != http.StatusOK {
		t.Fatalf("GET dst after src DELETE: status = %d, want 200; body: %s",
			gw2.Code, gw2.Body.String())
	}
	if got := gw2.Body.String(); got != "original content" {
		t.Errorf("GET dst body = %q, want \"original content\"", got)
	}
}

// ── 17. Router test: metadata DB records copy as separate object ──────────────

func TestCopyObject_RouterPathMapping(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)
	putObject(t, handler, "/my-bucket/src.txt", "value", now)

	// CopyObject is dispatched via PUT with x-amz-copy-source header.
	w := doCopy(t, handler, "/my-bucket/dst.txt", "/my-bucket/src.txt", nil, now)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	// Verify via metadata: both src and dst exist in DB.
	_, err := db.GetObjectByKey("my-bucket", "src.txt")
	if err != nil {
		t.Errorf("GetObjectByKey(src.txt): %v (should still exist)", err)
	}
	_, err = db.GetObjectByKey("my-bucket", "dst.txt")
	if err != nil {
		t.Errorf("GetObjectByKey(dst.txt): %v (copy should exist)", err)
	}
}
