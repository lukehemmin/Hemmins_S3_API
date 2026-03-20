package s3_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// doHead performs a signed HEAD request and returns the recorder result.
func doHead(t *testing.T, handler http.Handler, path string, now time.Time) *httptest.ResponseRecorder {
	t.Helper()
	r := makeSignedRequest(t, http.MethodHead, path, now)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

// ── 1. HEAD existing object returns 200 ──────────────────────────────────────

func TestHeadObject_Success(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)
	putObject(t, handler, "/my-bucket/hello.txt", "hello, world", now)

	w := doHead(t, handler, "/my-bucket/hello.txt", now)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

// ── 2. Missing key returns 404 NoSuchKey ─────────────────────────────────────

func TestHeadObject_NoSuchKey(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	insertBucket(t, db, "my-bucket", time.Now())
	// No object inserted.

	w := doHead(t, handler, "/my-bucket/missing-key.txt", time.Now())

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", w.Code, w.Body.String())
	}
	// HEAD responses have no body per RFC, but httptest.ResponseRecorder holds
	// the XML writeError output — we can still parse it.
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "NoSuchKey" {
		t.Errorf("error code = %q, want NoSuchKey", code)
	}
}

// ── 3. Missing bucket returns 404 NoSuchBucket ───────────────────────────────

func TestHeadObject_NoSuchBucket(t *testing.T) {
	handler, _ := setupPutObjectServer(t)
	// No bucket inserted.

	w := doHead(t, handler, "/missing-bucket/key.txt", time.Now())

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "NoSuchBucket" {
		t.Errorf("error code = %q, want NoSuchBucket", code)
	}
}

// ── 4. Unauthenticated HEAD returns 403 AccessDenied ─────────────────────────

func TestHeadObject_Unauthenticated(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	insertBucket(t, db, "my-bucket", time.Now())

	r, _ := http.NewRequest(http.MethodHead, "http://"+testHost+"/my-bucket/key.txt", nil)
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

func TestHeadObject_KeyWithSlashes(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)
	putObject(t, handler, "/my-bucket/folder/sub/file.dat", "content", now)

	w := doHead(t, handler, "/my-bucket/folder/sub/file.dat", now)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

// ── 6. Zero-byte object HEAD success ─────────────────────────────────────────

func TestHeadObject_ZeroByteObject(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)
	putObject(t, handler, "/my-bucket/empty.bin", "", now)

	w := doHead(t, handler, "/my-bucket/empty.bin", now)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	// Content-Length must be 0 for a zero-byte object.
	if cl := w.Result().Header.Get("Content-Length"); cl != "0" {
		t.Errorf("Content-Length = %q, want 0", cl)
	}
}

// ── 7. Content-Type is restored ──────────────────────────────────────────────

func TestHeadObject_ContentTypeRestored(t *testing.T) {
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

	w := doHead(t, handler, "/my-bucket/page.html", now)

	if w.Code != http.StatusOK {
		t.Fatalf("HEAD: status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if ct := w.Result().Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/html; charset=utf-8", ct)
	}
}

// ── 8. ETag is restored and quoted ───────────────────────────────────────────

func TestHeadObject_ETagRestoredAndQuoted(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)

	const body = "etag head test"
	putObject(t, handler, "/my-bucket/etag.txt", body, now)

	w := doHead(t, handler, "/my-bucket/etag.txt", now)

	if w.Code != http.StatusOK {
		t.Fatalf("HEAD: status = %d, want 200", w.Code)
	}
	wantETag := `"` + md5Hex(body) + `"`
	if got := w.Result().Header.Get("ETag"); got != wantETag {
		t.Errorf("ETag = %q, want %q", got, wantETag)
	}
}

// ── 9. Last-Modified header is present ───────────────────────────────────────

func TestHeadObject_LastModifiedPresent(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)
	putObject(t, handler, "/my-bucket/dated.txt", "content", now)

	w := doHead(t, handler, "/my-bucket/dated.txt", now)

	if w.Code != http.StatusOK {
		t.Fatalf("HEAD: status = %d, want 200", w.Code)
	}
	lm := w.Result().Header.Get("Last-Modified")
	if lm == "" {
		t.Error("Last-Modified header is absent")
	}
	if _, err := http.ParseTime(lm); err != nil {
		t.Errorf("Last-Modified %q is not a valid HTTP date: %v", lm, err)
	}
}

// ── 10. Content-Length is restored ───────────────────────────────────────────

func TestHeadObject_ContentLengthRestored(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)

	const body = "twelve bytes"
	putObject(t, handler, "/my-bucket/sized.txt", body, now)

	w := doHead(t, handler, "/my-bucket/sized.txt", now)

	if w.Code != http.StatusOK {
		t.Fatalf("HEAD: status = %d, want 200", w.Code)
	}
	wantCL := "12"
	if got := w.Result().Header.Get("Content-Length"); got != wantCL {
		t.Errorf("Content-Length = %q, want %q", got, wantCL)
	}
}

// ── 11. x-amz-meta-* headers are restored ────────────────────────────────────

func TestHeadObject_UserMetaRestored(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)

	r := makeSignedPutRequest(t, "/my-bucket/meta.txt", "payload", now)
	r.Header.Set("X-Amz-Meta-Owner", "bob")
	pw := httptest.NewRecorder()
	handler.ServeHTTP(pw, r)
	if pw.Code != http.StatusOK {
		t.Fatalf("PUT: status = %d, want 200", pw.Code)
	}

	w := doHead(t, handler, "/my-bucket/meta.txt", now)

	if w.Code != http.StatusOK {
		t.Fatalf("HEAD: status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if got := w.Result().Header.Get("X-Amz-Meta-Owner"); got != "bob" {
		t.Errorf("X-Amz-Meta-Owner = %q, want bob", got)
	}
}

// ── 12a. is_corrupt=1 → 500 InternalError, no path leak ─────────────────────

func TestHeadObject_CorruptObject_InternalError(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)

	const fakePath = "/tmp/hemmins-test-head-corrupt-abc999/obj.blob"
	insertObjectRow(t, db, "my-bucket", "corrupt.txt",
		fakePath, "text/plain", "aabbccdd", "{}", 42, 1 /* is_corrupt=1 */)

	w := doHead(t, handler, "/my-bucket/corrupt.txt", now)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "InternalError" {
		t.Errorf("error code = %q, want InternalError", code)
	}
	if strings.Contains(w.Body.String(), fakePath) {
		t.Error("response leaks internal storage path")
	}
}

// ── 12b. Missing blob file → 500 InternalError, no path leak ─────────────────

func TestHeadObject_MissingBlob_InternalError(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)

	const missingPath = "/tmp/hemmins-test-head-missing-xyz321/obj.blob"
	insertObjectRow(t, db, "my-bucket", "missing.txt",
		missingPath, "text/plain", "aabbccdd", "{}", 42, 0 /* is_corrupt=0 */)

	w := doHead(t, handler, "/my-bucket/missing.txt", now)

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
		t.Error("response leaks OS error message")
	}
}

// ── 13. Response body must be empty on success ────────────────────────────────

func TestHeadObject_SuccessBodyEmpty(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)
	putObject(t, handler, "/my-bucket/body-check.txt", "some content here", now)

	r := makeSignedRequest(t, http.MethodHead, "/my-bucket/body-check.txt", now)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	// The handler must NOT call w.Write for a HEAD success response.
	// httptest.ResponseRecorder does NOT auto-strip HEAD bodies (unlike the real
	// net/http server), so checking w.Body directly verifies handler correctness.
	body, _ := io.ReadAll(w.Body)
	if len(body) != 0 {
		t.Errorf("HEAD success response has %d body bytes, want 0: %q", len(body), body)
	}
}

// ── 14. Router: HEAD /{bucket}/{key...} routes to HeadObject ─────────────────

func TestRouter_HeadObject_PathMapping(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "my-bucket", now)
	putObject(t, handler, "/my-bucket/routed.txt", "data", now)

	cases := []struct {
		path       string
		wantStatus int
		desc       string
	}{
		// HEAD /{bucket}/{key} existing object → 200
		{"/my-bucket/routed.txt", http.StatusOK, "HEAD /bucket/key → 200"},
		// HEAD /{bucket}/{key} missing key → 404
		{"/my-bucket/no-such-key", http.StatusNotFound, "HEAD /bucket/missing-key → 404"},
		// HEAD /{missing-bucket}/{key} → 404
		{"/no-such-bucket/key", http.StatusNotFound, "HEAD /missing-bucket/key → 404"},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			r := makeSignedRequest(t, http.MethodHead, tc.path, now)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)

			if got := w.Result().StatusCode; got != tc.wantStatus {
				t.Errorf("%s: status = %d, want %d; body: %s",
					tc.desc, got, tc.wantStatus, w.Body.String())
			}
		})
	}
}
