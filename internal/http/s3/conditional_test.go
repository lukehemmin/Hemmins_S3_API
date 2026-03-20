package s3_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// doGetWithHeaders performs a signed GET request with additional headers applied
// after signing. Conditional headers (If-Match etc.) are not signed by the test
// helper so they are added post-signature, matching how real clients behave.
func doGetWithHeaders(t *testing.T, handler http.Handler, path string, extraHeaders map[string]string, now time.Time) *httptest.ResponseRecorder {
	t.Helper()
	r := makeSignedGetRequest(t, path, now)
	for k, v := range extraHeaders {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

// doHeadWithHeaders performs a signed HEAD request with additional headers applied
// after signing.
func doHeadWithHeaders(t *testing.T, handler http.Handler, path string, extraHeaders map[string]string, now time.Time) *httptest.ResponseRecorder {
	t.Helper()
	r := makeSignedRequest(t, http.MethodHead, path, now)
	for k, v := range extraHeaders {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

// setupConditionalTest creates a server, bucket, and object ready for conditional
// header tests. Returns the handler, the object path, and the quoted ETag.
func setupConditionalTest(t *testing.T) (http.Handler, string, string) {
	t.Helper()
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "cond-bucket", now)

	const body = "conditional test payload"
	putObject(t, handler, "/cond-bucket/obj.txt", body, now)

	quotedETag := `"` + md5Hex(body) + `"`
	return handler, "/cond-bucket/obj.txt", quotedETag
}

// httpDateFuture returns an HTTP-format date 24 h after now.
func httpDateFuture(now time.Time) string {
	return now.Add(24 * time.Hour).UTC().Format(http.TimeFormat)
}

// httpDatePast returns an HTTP-format date 24 h before now.
func httpDatePast(now time.Time) string {
	return now.Add(-24 * time.Hour).UTC().Format(http.TimeFormat)
}

// ── 1. GET + If-Match (matching ETag) → 200 OK ───────────────────────────────

func TestGetObject_IfMatch_Success(t *testing.T) {
	handler, path, quotedETag := setupConditionalTest(t)

	w := doGetWithHeaders(t, handler, path, map[string]string{
		"If-Match": quotedETag,
	}, time.Now())

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

// ── 2. GET + If-Match (wrong ETag) → 412 PreconditionFailed ──────────────────

func TestGetObject_IfMatch_Fail_412(t *testing.T) {
	handler, path, _ := setupConditionalTest(t)

	w := doGetWithHeaders(t, handler, path, map[string]string{
		"If-Match": `"000000000000000000000000000000000000"`,
	}, time.Now())

	if w.Code != http.StatusPreconditionFailed {
		t.Fatalf("status = %d, want 412; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "PreconditionFailed" {
		t.Errorf("error code = %q, want PreconditionFailed", code)
	}
}

// ── 3. GET + If-None-Match (matching ETag) → 304 Not Modified, no body ───────

func TestGetObject_IfNoneMatch_Match_304(t *testing.T) {
	handler, path, quotedETag := setupConditionalTest(t)

	w := doGetWithHeaders(t, handler, path, map[string]string{
		"If-None-Match": quotedETag,
	}, time.Now())

	if w.Code != http.StatusNotModified {
		t.Fatalf("status = %d, want 304; body: %s", w.Code, w.Body.String())
	}
	// 304 MUST NOT include a message body (RFC 7232 §4.1).
	if n := w.Body.Len(); n != 0 {
		t.Errorf("304 response body length = %d, want 0", n)
	}
	// ETag header must be present on 304.
	if etag := w.Result().Header.Get("ETag"); etag == "" {
		t.Error("ETag header absent on 304 response")
	}
}

// ── 4. GET + If-None-Match (wrong ETag) → 200 OK ─────────────────────────────

func TestGetObject_IfNoneMatch_NoMatch_200(t *testing.T) {
	handler, path, _ := setupConditionalTest(t)

	w := doGetWithHeaders(t, handler, path, map[string]string{
		"If-None-Match": `"000000000000000000000000000000000000"`,
	}, time.Now())

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

// ── 5. GET + If-Modified-Since (future date) → 304 Not Modified ──────────────

func TestGetObject_IfModifiedSince_NotModified_304(t *testing.T) {
	handler, path, _ := setupConditionalTest(t)
	// Provide a date well in the future: object has NOT been modified since then.
	futureDate := httpDateFuture(time.Now())

	w := doGetWithHeaders(t, handler, path, map[string]string{
		"If-Modified-Since": futureDate,
	}, time.Now())

	if w.Code != http.StatusNotModified {
		t.Fatalf("status = %d, want 304; body: %s", w.Code, w.Body.String())
	}
	if n := w.Body.Len(); n != 0 {
		t.Errorf("304 response body length = %d, want 0", n)
	}
}

// ── 6. GET + If-Modified-Since (past date) → 200 OK ──────────────────────────

func TestGetObject_IfModifiedSince_Modified_200(t *testing.T) {
	handler, path, _ := setupConditionalTest(t)
	// Provide a date well in the past: object WAS modified since then → 200.
	pastDate := httpDatePast(time.Now())

	w := doGetWithHeaders(t, handler, path, map[string]string{
		"If-Modified-Since": pastDate,
	}, time.Now())

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

// ── 7. GET + If-Unmodified-Since (future date) → 200 OK ──────────────────────

func TestGetObject_IfUnmodifiedSince_Success_200(t *testing.T) {
	handler, path, _ := setupConditionalTest(t)
	// Provide a date in the future: object has NOT been modified since then.
	// Condition satisfied → proceed with 200.
	futureDate := httpDateFuture(time.Now())

	w := doGetWithHeaders(t, handler, path, map[string]string{
		"If-Unmodified-Since": futureDate,
	}, time.Now())

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

// ── 8. GET + If-Unmodified-Since (past date) → 412 PreconditionFailed ────────

func TestGetObject_IfUnmodifiedSince_Fail_412(t *testing.T) {
	handler, path, _ := setupConditionalTest(t)
	// Provide a date well in the past: object WAS modified since then → 412.
	pastDate := httpDatePast(time.Now())

	w := doGetWithHeaders(t, handler, path, map[string]string{
		"If-Unmodified-Since": pastDate,
	}, time.Now())

	if w.Code != http.StatusPreconditionFailed {
		t.Fatalf("status = %d, want 412; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "PreconditionFailed" {
		t.Errorf("error code = %q, want PreconditionFailed", code)
	}
}

// ── 9. HEAD + If-None-Match (matching ETag) → 304, no body ───────────────────

func TestHeadObject_IfNoneMatch_Match_304(t *testing.T) {
	handler, path, quotedETag := setupConditionalTest(t)

	w := doHeadWithHeaders(t, handler, path, map[string]string{
		"If-None-Match": quotedETag,
	}, time.Now())

	if w.Code != http.StatusNotModified {
		t.Fatalf("status = %d, want 304; body: %s", w.Code, w.Body.String())
	}
	// HEAD 304: no body was written by the handler (only WriteHeader is called).
	if n := w.Body.Len(); n != 0 {
		t.Errorf("HEAD 304 body length = %d, want 0", n)
	}
}

// ── 10. HEAD + If-Match (wrong ETag) → 412, no blob body ─────────────────────

func TestHeadObject_IfMatch_Fail_412(t *testing.T) {
	handler, path, _ := setupConditionalTest(t)

	w := doHeadWithHeaders(t, handler, path, map[string]string{
		"If-Match": `"000000000000000000000000000000000000"`,
	}, time.Now())

	if w.Code != http.StatusPreconditionFailed {
		t.Fatalf("status = %d, want 412; body: %s", w.Code, w.Body.String())
	}
	// Note: writeError writes an XML body to the recorder; in real HTTP the
	// net/http server discards it for HEAD requests automatically. We verify
	// the status code here, which is the observable outcome.
}

// ── 11. GET + If-None-Match: * → 304 Not Modified ────────────────────────────

func TestGetObject_IfNoneMatch_Wildcard_304(t *testing.T) {
	handler, path, _ := setupConditionalTest(t)

	w := doGetWithHeaders(t, handler, path, map[string]string{
		"If-None-Match": "*",
	}, time.Now())

	if w.Code != http.StatusNotModified {
		t.Fatalf("status = %d, want 304; body: %s", w.Code, w.Body.String())
	}
}

// ── 12. GET + If-Match: * → 200 OK ───────────────────────────────────────────

func TestGetObject_IfMatch_Wildcard_200(t *testing.T) {
	handler, path, _ := setupConditionalTest(t)

	w := doGetWithHeaders(t, handler, path, map[string]string{
		"If-Match": "*",
	}, time.Now())

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

// ── 13. GET + invalid date in If-Modified-Since → ignored → 200 ──────────────

func TestGetObject_InvalidDate_Ignored_200(t *testing.T) {
	handler, path, _ := setupConditionalTest(t)

	w := doGetWithHeaders(t, handler, path, map[string]string{
		"If-Modified-Since": "not-a-date-at-all",
	}, time.Now())

	// Unparseable date must be silently ignored; request proceeds normally.
	// Per conditional.go policy: "treat as absent".
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (invalid date ignored); body: %s",
			w.Code, w.Body.String())
	}
}

// ── 14. GET + If-None-Match match + Range → 304 (condition checked first) ────

func TestGetObject_IfNoneMatch_WithRange_304(t *testing.T) {
	handler, path, quotedETag := setupConditionalTest(t)

	// Both Range and If-None-Match set. Conditional check happens before Range
	// parsing, so 304 must be returned regardless of the Range header.
	w := doGetWithHeaders(t, handler, path, map[string]string{
		"If-None-Match": quotedETag,
		"Range":         "bytes=0-3",
	}, time.Now())

	if w.Code != http.StatusNotModified {
		t.Fatalf("status = %d, want 304; body: %s", w.Code, w.Body.String())
	}
	if n := w.Body.Len(); n != 0 {
		t.Errorf("304 body length = %d, want 0", n)
	}
}

// ── 15. GET 304 response includes ETag and Last-Modified headers ──────────────

func TestGetObject_304_ValidationHeaders(t *testing.T) {
	handler, path, quotedETag := setupConditionalTest(t)

	w := doGetWithHeaders(t, handler, path, map[string]string{
		"If-None-Match": quotedETag,
	}, time.Now())

	if w.Code != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", w.Code)
	}
	resp := w.Result()
	if got := resp.Header.Get("ETag"); got != quotedETag {
		t.Errorf("304 ETag = %q, want %q", got, quotedETag)
	}
	if lm := resp.Header.Get("Last-Modified"); lm == "" {
		t.Error("304 Last-Modified header absent")
	}
	// Content-Length must NOT be set on 304 (no body).
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		t.Errorf("304 Content-Length = %q, want absent", cl)
	}
}

// ── 16. GET + If-Match takes precedence over If-Unmodified-Since ─────────────
// When both are present: If-Match succeeds → If-Unmodified-Since is skipped
// even if the date condition would fail. (RFC 7232 §6 step 2 prerequisite)

func TestGetObject_IfMatch_Precedence_Over_IfUnmodifiedSince(t *testing.T) {
	handler, path, quotedETag := setupConditionalTest(t)

	// If-Match matches (good) + If-Unmodified-Since is in the past (would 412).
	// Per RFC 7232 §6: If-Match takes precedence; If-Unmodified-Since is skipped.
	// Result must be 200 OK.
	w := doGetWithHeaders(t, handler, path, map[string]string{
		"If-Match":            quotedETag,
		"If-Unmodified-Since": httpDatePast(time.Now()),
	}, time.Now())

	if w.Code != http.StatusOK {
		b, _ := io.ReadAll(w.Result().Body)
		t.Fatalf("status = %d, want 200; body: %s", w.Code, b)
	}
}
