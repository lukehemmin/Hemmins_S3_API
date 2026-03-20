package s3_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// doGetWithRange performs a signed GET request with an optional Range header.
// If rangeHeader is empty no Range header is added (equivalent to doGet).
func doGetWithRange(t *testing.T, handler http.Handler, path, rangeHeader string, now time.Time) *httptest.ResponseRecorder {
	t.Helper()
	r := makeSignedGetRequest(t, path, now)
	if rangeHeader != "" {
		r.Header.Set("Range", rangeHeader)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

// testBody is the shared 10-byte content used across range tests.
// Offsets: 0='a', 1='b', 2='c', 3='d', 4='e', 5='f', 6='g', 7='h', 8='i', 9='j'
const testRangeBody = "abcdefghij"

// setupRangeTest creates a server, bucket, and object ready for Range tests.
// Returns the handler and the object path "/range-bucket/data.bin".
func setupRangeTest(t *testing.T) (http.Handler, string) {
	t.Helper()
	handler, db := setupPutObjectServer(t)
	now := time.Now()
	insertBucket(t, db, "range-bucket", now)
	putObject(t, handler, "/range-bucket/data.bin", testRangeBody, now)
	return handler, "/range-bucket/data.bin"
}

// ── 1. No Range header → 200 OK + Accept-Ranges: bytes ───────────────────────

func TestGetObject_NoRange_AcceptRanges(t *testing.T) {
	handler, path := setupRangeTest(t)

	w := doGetWithRange(t, handler, path, "", time.Now())

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if ar := w.Result().Header.Get("Accept-Ranges"); ar != "bytes" {
		t.Errorf("Accept-Ranges = %q, want \"bytes\"", ar)
	}
	if got := w.Body.String(); got != testRangeBody {
		t.Errorf("body = %q, want %q", got, testRangeBody)
	}
}

// ── 2. bytes=2-5 → 206 Partial Content, body "cdef" ─────────────────────────

func TestGetObject_Range_Standard_206(t *testing.T) {
	handler, path := setupRangeTest(t)

	w := doGetWithRange(t, handler, path, "bytes=2-5", time.Now())

	if w.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206; body: %s", w.Code, w.Body.String())
	}
	if got := w.Body.String(); got != "cdef" {
		t.Errorf("body = %q, want \"cdef\"", got)
	}
}

// ── 3. bytes=7- → 206 Partial Content, body "hij" (open-ended) ───────────────

func TestGetObject_Range_OpenEnded_206(t *testing.T) {
	handler, path := setupRangeTest(t)

	w := doGetWithRange(t, handler, path, "bytes=7-", time.Now())

	if w.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206; body: %s", w.Code, w.Body.String())
	}
	if got := w.Body.String(); got != "hij" {
		t.Errorf("body = %q, want \"hij\"", got)
	}
}

// ── 4. bytes=-4 → 206 Partial Content, body "ghij" (suffix) ─────────────────

func TestGetObject_Range_Suffix_206(t *testing.T) {
	handler, path := setupRangeTest(t)

	w := doGetWithRange(t, handler, path, "bytes=-4", time.Now())

	if w.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206; body: %s", w.Code, w.Body.String())
	}
	if got := w.Body.String(); got != "ghij" {
		t.Errorf("body = %q, want \"ghij\"", got)
	}
}

// ── 5. bytes=4-4 → 206 Partial Content, body "e" (single byte) ──────────────

func TestGetObject_Range_SingleByte_206(t *testing.T) {
	handler, path := setupRangeTest(t)

	w := doGetWithRange(t, handler, path, "bytes=4-4", time.Now())

	if w.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206; body: %s", w.Code, w.Body.String())
	}
	if got := w.Body.String(); got != "e" {
		t.Errorf("body = %q, want \"e\"", got)
	}
}

// ── 6. bytes=0-9 → 206 Partial Content, full file content ───────────────────

func TestGetObject_Range_EntireFile_206(t *testing.T) {
	handler, path := setupRangeTest(t)

	w := doGetWithRange(t, handler, path, "bytes=0-9", time.Now())

	if w.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206; body: %s", w.Code, w.Body.String())
	}
	if got := w.Body.String(); got != testRangeBody {
		t.Errorf("body = %q, want %q", got, testRangeBody)
	}
}

// ── 7. Content-Range header is correct on 206 ────────────────────────────────

func TestGetObject_Range_ContentRange_Header(t *testing.T) {
	handler, path := setupRangeTest(t)
	// totalSize = len("abcdefghij") = 10
	const want = "bytes 2-5/10"

	w := doGetWithRange(t, handler, path, "bytes=2-5", time.Now())

	if w.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206; body: %s", w.Code, w.Body.String())
	}
	if got := w.Result().Header.Get("Content-Range"); got != want {
		t.Errorf("Content-Range = %q, want %q", got, want)
	}
}

// ── 8. ETag and Last-Modified are present on 206 ─────────────────────────────

func TestGetObject_Range_ETagAndLastModified_On206(t *testing.T) {
	handler, path := setupRangeTest(t)

	w := doGetWithRange(t, handler, path, "bytes=0-3", time.Now())

	if w.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206; body: %s", w.Code, w.Body.String())
	}
	resp := w.Result()
	if etag := resp.Header.Get("ETag"); etag == "" {
		t.Error("ETag header absent on 206 response")
	}
	if lm := resp.Header.Get("Last-Modified"); lm == "" {
		t.Error("Last-Modified header absent on 206 response")
	}
	// Accept-Ranges must also be present.
	if ar := resp.Header.Get("Accept-Ranges"); ar != "bytes" {
		t.Errorf("Accept-Ranges = %q, want \"bytes\"", ar)
	}
}

// ── 9. Multi-range → 416 RequestedRangeNotSatisfiable ────────────────────────

func TestGetObject_Range_MultiRange_416(t *testing.T) {
	handler, path := setupRangeTest(t)

	w := doGetWithRange(t, handler, path, "bytes=0-1,3-4", time.Now())

	if w.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("status = %d, want 416; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "InvalidRange" {
		t.Errorf("error code = %q, want InvalidRange", code)
	}
}

// ── 10. Start beyond EOF → 416 + Content-Range: bytes */size ─────────────────

func TestGetObject_Range_StartBeyondSize_416(t *testing.T) {
	handler, path := setupRangeTest(t)
	// File is 10 bytes (0-9). bytes=10-20 is beyond the last byte.
	const wantCR = "bytes */10"

	w := doGetWithRange(t, handler, path, "bytes=10-20", time.Now())

	if w.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("status = %d, want 416; body: %s", w.Code, w.Body.String())
	}
	if got := w.Result().Header.Get("Content-Range"); got != wantCR {
		t.Errorf("Content-Range = %q, want %q", got, wantCR)
	}
}

// ── 11. Invalid Range syntax → 416 ───────────────────────────────────────────

func TestGetObject_Range_InvalidSyntax_416(t *testing.T) {
	handler, path := setupRangeTest(t)

	cases := []struct {
		desc        string
		rangeHeader string
	}{
		{"missing bytes= prefix", "0-5"},
		{"non-numeric start", "bytes=abc-def"},
		{"missing dash", "bytes=05"},
		{"empty spec after prefix", "bytes="},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			w := doGetWithRange(t, handler, path, tc.rangeHeader, time.Now())
			if w.Code != http.StatusRequestedRangeNotSatisfiable {
				t.Errorf("%s: status = %d, want 416; body: %s",
					tc.desc, w.Code, w.Body.String())
			}
		})
	}
}

// ── 12. Suffix larger than file → 206, entire file content (clamped) ─────────

func TestGetObject_Range_SuffixLargerThanFile_206(t *testing.T) {
	handler, path := setupRangeTest(t)
	// File is 10 bytes. bytes=-1000 → clamped to bytes=-10 → full file.
	wantCR := fmt.Sprintf("bytes 0-9/10")

	w := doGetWithRange(t, handler, path, "bytes=-1000", time.Now())

	if w.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206; body: %s", w.Code, w.Body.String())
	}
	if got := w.Body.String(); got != testRangeBody {
		t.Errorf("body = %q, want %q", got, testRangeBody)
	}
	if got := w.Result().Header.Get("Content-Range"); got != wantCR {
		t.Errorf("Content-Range = %q, want %q", got, wantCR)
	}
}

// ── 13. Content-Length is correct on 206 ─────────────────────────────────────

func TestGetObject_Range_ContentLength_On206(t *testing.T) {
	handler, path := setupRangeTest(t)
	// bytes=2-5 → 4 bytes ("cdef")

	w := doGetWithRange(t, handler, path, "bytes=2-5", time.Now())

	if w.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206; body: %s", w.Code, w.Body.String())
	}
	if got := w.Result().Header.Get("Content-Length"); got != "4" {
		t.Errorf("Content-Length = %q, want \"4\"", got)
	}
	gotBody, _ := io.ReadAll(w.Result().Body)
	if len(gotBody) != 4 {
		t.Errorf("actual body length = %d, want 4", len(gotBody))
	}
}
