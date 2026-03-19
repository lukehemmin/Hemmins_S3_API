package s3_test

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lukehemmin/hemmins-s3-api/internal/auth"
)

// makePresignRequest builds a valid presigned GET / request signed with testAccessKey/testSecretKey.
// The signing time is set 1 second in the past to avoid the strict not-yet-valid check
// in PresignVerifier.Verify.
func makePresignRequest(t *testing.T, now time.Time) *http.Request {
	t.Helper()
	// Sign 1 second in the past to avoid ErrPresignNotYetValid.
	signedAt := now.Add(-1 * time.Second).UTC()
	date := signedAt.Format("20060102")
	dateTime := signedAt.Format("20060102T150405Z")

	scope := auth.CredentialScope(date, testRegion, "s3")
	credential := testAccessKey + "/" + scope

	// Build query params WITHOUT X-Amz-Signature first.
	params := url.Values{}
	params.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	params.Set("X-Amz-Credential", credential)
	params.Set("X-Amz-Date", dateTime)
	params.Set("X-Amz-Expires", "300")
	params.Set("X-Amz-SignedHeaders", "host")

	rawURL := "http://" + testHost + "/?" + params.Encode()
	r, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	r.Host = testHost

	// Canonical query string computed BEFORE adding X-Amz-Signature (matches verifier's exclusion).
	canonQuery := auth.CanonicalQueryString(r.URL.Query())
	canonHdrs := "host:" + testHost + "\n"
	signedHdrsStr := "host"
	payloadHash := "UNSIGNED-PAYLOAD"

	canonReq := auth.CanonicalRequest(http.MethodGet, "/", canonQuery, canonHdrs, signedHdrsStr, payloadHash)
	sts := auth.StringToSign(dateTime, scope, auth.HashSHA256Hex([]byte(canonReq)))

	signingKey := auth.DeriveSigningKey(testSecretKey, date, testRegion, "s3")
	sig := auth.ComputeSignature(signingKey, sts)

	// Add signature and update URL.
	params.Set("X-Amz-Signature", sig)
	r.URL.RawQuery = params.Encode()

	return r
}

// xmlErrorMessage decodes the S3 error Message field from an XML error response body.
func xmlErrorMessage(t *testing.T, body []byte) string {
	t.Helper()
	var e struct {
		Message string `xml:"Message"`
	}
	if err := xml.Unmarshal(body, &e); err != nil {
		t.Fatalf("xml.Unmarshal error body: %v\nbody: %s", err, body)
	}
	return e.Message
}

// ---- 1. Both Authorization header + X-Amz-Algorithm query param → 403 InvalidRequest ----

func TestAuthenticate_BothAuthMethods_ReturnsInvalidRequest(t *testing.T) {
	handler, _ := setupTestServer(t)
	now := time.Now()

	// Start with a valid header-signed request.
	r := makeSignedRequest(t, http.MethodGet, "/", now)

	// Also inject a presigned query parameter.
	// The signatures don't need to be valid; conflict is detected before any verification.
	q := r.URL.Query()
	q.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	r.URL.RawQuery = q.Encode()

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d; body: %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/xml" {
		t.Errorf("Content-Type: got %q, want application/xml", ct)
	}
	if code := xmlErrorCode(t, body); code != "InvalidRequest" {
		t.Errorf("error code: got %q, want InvalidRequest", code)
	}
	// Error message must mention both mechanisms.
	msg := xmlErrorMessage(t, body)
	if !strings.Contains(msg, "Authorization header") || !strings.Contains(msg, "presigned") {
		t.Errorf("error message %q should mention both Authorization header and presigned", msg)
	}
	if !strings.Contains(msg, "only one authentication mechanism") {
		t.Errorf("error message %q should mention 'only one authentication mechanism'", msg)
	}
}

// ---- 2. Presigned-only succeeds (regression: change must not break presign path) ----

func TestAuthenticate_PresignOnly_Succeeds(t *testing.T) {
	handler, _ := setupTestServer(t)

	r := makePresignRequest(t, time.Now())

	// Confirm no Authorization header is present (pure presign path).
	if r.Header.Get("Authorization") != "" {
		t.Fatal("test setup error: Authorization header must be absent for presign-only test")
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("presign-only: expected 200, got %d; body: %s", resp.StatusCode, body)
	}
}

// ---- 3. Header-only succeeds (regression: change must not break header auth path) ----

func TestAuthenticate_HeaderOnly_Succeeds(t *testing.T) {
	handler, _ := setupTestServer(t)

	r := makeSignedRequest(t, http.MethodGet, "/", time.Now())

	// Confirm no X-Amz-Algorithm query param is present (pure header path).
	if r.URL.Query().Has("X-Amz-Algorithm") {
		t.Fatal("test setup error: X-Amz-Algorithm must be absent for header-only test")
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if got := w.Result().StatusCode; got != http.StatusOK {
		t.Errorf("header-only: expected 200, got %d; body: %s", got, w.Body.String())
	}
}

// ---- 4. No auth returns AccessDenied (regression) ----

func TestAuthenticate_NoAuth_ReturnsAccessDenied(t *testing.T) {
	handler, _ := setupTestServer(t)

	r, _ := http.NewRequest(http.MethodGet, "http://"+testHost+"/", nil)
	r.Host = testHost

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
	if code := xmlErrorCode(t, body); code != "AccessDenied" {
		t.Errorf("error code: got %q, want AccessDenied", code)
	}
}
