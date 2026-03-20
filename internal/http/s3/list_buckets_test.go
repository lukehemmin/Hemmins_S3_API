package s3_test

import (
	"encoding/xml"
	"fmt"
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

const (
	testRegion    = "us-east-1"
	testAccessKey = "AKIDTESTEXAMPLE12345"
	testSecretKey = "test/secret/key/for/tests/only"
	testMasterKey = "test-master-key-for-unit-tests-only"
	testHost      = "s3.us-east-1.example.com"
)

// setupTestServer opens an in-memory SQLite DB, bootstraps it with test credentials,
// and returns a ready-to-use S3 handler. Cleanup is registered via t.Cleanup.
func setupTestServer(t *testing.T) (http.Handler, *metadata.DB) {
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
	return srv.Handler(), db
}

// signRequest attaches a valid SigV4 Authorization header to r.
// r.Host must be set before calling this helper.
func signRequest(t *testing.T, r *http.Request, now time.Time) {
	t.Helper()
	date := now.UTC().Format("20060102")
	dateTime := now.UTC().Format("20060102T150405Z")

	payloadHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
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

	r.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		testAccessKey, scope, signedHdrsStr, sig,
	))
}

// makeSignedRequest builds a signed GET request for the given path.
func makeSignedRequest(t *testing.T, method, path string, now time.Time) *http.Request {
	t.Helper()
	rawURL := "http://" + testHost + path
	r, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	r.Host = testHost
	signRequest(t, r, now)
	return r
}

// insertBucket directly inserts a bucket row for testing without a full CreateBucket API.
func insertBucket(t *testing.T, db *metadata.DB, name string, createdAt time.Time) {
	t.Helper()
	_, err := db.SQLDB().Exec(
		"INSERT INTO buckets (name, created_at) VALUES (?, ?)",
		name, createdAt.UTC().Format(time.RFC3339),
	)
	if err != nil {
		t.Fatalf("insertBucket %q: %v", name, err)
	}
}

// xmlErrorCode decodes the S3 error code from an XML error response body.
func xmlErrorCode(t *testing.T, body []byte) string {
	t.Helper()
	var e struct {
		Code string `xml:"Code"`
	}
	if err := xml.Unmarshal(body, &e); err != nil {
		t.Fatalf("xml.Unmarshal error body: %v\nbody: %s", err, body)
	}
	return e.Code
}

// ---- 1. Metadata ListBuckets query unit test ----

func TestMetadataListBuckets(t *testing.T) {
	db, err := metadata.Open(":memory:")
	if err != nil {
		t.Fatalf("metadata.Open: %v", err)
	}
	defer db.Close()

	now := time.Date(2024, 3, 1, 10, 0, 0, 0, time.UTC)
	insertBucket(t, db, "zebra", now.Add(-1*time.Hour))
	insertBucket(t, db, "alpha", now.Add(-2*time.Hour))
	insertBucket(t, db, "mango", now)

	buckets, err := db.ListBuckets()
	if err != nil {
		t.Fatalf("ListBuckets: %v", err)
	}
	if len(buckets) != 3 {
		t.Fatalf("expected 3 buckets, got %d", len(buckets))
	}
	// Must be sorted alphabetically by name.
	names := []string{buckets[0].Name, buckets[1].Name, buckets[2].Name}
	want := []string{"alpha", "mango", "zebra"}
	for i, n := range names {
		if n != want[i] {
			t.Errorf("bucket[%d]: got %q, want %q", i, n, want[i])
		}
	}
	// CreatedAt must be parsed correctly.
	if buckets[0].CreatedAt.IsZero() {
		t.Error("bucket[0].CreatedAt is zero; expected parsed time")
	}
}

// ---- 2. XML marshal test for ListAllMyBucketsResult ----

func TestXMLMarshal_ListBucketsResult(t *testing.T) {
	type listResult struct {
		XMLName xml.Name `xml:"ListAllMyBucketsResult"`
		Owner   struct {
			ID          string `xml:"ID"`
			DisplayName string `xml:"DisplayName"`
		} `xml:"Owner"`
		Buckets struct {
			Bucket []struct {
				Name         string `xml:"Name"`
				CreationDate string `xml:"CreationDate"`
			} `xml:"Bucket"`
		} `xml:"Buckets"`
	}

	// Use the actual handler output to test marshaling end-to-end.
	handler, db := setupTestServer(t)
	insertBucket(t, db, "my-bucket", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))

	r := makeSignedRequest(t, http.MethodGet, "/", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", resp.StatusCode, body)
	}

	var parsed listResult
	if err := xml.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("xml.Unmarshal: %v\nbody: %s", err, body)
	}
	if len(parsed.Buckets.Bucket) != 1 {
		t.Fatalf("expected 1 bucket, got %d", len(parsed.Buckets.Bucket))
	}
	if parsed.Buckets.Bucket[0].Name != "my-bucket" {
		t.Errorf("bucket name: got %q, want %q", parsed.Buckets.Bucket[0].Name, "my-bucket")
	}
	// CreationDate must be present and non-empty.
	if parsed.Buckets.Bucket[0].CreationDate == "" {
		t.Error("CreationDate is empty")
	}
	// Namespace must be present in raw output (SDK checks it).
	if !strings.Contains(string(body), "http://s3.amazonaws.com/doc/2006-03-01/") {
		t.Error("XML namespace not found in response body")
	}
}

// ---- 3. Unauthenticated GET / returns 403 AccessDenied ----

func TestHandler_Unauthenticated(t *testing.T) {
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
		t.Errorf("expected AccessDenied, got %q", code)
	}
}

// ---- 4. Authenticated GET / returns 200 ----

func TestHandler_Authenticated(t *testing.T) {
	handler, _ := setupTestServer(t)

	r := makeSignedRequest(t, http.MethodGet, "/", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if got := w.Result().StatusCode; got != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", got, w.Body.String())
	}
}

// ---- 5. Malformed Authorization header returns S3 error XML ----

func TestHandler_MalformedAuth(t *testing.T) {
	handler, _ := setupTestServer(t)

	r, _ := http.NewRequest(http.MethodGet, "http://"+testHost+"/", nil)
	r.Host = testHost
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 this-is-not-valid")
	r.Header.Set("X-Amz-Date", time.Now().UTC().Format("20060102T150405Z"))
	r.Header.Set("X-Amz-Content-Sha256",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Type") != "application/xml" {
		t.Errorf("Content-Type: got %q, want application/xml", resp.Header.Get("Content-Type"))
	}
	code := xmlErrorCode(t, body)
	if code != "InvalidRequest" && code != "AccessDenied" {
		t.Errorf("expected InvalidRequest or AccessDenied, got %q", code)
	}
}

// ---- 6. Wrong signature returns SignatureDoesNotMatch ----

func TestHandler_SignatureMismatch(t *testing.T) {
	handler, _ := setupTestServer(t)

	now := time.Now().UTC()
	r, _ := http.NewRequest(http.MethodGet, "http://"+testHost+"/", nil)
	r.Host = testHost
	// Set correct headers but put a garbage signature.
	date := now.Format("20060102")
	dateTime := now.Format("20060102T150405Z")
	r.Header.Set("X-Amz-Date", dateTime)
	r.Header.Set("X-Amz-Content-Sha256",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	scope := auth.CredentialScope(date, testRegion, "s3")
	r.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=%s",
		testAccessKey, scope, strings.Repeat("0", 64),
	))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
	if code := xmlErrorCode(t, body); code != "SignatureDoesNotMatch" {
		t.Errorf("expected SignatureDoesNotMatch, got %q", code)
	}
}

// ---- 7. Successful response has Content-Type: application/xml and 200 ----

func TestHandler_SuccessContentType(t *testing.T) {
	handler, _ := setupTestServer(t)

	r := makeSignedRequest(t, http.MethodGet, "/", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/xml" {
		t.Errorf("Content-Type: got %q, want application/xml", ct)
	}
}

// ---- 8. Empty bucket list returns valid XML with empty Buckets element ----

func TestHandler_EmptyBucketList(t *testing.T) {
	handler, _ := setupTestServer(t)
	// No buckets inserted — DB only has the bootstrap access key, no buckets.

	r := makeSignedRequest(t, http.MethodGet, "/", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", resp.StatusCode, body)
	}

	var result struct {
		Buckets struct {
			Bucket []struct{ Name string `xml:"Name"` } `xml:"Bucket"`
		} `xml:"Buckets"`
	}
	if err := xml.Unmarshal(body, &result); err != nil {
		t.Fatalf("xml.Unmarshal: %v\nbody: %s", err, body)
	}
	if n := len(result.Buckets.Bucket); n != 0 {
		t.Errorf("expected 0 buckets, got %d", n)
	}
}

// ---- 9. Non-empty bucket list returns all buckets in alphabetical order ----

func TestHandler_NonEmptyBucketList(t *testing.T) {
	handler, db := setupTestServer(t)
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	insertBucket(t, db, "zeta-bucket", base.Add(2*time.Hour))
	insertBucket(t, db, "alpha-bucket", base)
	insertBucket(t, db, "middle-bucket", base.Add(1*time.Hour))

	r := makeSignedRequest(t, http.MethodGet, "/", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", resp.StatusCode, body)
	}

	var result struct {
		Buckets struct {
			Bucket []struct {
				Name         string `xml:"Name"`
				CreationDate string `xml:"CreationDate"`
			} `xml:"Bucket"`
		} `xml:"Buckets"`
	}
	if err := xml.Unmarshal(body, &result); err != nil {
		t.Fatalf("xml.Unmarshal: %v\nbody: %s", err, body)
	}

	buckets := result.Buckets.Bucket
	if len(buckets) != 3 {
		t.Fatalf("expected 3 buckets, got %d", len(buckets))
	}
	want := []string{"alpha-bucket", "middle-bucket", "zeta-bucket"}
	for i, b := range buckets {
		if b.Name != want[i] {
			t.Errorf("bucket[%d]: got %q, want %q", i, b.Name, want[i])
		}
		if b.CreationDate == "" {
			t.Errorf("bucket[%d].CreationDate is empty", i)
		}
	}
}

// ---- 10. Router: GET / maps to ListBuckets only ----

func TestRouter_PathMapping(t *testing.T) {
	handler, _ := setupTestServer(t)
	now := time.Now()

	cases := []struct {
		method     string
		path       string
		wantStatus int
		desc       string
	}{
		{http.MethodGet, "/", http.StatusOK, "GET / → ListBuckets (authenticated)"},
		{http.MethodGet, "/some-bucket", http.StatusNotImplemented, "GET /bucket → 501"},
		{http.MethodGet, "/some-bucket/key", http.StatusNotFound, "GET /bucket/key → NoSuchBucket"},
		{http.MethodPut, "/", http.StatusNotImplemented, "PUT / → 501"},
		{http.MethodDelete, "/", http.StatusNotImplemented, "DELETE / → 501"},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			rawURL := "http://" + testHost + tc.path
			r, err := http.NewRequest(tc.method, rawURL, nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			r.Host = testHost
			signRequest(t, r, now)

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)

			if got := w.Result().StatusCode; got != tc.wantStatus {
				t.Errorf("expected %d, got %d; body: %s", tc.wantStatus, got, w.Body.String())
			}
		})
	}
}
