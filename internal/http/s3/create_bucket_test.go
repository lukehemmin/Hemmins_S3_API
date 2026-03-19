package s3_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/lukehemmin/hemmins-s3-api/internal/auth"
)

// makeSignedPutRequest builds a correctly-signed PUT request.
// body may be empty for requests with no CreateBucketConfiguration XML.
// The payload hash is computed from the actual body so signature verification
// passes when the handler reads r.Body.
func makeSignedPutRequest(t *testing.T, path, body string, now time.Time) *http.Request {
	t.Helper()

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	r, err := http.NewRequest(http.MethodPut, "http://"+testHost+path, bodyReader)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	r.Host = testHost

	// Compute payload hash for actual body (empty body = well-known SHA256 of "").
	var payloadHash string
	if body == "" {
		payloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	} else {
		payloadHash = auth.HashSHA256Hex([]byte(body))
	}

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

	r.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		testAccessKey, scope, signedHdrsStr, sig,
	))
	return r
}

// ---- 1. PUT /my-bucket success ----

func TestCreateBucket_Success(t *testing.T) {
	handler, _ := setupTestServer(t)

	r := makeSignedPutRequest(t, "/test-bucket", "", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", resp.StatusCode, body)
	}
	if loc := resp.Header.Get("Location"); loc != "/test-bucket" {
		t.Errorf("Location: got %q, want %q", loc, "/test-bucket")
	}
}

// ---- 2. Duplicate bucket name → 409 BucketAlreadyOwnedByYou ----

func TestCreateBucket_Duplicate(t *testing.T) {
	handler, _ := setupTestServer(t)
	now := time.Now()

	// First creation succeeds.
	r1 := makeSignedPutRequest(t, "/dup-bucket", "", now)
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, r1)
	if w1.Result().StatusCode != http.StatusOK {
		t.Fatalf("first create: expected 200, got %d", w1.Result().StatusCode)
	}

	// Second creation for same name must fail.
	r2 := makeSignedPutRequest(t, "/dup-bucket", "", now.Add(time.Second))
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, r2)

	resp := w2.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusConflict {
		t.Errorf("expected 409, got %d; body: %s", resp.StatusCode, body)
	}
	if code := xmlErrorCode(t, body); code != "BucketAlreadyOwnedByYou" {
		t.Errorf("error code: got %q, want BucketAlreadyOwnedByYou", code)
	}
}

// ---- 3. Invalid bucket name (too short) → 400 InvalidBucketName ----

func TestCreateBucket_TooShort(t *testing.T) {
	handler, _ := setupTestServer(t)

	r := makeSignedPutRequest(t, "/ab", "", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d; body: %s", resp.StatusCode, body)
	}
	if code := xmlErrorCode(t, body); code != "InvalidBucketName" {
		t.Errorf("error code: got %q, want InvalidBucketName", code)
	}
}

// ---- 4. Uppercase bucket name → 400 InvalidBucketName ----

func TestCreateBucket_Uppercase(t *testing.T) {
	handler, _ := setupTestServer(t)

	r := makeSignedPutRequest(t, "/My-Bucket", "", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d; body: %s", resp.StatusCode, body)
	}
	if code := xmlErrorCode(t, body); code != "InvalidBucketName" {
		t.Errorf("error code: got %q, want InvalidBucketName", code)
	}
}

// ---- 5. Underscore in name → 400 InvalidBucketName ----

func TestCreateBucket_Underscore(t *testing.T) {
	handler, _ := setupTestServer(t)

	r := makeSignedPutRequest(t, "/my_bucket", "", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d; body: %s", resp.StatusCode, body)
	}
	if code := xmlErrorCode(t, body); code != "InvalidBucketName" {
		t.Errorf("error code: got %q, want InvalidBucketName", code)
	}
}

// ---- 6. IP-style bucket name → 400 InvalidBucketName ----

func TestCreateBucket_IPStyleName(t *testing.T) {
	handler, _ := setupTestServer(t)

	r := makeSignedPutRequest(t, "/192.168.1.1", "", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d; body: %s", resp.StatusCode, body)
	}
	if code := xmlErrorCode(t, body); code != "InvalidBucketName" {
		t.Errorf("error code: got %q, want InvalidBucketName", code)
	}
}

// ---- 7. Bad LocationConstraint → 400 InvalidLocationConstraint ----

func TestCreateBucket_BadLocationConstraint(t *testing.T) {
	handler, _ := setupTestServer(t)

	xmlBody := `<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">` +
		`<LocationConstraint>eu-west-1</LocationConstraint>` +
		`</CreateBucketConfiguration>`

	r := makeSignedPutRequest(t, "/my-bucket", xmlBody, time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d; body: %s", resp.StatusCode, body)
	}
	if code := xmlErrorCode(t, body); code != "InvalidLocationConstraint" {
		t.Errorf("error code: got %q, want InvalidLocationConstraint", code)
	}
}

// ---- 8. Matching LocationConstraint → 200 OK ----

func TestCreateBucket_MatchingLocationConstraint(t *testing.T) {
	handler, _ := setupTestServer(t)

	// testRegion = "us-east-1" — matching constraint must succeed.
	xmlBody := `<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">` +
		`<LocationConstraint>` + testRegion + `</LocationConstraint>` +
		`</CreateBucketConfiguration>`

	r := makeSignedPutRequest(t, "/constrained-bucket", xmlBody, time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", resp.StatusCode, body)
	}
}

// ---- 9. Unauthenticated CreateBucket → 403 AccessDenied ----

func TestCreateBucket_Unauthenticated(t *testing.T) {
	handler, _ := setupTestServer(t)

	r, _ := http.NewRequest(http.MethodPut, "http://"+testHost+"/unauth-bucket", nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d; body: %s", resp.StatusCode, body)
	}
	if code := xmlErrorCode(t, body); code != "AccessDenied" {
		t.Errorf("error code: got %q, want AccessDenied", code)
	}
}

// ---- 10. Router path mapping: PUT /{bucket} routes to CreateBucket ----

func TestRouter_CreateBucket_PathMapping(t *testing.T) {
	handler, _ := setupTestServer(t)
	now := time.Now()

	cases := []struct {
		method     string
		path       string
		wantStatus int
		desc       string
	}{
		// PUT /{bucket} → CreateBucket (authenticated, valid name)
		{http.MethodPut, "/new-bucket", http.StatusOK, "PUT /bucket → 200"},
		// PUT /{bucket}/{key} → PutObject handler → 404 NoSuchBucket (bucket "bucket" not in DB)
		{http.MethodPut, "/bucket/key", http.StatusNotFound, "PUT /bucket/key → 404"},
		// GET /{bucket} → not yet implemented → 501
		{http.MethodGet, "/some-bucket", http.StatusNotImplemented, "GET /bucket → 501"},
		// DELETE /{bucket} → now implemented → routes to DeleteBucket → 404 NoSuchBucket
		// (bucket "some-bucket" does not exist in this test's DB)
		{http.MethodDelete, "/some-bucket", http.StatusNotFound, "DELETE /bucket → 404"},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			r := makeSignedPutRequest(t, tc.path, "", now)
			// Override the method after signing (for non-PUT cases).
			// For non-PUT tests, use makeSignedRequest which handles GET/DELETE correctly.
			if tc.method != http.MethodPut {
				r = makeSignedRequest(t, tc.method, tc.path, now)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)

			if got := w.Result().StatusCode; got != tc.wantStatus {
				t.Errorf("%s: expected %d, got %d; body: %s", tc.desc, tc.wantStatus, got, w.Body.String())
			}
		})
	}
}

// ---- 11. PUT / without bucket should not create anything → 501 ----

func TestCreateBucket_PutServiceRoot_IsNotImplemented(t *testing.T) {
	handler, _ := setupTestServer(t)

	// PUT / is service-level; only GET / (ListBuckets) is implemented.
	r := makeSignedPutRequest(t, "/", "", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("expected 501, got %d; body: %s", resp.StatusCode, body)
	}
	if code := xmlErrorCode(t, body); code != "NotImplemented" {
		t.Errorf("error code: got %q, want NotImplemented", code)
	}
}

// ---- 12. Additional name-rule edge cases ----

func TestCreateBucket_NameValidationEdgeCases(t *testing.T) {
	handler, _ := setupTestServer(t)

	cases := []struct {
		name       string
		bucketPath string
		wantStatus int
		wantCode   string
		desc       string
	}{
		{
			desc:       "leading dot",
			bucketPath: "/.bucket",
			wantStatus: http.StatusBadRequest,
			wantCode:   "InvalidBucketName",
		},
		{
			desc:       "trailing hyphen",
			bucketPath: "/bucket-",
			wantStatus: http.StatusBadRequest,
			wantCode:   "InvalidBucketName",
		},
		{
			desc:       "double dot",
			bucketPath: "/my..bucket",
			wantStatus: http.StatusBadRequest,
			wantCode:   "InvalidBucketName",
		},
		{
			desc:       "too long (64 chars)",
			bucketPath: "/" + strings.Repeat("a", 64),
			wantStatus: http.StatusBadRequest,
			wantCode:   "InvalidBucketName",
		},
		{
			desc:       "minimum valid (3 chars)",
			bucketPath: "/abc",
			wantStatus: http.StatusOK,
			wantCode:   "",
		},
	}

	now := time.Now()
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			r := makeSignedPutRequest(t, tc.bucketPath, "", now)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)

			resp := w.Result()
			respBody, _ := io.ReadAll(resp.Body)

			if resp.StatusCode != tc.wantStatus {
				t.Errorf("%s: expected %d, got %d; body: %s", tc.desc, tc.wantStatus, resp.StatusCode, respBody)
				return
			}
			if tc.wantCode != "" {
				if code := xmlErrorCode(t, respBody); code != tc.wantCode {
					t.Errorf("%s: error code got %q, want %q", tc.desc, code, tc.wantCode)
				}
			}
		})
	}
}

// ---- XML validation hardening tests ----
// These tests cover the fix for the XMLName.Local check in checkLocationConstraint().

// TestCreateBucket_UnexpectedRootXML verifies that a well-formed but semantically wrong
// root element is rejected with MalformedXML.
// This is the primary finding: before the fix, <Foo/> was silently accepted because
// Go's xml.Unmarshal does not enforce the struct's XMLName tag during decoding.
func TestCreateBucket_UnexpectedRootXML(t *testing.T) {
	handler, _ := setupTestServer(t)

	r := makeSignedPutRequest(t, "/xml-test-bucket", "<Foo/>", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d; body: %s", resp.StatusCode, body)
	}
	if code := xmlErrorCode(t, body); code != "MalformedXML" {
		t.Errorf("error code: got %q, want MalformedXML", code)
	}
}

// TestCreateBucket_MalformedXML_Syntax verifies that syntactically invalid XML is rejected.
func TestCreateBucket_MalformedXML_Syntax(t *testing.T) {
	handler, _ := setupTestServer(t)

	r := makeSignedPutRequest(t, "/xml-test-bucket2", "not-valid-xml{{<>", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d; body: %s", resp.StatusCode, body)
	}
	if code := xmlErrorCode(t, body); code != "MalformedXML" {
		t.Errorf("error code: got %q, want MalformedXML", code)
	}
}

// TestCreateBucket_ValidEmptyConfiguration verifies that <CreateBucketConfiguration/>
// with no LocationConstraint child is accepted (empty == no constraint == allowed).
func TestCreateBucket_ValidEmptyConfiguration(t *testing.T) {
	handler, _ := setupTestServer(t)

	r := makeSignedPutRequest(t, "/empty-cfg-bucket", "<CreateBucketConfiguration/>", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", resp.StatusCode, body)
	}
}

// TestCreateBucket_WrongNamespaceButCorrectLocal documents the permissive namespace policy.
// A wrong or absent namespace with the correct local name "CreateBucketConfiguration"
// must be ACCEPTED. AWS itself accepts namespace-free bodies, and some SDK versions omit
// the namespace declaration. Enforcing the namespace would hurt compatibility.
// Per the namespace policy comment in checkLocationConstraint().
func TestCreateBucket_WrongNamespaceButCorrectLocal(t *testing.T) {
	handler, _ := setupTestServer(t)

	xmlBody := `<CreateBucketConfiguration xmlns="urn:wrong-namespace">` +
		`<LocationConstraint>` + testRegion + `</LocationConstraint>` +
		`</CreateBucketConfiguration>`

	r := makeSignedPutRequest(t, "/ns-bucket", xmlBody, time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("permissive-namespace policy: expected 200, got %d; body: %s", resp.StatusCode, body)
	}
}

// TestCreateBucket_NoNamespace verifies that a body without any xmlns declaration
// but with the correct local name is ACCEPTED (permissive namespace policy).
func TestCreateBucket_NoNamespace(t *testing.T) {
	handler, _ := setupTestServer(t)

	xmlBody := `<CreateBucketConfiguration>` +
		`<LocationConstraint>` + testRegion + `</LocationConstraint>` +
		`</CreateBucketConfiguration>`

	r := makeSignedPutRequest(t, "/no-ns-bucket", xmlBody, time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("no-namespace policy: expected 200, got %d; body: %s", resp.StatusCode, body)
	}
}
