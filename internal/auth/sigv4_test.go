package auth

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
)

// Test fixtures used across multiple tests.
const (
	testAccessKey = "AKIDTESTEXAMPLE0001"
	testSecretKey = "test-secret-key-for-sigv4-unit-tests-01"
	testRegion    = "us-east-1"
	testService   = "s3"
	testDate      = "20240101"
	testDateTime  = "20240101T120000Z"
	// emptyBodyHash is SHA-256("").
	emptyBodyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// ---- 1. ParseAuthorization: valid header ----

func TestParseAuthorization_Valid(t *testing.T) {
	header := `AWS4-HMAC-SHA256 Credential=AKIDTESTEXAMPLE0001/20240101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890`

	got, err := ParseAuthorization(header)
	if err != nil {
		t.Fatalf("ParseAuthorization: unexpected error: %v", err)
	}

	if got.AccessKeyID != testAccessKey {
		t.Errorf("AccessKeyID: got %q, want %q", got.AccessKeyID, testAccessKey)
	}
	if got.Date != testDate {
		t.Errorf("Date: got %q, want %q", got.Date, testDate)
	}
	if got.Region != testRegion {
		t.Errorf("Region: got %q, want %q", got.Region, testRegion)
	}
	if got.Service != testService {
		t.Errorf("Service: got %q, want %q", got.Service, testService)
	}
	wantHeaders := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	if strings.Join(got.SignedHeaders, ";") != strings.Join(wantHeaders, ";") {
		t.Errorf("SignedHeaders: got %v, want %v", got.SignedHeaders, wantHeaders)
	}
	if got.Signature != "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890" {
		t.Errorf("Signature: got %q", got.Signature)
	}
}

// ---- 2. ParseAuthorization: wrong algorithm prefix ----

func TestParseAuthorization_WrongAlgorithm(t *testing.T) {
	header := `AWS4-HMAC-SHA512 Credential=AKID/20240101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc`

	_, err := ParseAuthorization(header)
	if err == nil {
		t.Fatal("expected error for wrong algorithm prefix, got nil")
	}
	if !errors.Is(err, ErrMalformedAuthorization) {
		t.Errorf("expected ErrMalformedAuthorization, got %v", err)
	}
}

// ---- 3. ParseAuthorization: malformed credential (wrong number of parts) ----

func TestParseAuthorization_MalformedCredentialParts(t *testing.T) {
	// Missing the service part: only 4 parts instead of 5.
	header := `AWS4-HMAC-SHA256 Credential=AKID/20240101/us-east-1/aws4_request, SignedHeaders=host, Signature=abc`

	_, err := ParseAuthorization(header)
	if err == nil {
		t.Fatal("expected error for malformed credential, got nil")
	}
	if !errors.Is(err, ErrMalformedAuthorization) {
		t.Errorf("expected ErrMalformedAuthorization, got %v", err)
	}
	if !errors.Is(err, ErrMalformedCredential) {
		t.Errorf("expected ErrMalformedCredential wrapped inside error, got %v", err)
	}
}

// ---- 4. ParseAuthorization: missing SignedHeaders field ----

func TestParseAuthorization_MissingSignedHeaders(t *testing.T) {
	header := `AWS4-HMAC-SHA256 Credential=AKID/20240101/us-east-1/s3/aws4_request, Signature=abc`

	_, err := ParseAuthorization(header)
	if err == nil {
		t.Fatal("expected error for missing SignedHeaders, got nil")
	}
	if !errors.Is(err, ErrMalformedAuthorization) {
		t.Errorf("expected ErrMalformedAuthorization, got %v", err)
	}
}

// ---- 5a. CanonicalURI: explicit expected-value tests (S3 no-double-encode contract) ----

func TestCanonicalURI_PlainPath(t *testing.T) {
	// Unreserved-character path passes through unchanged.
	got := CanonicalURI("/bucket/key")
	const want = "/bucket/key"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalURI_PercentEncodedSpace(t *testing.T) {
	// %20 must be preserved as-is; NOT double-encoded to %2520.
	// AWS S3 SDK DisableURIPathEscaping=true: raw escaped path is used directly.
	got := CanonicalURI("/bucket/my%20key")
	const want = "/bucket/my%20key" // NOT "/bucket/my%2520key"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalURI_PercentEncodedSlash(t *testing.T) {
	// %2F must be preserved as-is; NOT double-encoded to %252F.
	// The slash is part of the object key name, not a path separator.
	got := CanonicalURI("/bucket/a%2Fb")
	const want = "/bucket/a%2Fb" // NOT "/bucket/a%252Fb"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalURI_UTF8PercentEncoded(t *testing.T) {
	// Multi-byte UTF-8 percent-encoded sequences (e.g. é = U+00E9 = %C3%A9)
	// must pass through without further encoding.
	got := CanonicalURI("/bucket/caf%C3%A9")
	const want = "/bucket/caf%C3%A9"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalURI_Empty(t *testing.T) {
	got := CanonicalURI("")
	const want = "/"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalURI_NoLeadingSlash(t *testing.T) {
	// Path without leading slash gets one prepended.
	got := CanonicalURI("bucket/key")
	const want = "/bucket/key"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// ---- 5. CanonicalRequest: deterministic format ----

func TestCanonicalRequest_Format(t *testing.T) {
	// Verify the exact structure of the canonical request string.
	// The canonical request must have exactly 6 newline-separated sections.
	// Per AWS SigV4 spec: method\nuri\nquery\nheaders\nsignedHeaders\npayloadHash
	method := "GET"
	uri := "/my-bucket/my-object"
	query := ""
	// Canonical headers block: each header ends with '\n'.
	headers := "host:s3.us-east-1.example.com\nx-amz-content-sha256:" + emptyBodyHash + "\nx-amz-date:" + testDateTime + "\n"
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	payloadHash := emptyBodyHash

	canon := CanonicalRequest(method, uri, query, headers, signedHeaders, payloadHash)

	// Split into lines and verify structure.
	lines := strings.Split(canon, "\n")
	// Expected lines:
	//   0: method
	//   1: uri
	//   2: query (empty)
	//   3: host:...
	//   4: x-amz-content-sha256:...
	//   5: x-amz-date:...
	//   6: (empty line — because headers block ends with \n, then \n separator)
	//   7: signedHeaders
	//   8: payloadHash
	if len(lines) != 9 {
		t.Fatalf("canonical request: expected 9 lines, got %d\nContent:\n%s", len(lines), canon)
	}
	if lines[0] != method {
		t.Errorf("line 0 (method): got %q, want %q", lines[0], method)
	}
	if lines[1] != uri {
		t.Errorf("line 1 (uri): got %q, want %q", lines[1], uri)
	}
	if lines[2] != query {
		t.Errorf("line 2 (query): got %q, want %q (empty)", lines[2], query)
	}
	if lines[6] != "" {
		t.Errorf("line 6 (blank after headers block): got %q, want empty", lines[6])
	}
	if lines[7] != signedHeaders {
		t.Errorf("line 7 (signedHeaders): got %q, want %q", lines[7], signedHeaders)
	}
	if lines[8] != payloadHash {
		t.Errorf("line 8 (payloadHash): got %q, want %q", lines[8], payloadHash)
	}
}

// ---- 6. StringToSign: deterministic format ----

func TestStringToSign_Format(t *testing.T) {
	// Verify the exact structure of the string-to-sign.
	// Per AWS SigV4 spec: algorithm\ndatetime\nscope\nhash
	datetime := testDateTime
	scope := CredentialScope(testDate, testRegion, testService)
	canonReqHash := "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222"

	sts := StringToSign(datetime, scope, canonReqHash)

	lines := strings.Split(sts, "\n")
	if len(lines) != 4 {
		t.Fatalf("string-to-sign: expected 4 lines, got %d\nContent:\n%s", len(lines), sts)
	}
	if lines[0] != sigV4Algorithm {
		t.Errorf("line 0 (algorithm): got %q, want %q", lines[0], sigV4Algorithm)
	}
	if lines[1] != datetime {
		t.Errorf("line 1 (datetime): got %q, want %q", lines[1], datetime)
	}
	if lines[2] != scope {
		t.Errorf("line 2 (scope): got %q, want %q", lines[2], scope)
	}
	if lines[3] != canonReqHash {
		t.Errorf("line 3 (hash): got %q, want %q", lines[3], canonReqHash)
	}

	// Verify the scope format: YYYYMMDD/region/service/aws4_request
	wantScope := testDate + "/" + testRegion + "/" + testService + "/aws4_request"
	if scope != wantScope {
		t.Errorf("CredentialScope: got %q, want %q", scope, wantScope)
	}
}

// ---- 7. DeriveSigningKey: deterministic (same inputs → same key) ----

func TestDeriveSigningKey_Deterministic(t *testing.T) {
	key1 := DeriveSigningKey(testSecretKey, testDate, testRegion, testService)
	key2 := DeriveSigningKey(testSecretKey, testDate, testRegion, testService)

	if len(key1) != 32 {
		t.Errorf("signing key length: got %d, want 32 (SHA-256 output)", len(key1))
	}
	if string(key1) != string(key2) {
		t.Error("DeriveSigningKey: same inputs produced different keys (non-deterministic)")
	}

	// Different date must produce a different key.
	keyOtherDate := DeriveSigningKey(testSecretKey, "20240102", testRegion, testService)
	if string(key1) == string(keyOtherDate) {
		t.Error("DeriveSigningKey: different dates produced the same key")
	}

	// Different region must produce a different key.
	keyOtherRegion := DeriveSigningKey(testSecretKey, testDate, "ap-northeast-2", testService)
	if string(key1) == string(keyOtherRegion) {
		t.Error("DeriveSigningKey: different regions produced the same key")
	}

	// Different service must produce a different key.
	keyOtherService := DeriveSigningKey(testSecretKey, testDate, testRegion, "iam")
	if string(key1) == string(keyOtherService) {
		t.Error("DeriveSigningKey: different services produced the same key")
	}
}

// ---- 8. ComputeSignature: round-trip (sign then re-derive and compare) ----

func TestComputeSignature_RoundTrip(t *testing.T) {
	sts := "AWS4-HMAC-SHA256\n20240101T120000Z\n20240101/us-east-1/s3/aws4_request\ndeadbeef"

	key1 := DeriveSigningKey(testSecretKey, testDate, testRegion, testService)
	sig1 := ComputeSignature(key1, sts)

	// Re-derive the same key and compute signature again; must be identical.
	key2 := DeriveSigningKey(testSecretKey, testDate, testRegion, testService)
	sig2 := ComputeSignature(key2, sts)

	if sig1 != sig2 {
		t.Errorf("ComputeSignature: non-deterministic output\nsig1=%s\nsig2=%s", sig1, sig2)
	}
	// Signature must be 64 lowercase hex characters (32-byte HMAC-SHA256).
	if len(sig1) != 64 {
		t.Errorf("signature length: got %d, want 64", len(sig1))
	}
	for _, c := range sig1 {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("signature contains non-lowercase-hex character %q", c)
			break
		}
	}

	// A different string-to-sign must produce a different signature.
	sigOther := ComputeSignature(key1, sts+"extra")
	if sig1 == sigOther {
		t.Error("ComputeSignature: different inputs produced the same signature")
	}
}

// ---- helpers: build a correctly signed request ----

// makeSignedRequest creates an http.Request with a valid SigV4 Authorization header
// signed with testSecretKey for testRegion/testService.
func makeSignedRequest(t *testing.T, method, rawURL string) *http.Request {
	t.Helper()

	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", rawURL, err)
	}

	r := httptest.NewRequest(method, rawURL, nil)
	r.Host = u.Host

	r.Header.Set("X-Amz-Date", testDateTime)
	r.Header.Set("X-Amz-Content-Sha256", emptyBodyHash)

	signedHeaderNames := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	sort.Strings(signedHeaderNames)

	canonHdrs, signedHdrsStr, err := CanonicalHeaders(r, signedHeaderNames)
	if err != nil {
		t.Fatalf("CanonicalHeaders: %v", err)
	}

	// Canonical URI: use the already-escaped path directly, matching what Verify() does.
	// We deliberately do NOT call CanonicalURI() here to avoid masking a shared-impl bug.
	// Instead we replicate the same two-step logic that Verify() uses:
	//   1. prefer RawPath (preserved by Go HTTP server when encoding changes the path)
	//   2. fall back to EscapedPath()
	// CanonicalURI() then returns this value unchanged (S3 no-double-encode contract).
	escapedPath := r.URL.RawPath
	if escapedPath == "" {
		escapedPath = r.URL.EscapedPath()
	}
	canonQuery := CanonicalQueryString(r.URL.Query())
	canonReq := CanonicalRequest(method, escapedPath, canonQuery, canonHdrs, signedHdrsStr, emptyBodyHash)

	scope := CredentialScope(testDate, testRegion, testService)
	sts := StringToSign(testDateTime, scope, HashSHA256Hex([]byte(canonReq)))

	signingKey := DeriveSigningKey(testSecretKey, testDate, testRegion, testService)
	sig := ComputeSignature(signingKey, sts)

	authHeader := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		sigV4Algorithm, testAccessKey, scope, signedHdrsStr, sig)
	r.Header.Set("Authorization", authHeader)

	return r
}

// activeProvider returns a SecretProvider that always returns testSecretKey as active.
func activeProvider() SecretProvider {
	return func(accessKeyID string) (string, bool, error) {
		if accessKeyID == testAccessKey {
			return testSecretKey, true, nil
		}
		return "", false, nil
	}
}

// ---- 9. Verifier.Verify: success (full round-trip) ----

func TestVerifier_Success(t *testing.T) {
	r := makeSignedRequest(t, http.MethodGet, "http://s3.us-east-1.example.com/my-bucket/my-object")

	v := &Verifier{
		Region:    testRegion,
		Service:   testService,
		GetSecret: activeProvider(),
	}

	if err := v.Verify(r); err != nil {
		t.Errorf("Verify: unexpected error: %v", err)
	}
}

// ---- 10. Verifier.Verify: wrong region ----

func TestVerifier_WrongRegion(t *testing.T) {
	// The request is signed for us-east-1 but the verifier expects ap-northeast-2.
	r := makeSignedRequest(t, http.MethodGet, "http://s3.us-east-1.example.com/bucket/key")

	v := &Verifier{
		Region:    "ap-northeast-2",
		Service:   testService,
		GetSecret: activeProvider(),
	}

	err := v.Verify(r)
	if err == nil {
		t.Fatal("expected error for wrong region, got nil")
	}
	if !errors.Is(err, ErrWrongRegion) {
		t.Errorf("expected ErrWrongRegion, got %v", err)
	}
}

// ---- 11. Verifier.Verify: signature mismatch ----

func TestVerifier_SignatureMismatch(t *testing.T) {
	r := makeSignedRequest(t, http.MethodGet, "http://s3.us-east-1.example.com/bucket/key")

	// Tamper the Authorization header by replacing the signature with all zeros.
	original := r.Header.Get("Authorization")
	sigIdx := strings.LastIndex(original, "Signature=")
	tampered := original[:sigIdx+len("Signature=")] +
		"0000000000000000000000000000000000000000000000000000000000000000"
	r.Header.Set("Authorization", tampered)

	v := &Verifier{
		Region:    testRegion,
		Service:   testService,
		GetSecret: activeProvider(),
	}

	err := v.Verify(r)
	if err == nil {
		t.Fatal("expected error for tampered signature, got nil")
	}
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Errorf("expected ErrSignatureMismatch, got %v", err)
	}
}

// ---- 12. Verifier.Verify: inactive key ----

func TestVerifier_InactiveKey(t *testing.T) {
	r := makeSignedRequest(t, http.MethodGet, "http://s3.us-east-1.example.com/bucket/key")

	// Provider reports the key as inactive.
	inactiveProvider := SecretProvider(func(accessKeyID string) (string, bool, error) {
		return testSecretKey, false, nil // isActive = false
	})

	v := &Verifier{
		Region:    testRegion,
		Service:   testService,
		GetSecret: inactiveProvider,
	}

	err := v.Verify(r)
	if err == nil {
		t.Fatal("expected error for inactive key, got nil")
	}
	if !errors.Is(err, ErrInactiveKey) {
		t.Errorf("expected ErrInactiveKey, got %v", err)
	}
}

// ---- bonus: missing signed header ----

func TestVerifier_MissingSignedHeader(t *testing.T) {
	// Sign a request that claims to sign "x-custom-header", but don't add it to the request.
	r := httptest.NewRequest(http.MethodGet, "http://s3.us-east-1.example.com/bucket/key", nil)
	r.Host = "s3.us-east-1.example.com"
	r.Header.Set("X-Amz-Date", testDateTime)
	r.Header.Set("X-Amz-Content-Sha256", emptyBodyHash)

	// Build an Authorization header claiming x-custom-header is signed but don't add it.
	scope := CredentialScope(testDate, testRegion, testService)
	signingKey := DeriveSigningKey(testSecretKey, testDate, testRegion, testService)
	sig := ComputeSignature(signingKey, "dummy")

	authHeader := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=host;x-amz-date;x-custom-header, Signature=%s",
		sigV4Algorithm, testAccessKey, scope, sig)
	r.Header.Set("Authorization", authHeader)

	v := &Verifier{
		Region:    testRegion,
		Service:   testService,
		GetSecret: activeProvider(),
	}

	err := v.Verify(r)
	if err == nil {
		t.Fatal("expected error for missing signed header, got nil")
	}
	if !errors.Is(err, ErrMissingSignedHeader) {
		t.Errorf("expected ErrMissingSignedHeader, got %v", err)
	}
}

// ---- bonus: unsupported streaming payload mode ----

func TestVerifier_UnsupportedStreamingPayload(t *testing.T) {
	r := makeSignedRequest(t, http.MethodPut, "http://s3.us-east-1.example.com/bucket/key")
	r.Header.Set("X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")

	v := &Verifier{
		Region:    testRegion,
		Service:   testService,
		GetSecret: activeProvider(),
	}

	err := v.Verify(r)
	if err == nil {
		t.Fatal("expected error for streaming payload, got nil")
	}
	if !errors.Is(err, ErrUnsupportedPayload) {
		t.Errorf("expected ErrUnsupportedPayload, got %v", err)
	}
}

// ---- bonus 2: missing X-Amz-Content-Sha256 must be rejected (Finding 1) ----

func TestVerifier_MissingPayloadHash(t *testing.T) {
	// Build a correctly signed request, then remove the X-Amz-Content-Sha256 header.
	// Verify must return ErrMissingPayloadHash, not silently treat the body as empty.
	r := makeSignedRequest(t, http.MethodGet, "http://s3.us-east-1.example.com/bucket/key")
	r.Header.Del("X-Amz-Content-Sha256")

	v := &Verifier{
		Region:    testRegion,
		Service:   testService,
		GetSecret: activeProvider(),
	}

	err := v.Verify(r)
	if err == nil {
		t.Fatal("expected error for missing X-Amz-Content-Sha256, got nil")
	}
	if !errors.Is(err, ErrMissingPayloadHash) {
		t.Errorf("expected ErrMissingPayloadHash, got %v", err)
	}
}

// ---- bonus 3: UNSIGNED-PAYLOAD must be accepted (Finding 1 – allowed value) ----

func TestVerifier_UnsignedPayloadAccepted(t *testing.T) {
	// Build a request signed with UNSIGNED-PAYLOAD as the payload hash,
	// as the AWS SDK does for some presigned/simple upload scenarios.
	// Per s3-compatibility-matrix.md 5.1: UNSIGNED-PAYLOAD is allowed.
	const unsignedPayload = "UNSIGNED-PAYLOAD"

	u := "http://s3.us-east-1.example.com/bucket/key"
	r := httptest.NewRequest(http.MethodPut, u, nil)
	r.Host = "s3.us-east-1.example.com"
	r.Header.Set("X-Amz-Date", testDateTime)
	r.Header.Set("X-Amz-Content-Sha256", unsignedPayload)

	signedHeaderNames := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	sort.Strings(signedHeaderNames)

	canonHdrs, signedHdrsStr, err := CanonicalHeaders(r, signedHeaderNames)
	if err != nil {
		t.Fatalf("CanonicalHeaders: %v", err)
	}

	rawPath := r.URL.EscapedPath()
	canonReq := CanonicalRequest(http.MethodPut,
		CanonicalURI(rawPath),
		CanonicalQueryString(r.URL.Query()),
		canonHdrs, signedHdrsStr, unsignedPayload)

	scope := CredentialScope(testDate, testRegion, testService)
	sts := StringToSign(testDateTime, scope, HashSHA256Hex([]byte(canonReq)))

	signingKey := DeriveSigningKey(testSecretKey, testDate, testRegion, testService)
	sig := ComputeSignature(signingKey, sts)

	authHeader := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		sigV4Algorithm, testAccessKey, scope, signedHdrsStr, sig)
	r.Header.Set("Authorization", authHeader)

	v := &Verifier{
		Region:    testRegion,
		Service:   testService,
		GetSecret: activeProvider(),
	}

	if err := v.Verify(r); err != nil {
		t.Errorf("UNSIGNED-PAYLOAD should be accepted, got error: %v", err)
	}
}

// ---- bonus 4: raw path %20 – verify succeeds (Finding 2) ----

func TestVerifier_RawPath_PercentEncodedSpace(t *testing.T) {
	// Object key contains a space; the SDK sends the path as /bucket/my%20key.
	// Canonical URI (S3 contract) = /bucket/my%20key  ← preserved as-is, NOT /bucket/my%2520key.
	// Using r.URL.Path (decoded) would give canonical URI /bucket/my key (space!), causing mismatch.
	rawURL := "http://s3.us-east-1.example.com/bucket/my%20key"
	r := makeSignedRequest(t, http.MethodGet, rawURL)

	v := &Verifier{
		Region:    testRegion,
		Service:   testService,
		GetSecret: activeProvider(),
	}

	if err := v.Verify(r); err != nil {
		t.Errorf("Verify with %%20 in path: unexpected error: %v", err)
	}
}

// ---- bonus 5: raw path %2F – verify succeeds (Finding 2) ----

func TestVerifier_RawPath_EncodedSlash(t *testing.T) {
	// Object key contains an encoded slash %2F.
	// Canonical URI (S3 contract) = /bucket/a%2Fb  ← preserved as-is, NOT /bucket/a%252Fb.
	// r.URL.Path decodes %2F → '/', losing the distinction from a real path separator.
	rawURL := "http://s3.us-east-1.example.com/bucket/a%2Fb"
	r := makeSignedRequest(t, http.MethodGet, rawURL)

	v := &Verifier{
		Region:    testRegion,
		Service:   testService,
		GetSecret: activeProvider(),
	}

	if err := v.Verify(r); err != nil {
		t.Errorf("Verify with %%2F in path: unexpected error: %v", err)
	}
}

// ---- bonus 6: regression – decoded path causes signature mismatch ----

func TestVerifier_DecodedPath_Regression(t *testing.T) {
	// Regression: using r.URL.Path (decoded) as canonical URI causes mismatch.
	//
	// S3 contract:
	//   Raw path  /bucket/my%20key  → canonical URI = /bucket/my%20key
	//   Decoded path /bucket/my key → canonical URI = /bucket/my key  (has literal space — WRONG)
	//
	// This test confirms:
	//   a) decoded and raw canonical URIs differ for this path,
	//   b) requestRawPath() + CanonicalURI() produces the correct canonical URI.
	rawURL := "http://s3.us-east-1.example.com/bucket/my%20key"
	r := makeSignedRequest(t, http.MethodGet, rawURL)

	// Compute both variants to prove they differ.
	// After the fix, CanonicalURI() does NOT re-encode; it returns its input as-is.
	decodedCanonURI := CanonicalURI(r.URL.Path)         // "/bucket/my key"    (literal space)
	rawCanonURI := CanonicalURI(r.URL.EscapedPath())    // "/bucket/my%20key"  (correct)

	if decodedCanonURI == rawCanonURI {
		t.Skip("decoded and raw canonical URIs are identical; test not meaningful")
	}

	// Explicit expected values.
	if decodedCanonURI != "/bucket/my key" {
		t.Errorf("decoded canonical URI: got %q, want %q", decodedCanonURI, "/bucket/my key")
	}
	if rawCanonURI != "/bucket/my%20key" {
		t.Errorf("raw canonical URI: got %q, want %q", rawCanonURI, "/bucket/my%20key")
	}

	// With requestRawPath() fix in Verify(), verification must succeed.
	v := &Verifier{
		Region:    testRegion,
		Service:   testService,
		GetSecret: activeProvider(),
	}
	if err := v.Verify(r); err != nil {
		t.Errorf("Verify (post-fix): unexpected error for %%20 path: %v", err)
	}
}

// ---- bonus: decrypt round-trip integrated with the lookup path (requirement #12) ----
// This test simulates the full path: encrypt a secret → mock the provider that decrypts it
// → use the decrypted secret in SigV4 verification.
func TestVerifier_DecryptRoundTrip(t *testing.T) {
	masterKey := "a-test-master-key-for-round-trip-test-32b"
	realSecret := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

	// Simulate what bootstrap does: encrypt the secret before storing.
	ciphertext, err := EncryptSecret(masterKey, realSecret)
	if err != nil {
		t.Fatalf("EncryptSecret: %v", err)
	}

	// Simulate what the middleware does: decrypt on lookup.
	decryptingProvider := SecretProvider(func(accessKeyID string) (string, bool, error) {
		if accessKeyID != testAccessKey {
			return "", false, nil
		}
		// Decrypt using the master key — as the real middleware would.
		plaintext, decErr := DecryptSecret(masterKey, ciphertext)
		if decErr != nil {
			return "", false, fmt.Errorf("decrypting secret: %w", decErr)
		}
		return plaintext, true, nil
	})

	// Build a request signed with the real (decrypted) secret.
	r := httptest.NewRequest(http.MethodGet, "http://s3.us-east-1.example.com/bucket/key", nil)
	r.Host = "s3.us-east-1.example.com"
	r.Header.Set("X-Amz-Date", testDateTime)
	r.Header.Set("X-Amz-Content-Sha256", emptyBodyHash)

	signedHeaderNames := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	sort.Strings(signedHeaderNames)
	canonHdrs, signedHdrsStr, err := CanonicalHeaders(r, signedHeaderNames)
	if err != nil {
		t.Fatalf("CanonicalHeaders: %v", err)
	}

	canonReq := CanonicalRequest(http.MethodGet,
		CanonicalURI(r.URL.Path),
		CanonicalQueryString(r.URL.Query()),
		canonHdrs, signedHdrsStr, emptyBodyHash)

	scope := CredentialScope(testDate, testRegion, testService)
	sts := StringToSign(testDateTime, scope, HashSHA256Hex([]byte(canonReq)))

	// Sign with the REAL secret (simulating what the AWS SDK does client-side).
	signingKey := DeriveSigningKey(realSecret, testDate, testRegion, testService)
	sig := ComputeSignature(signingKey, sts)

	authHeader := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		sigV4Algorithm, testAccessKey, scope, signedHdrsStr, sig)
	r.Header.Set("Authorization", authHeader)

	v := &Verifier{
		Region:    testRegion,
		Service:   testService,
		GetSecret: decryptingProvider,
	}

	if err := v.Verify(r); err != nil {
		t.Errorf("Verify with decrypted secret: unexpected error: %v", err)
	}
}
