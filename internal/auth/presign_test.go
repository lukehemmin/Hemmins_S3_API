package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// testSigningTime is the signing time for presign tests.
// Corresponds to testDate + testDateTime constants defined in sigv4_test.go.
var testSigningTime = time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

// newPresignVerifier builds a PresignVerifier with standard test credentials and
// a fixed "now" time for deterministic expiry evaluation.
func newPresignVerifier(now time.Time, maxTTL time.Duration) *PresignVerifier {
	return &PresignVerifier{
		Region:    testRegion,
		Service:   testService,
		MaxTTL:    maxTTL,
		GetSecret: activeProvider(),
		Now:       func() time.Time { return now },
	}
}

// makePresignedRequest creates an *http.Request carrying valid SigV4 presigned
// URL query parameters signed with testSecretKey.
//
// Design note: the canonical URI is computed from the raw/escaped path directly
// (NOT via CanonicalURI) to avoid sharing production URI logic and masking bugs.
// The canonical query is computed via canonicalQueryStringExcluding, which is
// independently tested in TestCanonicalQueryStringExcluding.
func makePresignedRequest(t *testing.T, method, rawURL string, expiresSeconds int64, signingTime time.Time) *http.Request {
	t.Helper()

	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", rawURL, err)
	}

	dateTime := signingTime.UTC().Format(sigV4DateTimeFormat)
	date := signingTime.UTC().Format(sigV4DateFormat)

	// AWS SDK default: only "host" is signed in presigned requests.
	signedHeaderNames := []string{"host"}
	sort.Strings(signedHeaderNames)
	signedHeadersStr := strings.Join(signedHeaderNames, ";")

	scope := CredentialScope(date, testRegion, testService)
	credential := testAccessKey + "/" + scope

	// Step 1: Build query params without X-Amz-Signature.
	q := u.Query()
	q.Set("X-Amz-Algorithm", sigV4Algorithm)
	q.Set("X-Amz-Credential", credential)
	q.Set("X-Amz-Date", dateTime)
	q.Set("X-Amz-Expires", strconv.FormatInt(expiresSeconds, 10))
	q.Set("X-Amz-SignedHeaders", signedHeadersStr)
	u.RawQuery = q.Encode()

	// Step 2: Build request; host must be set for canonical headers.
	r := httptest.NewRequest(method, u.String(), nil)
	r.Host = u.Host

	// Step 3: Canonical headers (only "host" for minimal presigned requests).
	canonHdrs, _, err := CanonicalHeaders(r, signedHeaderNames)
	if err != nil {
		t.Fatalf("CanonicalHeaders: %v", err)
	}

	// Step 4: Canonical query without X-Amz-Signature (not added yet).
	canonQuery := canonicalQueryStringExcluding(r.URL.Query(), "X-Amz-Signature")

	// Step 5: Canonical URI — raw/escaped path directly, NOT via CanonicalURI().
	// This avoids sharing the production URI path to help detect regressions.
	escapedPath := r.URL.RawPath
	if escapedPath == "" {
		escapedPath = r.URL.EscapedPath()
	}

	// Step 6: Canonical request. Payload hash = UNSIGNED-PAYLOAD for presigned.
	canonReq := CanonicalRequest(method, escapedPath, canonQuery, canonHdrs, signedHeadersStr, "UNSIGNED-PAYLOAD")

	sts := StringToSign(dateTime, scope, HashSHA256Hex([]byte(canonReq)))
	signingKey := DeriveSigningKey(testSecretKey, date, testRegion, testService)
	sig := ComputeSignature(signingKey, sts)

	// Step 7: Add X-Amz-Signature and update request URL.
	q.Set("X-Amz-Signature", sig)
	r.URL.RawQuery = q.Encode()

	return r
}

// ---- 1. Valid presigned GET success ----

func TestPresignVerifier_GETSuccess(t *testing.T) {
	const expiresSeconds = 3600
	r := makePresignedRequest(t, http.MethodGet,
		"http://s3.us-east-1.example.com/bucket/key",
		expiresSeconds, testSigningTime)

	// "now" is 30 minutes after signing — within the 1-hour window.
	now := testSigningTime.Add(30 * time.Minute)
	v := newPresignVerifier(now, 24*time.Hour)

	if err := v.Verify(r); err != nil {
		t.Errorf("Verify presigned GET: unexpected error: %v", err)
	}
}

// ---- 2. Valid presigned PUT success ----

func TestPresignVerifier_PUTSuccess(t *testing.T) {
	const expiresSeconds = 3600
	r := makePresignedRequest(t, http.MethodPut,
		"http://s3.us-east-1.example.com/bucket/key",
		expiresSeconds, testSigningTime)

	now := testSigningTime.Add(30 * time.Minute)
	v := newPresignVerifier(now, 24*time.Hour)

	if err := v.Verify(r); err != nil {
		t.Errorf("Verify presigned PUT: unexpected error: %v", err)
	}
}

// ---- 3–6. Missing required query parameters ----

func TestPresignVerifier_MissingRequiredParam(t *testing.T) {
	tests := []struct {
		name    string
		dropKey string
		wantErr error
	}{
		{"missing X-Amz-Algorithm", "X-Amz-Algorithm", ErrMissingPresignParam},
		{"missing X-Amz-Credential", "X-Amz-Credential", ErrMissingPresignParam},
		{"missing X-Amz-Date", "X-Amz-Date", ErrMissingPresignParam},
		{"missing X-Amz-Expires", "X-Amz-Expires", ErrMissingPresignParam},
		{"missing X-Amz-SignedHeaders", "X-Amz-SignedHeaders", ErrMissingPresignParam},
		{"missing X-Amz-Signature", "X-Amz-Signature", ErrMissingPresignParam},
	}

	const expiresSeconds = 3600
	now := testSigningTime.Add(30 * time.Minute)
	v := newPresignVerifier(now, 24*time.Hour)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := makePresignedRequest(t, http.MethodGet,
				"http://s3.us-east-1.example.com/bucket/key",
				expiresSeconds, testSigningTime)

			// Remove the required parameter.
			q := r.URL.Query()
			q.Del(tc.dropKey)
			r.URL.RawQuery = q.Encode()

			err := v.Verify(r)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("expected %v, got %v", tc.wantErr, err)
			}
		})
	}
}

// ---- 7. Malformed credential scope failure ----

func TestPresignVerifier_MalformedCredential(t *testing.T) {
	now := testSigningTime.Add(30 * time.Minute)
	v := newPresignVerifier(now, 24*time.Hour)

	// Build a query with a malformed credential (only 3 parts instead of 5).
	q := url.Values{
		"X-Amz-Algorithm":    {sigV4Algorithm},
		"X-Amz-Credential":   {"AKID/20240101/us-east-1"},
		"X-Amz-Date":         {testDateTime},
		"X-Amz-Expires":      {"3600"},
		"X-Amz-SignedHeaders": {"host"},
		"X-Amz-Signature":    {"deadbeef"},
	}
	_, err := ParsePresignQuery(q)
	if err == nil {
		t.Fatal("expected error for malformed credential, got nil")
	}
	if !errors.Is(err, ErrMalformedCredential) {
		t.Errorf("expected ErrMalformedCredential, got %v", err)
	}

	// Also test via Verify.
	r := httptest.NewRequest(http.MethodGet, "http://s3.us-east-1.example.com/bucket/key?"+q.Encode(), nil)
	r.Host = "s3.us-east-1.example.com"
	if err := v.Verify(r); !errors.Is(err, ErrMalformedCredential) {
		t.Errorf("Verify: expected ErrMalformedCredential, got %v", err)
	}
}

// ---- 8. Wrong region failure ----

func TestPresignVerifier_WrongRegion(t *testing.T) {
	const expiresSeconds = 3600
	r := makePresignedRequest(t, http.MethodGet,
		"http://s3.us-east-1.example.com/bucket/key",
		expiresSeconds, testSigningTime)

	now := testSigningTime.Add(30 * time.Minute)
	v := &PresignVerifier{
		Region:    "eu-west-1", // mismatch
		Service:   testService,
		MaxTTL:    24 * time.Hour,
		GetSecret: activeProvider(),
		Now:       func() time.Time { return now },
	}

	err := v.Verify(r)
	if err == nil {
		t.Fatal("expected error for wrong region, got nil")
	}
	if !errors.Is(err, ErrWrongRegion) {
		t.Errorf("expected ErrWrongRegion, got %v", err)
	}
}

// ---- 9. Expired URL failure ----

func TestPresignVerifier_Expired(t *testing.T) {
	const expiresSeconds = 3600 // 1 hour
	r := makePresignedRequest(t, http.MethodGet,
		"http://s3.us-east-1.example.com/bucket/key",
		expiresSeconds, testSigningTime)

	// "now" is 2 hours after signing — past the 1-hour expiry.
	now := testSigningTime.Add(2 * time.Hour)
	v := newPresignVerifier(now, 24*time.Hour)

	err := v.Verify(r)
	if err == nil {
		t.Fatal("expected error for expired URL, got nil")
	}
	if !errors.Is(err, ErrExpiredPresignURL) {
		t.Errorf("expected ErrExpiredPresignURL, got %v", err)
	}
}

// ---- 10. X-Amz-Expires exceeds max TTL failure ----

func TestPresignVerifier_TTLExceeded(t *testing.T) {
	// Request signed for 48 hours; verifier only allows 24 hours.
	const expiresSeconds = 48 * 3600
	r := makePresignedRequest(t, http.MethodGet,
		"http://s3.us-east-1.example.com/bucket/key",
		expiresSeconds, testSigningTime)

	now := testSigningTime.Add(1 * time.Hour)
	v := newPresignVerifier(now, 24*time.Hour)

	err := v.Verify(r)
	if err == nil {
		t.Fatal("expected error for TTL exceeded, got nil")
	}
	if !errors.Is(err, ErrPresignTTLExceeded) {
		t.Errorf("expected ErrPresignTTLExceeded, got %v", err)
	}
}

// ---- 11. Inactive key failure ----

func TestPresignVerifier_InactiveKey(t *testing.T) {
	const expiresSeconds = 3600
	r := makePresignedRequest(t, http.MethodGet,
		"http://s3.us-east-1.example.com/bucket/key",
		expiresSeconds, testSigningTime)

	now := testSigningTime.Add(30 * time.Minute)
	v := &PresignVerifier{
		Region:  testRegion,
		Service: testService,
		MaxTTL:  24 * time.Hour,
		GetSecret: func(accessKeyID string) (string, bool, error) {
			return "", false, nil // inactive / not found
		},
		Now: func() time.Time { return now },
	}

	err := v.Verify(r)
	if err == nil {
		t.Fatal("expected error for inactive key, got nil")
	}
	if !errors.Is(err, ErrInactiveKey) {
		t.Errorf("expected ErrInactiveKey, got %v", err)
	}
}

// ---- 12. Signature mismatch failure ----

func TestPresignVerifier_SignatureMismatch(t *testing.T) {
	const expiresSeconds = 3600
	r := makePresignedRequest(t, http.MethodGet,
		"http://s3.us-east-1.example.com/bucket/key",
		expiresSeconds, testSigningTime)

	// Tamper with the X-Amz-Signature value.
	q := r.URL.Query()
	q.Set("X-Amz-Signature", "0000000000000000000000000000000000000000000000000000000000000000")
	r.URL.RawQuery = q.Encode()

	now := testSigningTime.Add(30 * time.Minute)
	v := newPresignVerifier(now, 24*time.Hour)

	err := v.Verify(r)
	if err == nil {
		t.Fatal("expected error for signature mismatch, got nil")
	}
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Errorf("expected ErrSignatureMismatch, got %v", err)
	}
}

// ---- 13. X-Amz-Signature excluded from canonical query ----

func TestCanonicalQueryStringExcluding(t *testing.T) {
	q := url.Values{
		"X-Amz-Algorithm":     {sigV4Algorithm},
		"X-Amz-Credential":    {"AKID/20240101/us-east-1/s3/aws4_request"},
		"X-Amz-Date":          {testDateTime},
		"X-Amz-Expires":       {"3600"},
		"X-Amz-SignedHeaders":  {"host"},
		"X-Amz-Signature":     {"deadbeefdeadbeef"},
	}

	withSig := CanonicalQueryString(q)
	withoutSig := canonicalQueryStringExcluding(q, "X-Amz-Signature")

	if withSig == withoutSig {
		t.Fatal("canonical query with and without X-Amz-Signature must differ")
	}
	if strings.Contains(withoutSig, "X-Amz-Signature") {
		t.Errorf("canonical query (no sig) still contains X-Amz-Signature: %q", withoutSig)
	}
	if !strings.Contains(withSig, "X-Amz-Signature") {
		t.Errorf("canonical query (with sig) is missing X-Amz-Signature: %q", withSig)
	}
	// Original map must not be modified.
	if _, ok := q["X-Amz-Signature"]; !ok {
		t.Error("canonicalQueryStringExcluding must not modify the input url.Values")
	}
}

// ---- 14. Deterministic canonical query ordering ----

func TestPresignCanonicalQueryOrder(t *testing.T) {
	// Build params in deliberately non-sorted order.
	q := url.Values{}
	q.Set("X-Amz-SignedHeaders", "host")
	q.Set("X-Amz-Date", testDateTime)
	q.Set("X-Amz-Algorithm", sigV4Algorithm)
	q.Set("X-Amz-Expires", "3600")
	q.Set("X-Amz-Credential", testAccessKey+"/"+testDate+"/"+testRegion+"/"+testService+"/aws4_request")

	canon := canonicalQueryStringExcluding(q, "X-Amz-Signature")

	// Expected: lexicographically sorted keys, values sigV4-encoded.
	// "/" in credential value → %2F (sigV4Encode: '/' is not unreserved).
	// testAccessKey = "AKIDTESTEXAMPLE0001" (defined in sigv4_test.go).
	want := "X-Amz-Algorithm=AWS4-HMAC-SHA256" +
		"&X-Amz-Credential=" + sigV4Encode(testAccessKey+"/"+testDate+"/"+testRegion+"/"+testService+"/aws4_request") +
		"&X-Amz-Date=" + testDateTime +
		"&X-Amz-Expires=3600" +
		"&X-Amz-SignedHeaders=host"

	if canon != want {
		t.Errorf("canonical query ordering:\ngot:  %s\nwant: %s", canon, want)
	}
}

// ---- 15. Encoded path %20 (space) with presigned URL success ----

func TestPresignVerifier_EncodedPath_Space(t *testing.T) {
	// Object key contains a space; SDK sends /bucket/my%20key as the path.
	// S3 canonical URI contract: %20 is preserved as-is (no double-encode to %2520).
	rawURL := "http://s3.us-east-1.example.com/bucket/my%20key"
	r := makePresignedRequest(t, http.MethodGet, rawURL, 3600, testSigningTime)

	now := testSigningTime.Add(30 * time.Minute)
	v := newPresignVerifier(now, 24*time.Hour)

	if err := v.Verify(r); err != nil {
		t.Errorf("Verify with %%20 in path: unexpected error: %v", err)
	}
}

// ---- 16. Encoded path %2F (encoded slash) with presigned URL success ----

func TestPresignVerifier_EncodedPath_Slash(t *testing.T) {
	// Object key contains a literal encoded slash %2F.
	// S3 canonical URI contract: %2F is preserved (not decoded to '/' path separator,
	// and not double-encoded to %252F).
	rawURL := "http://s3.us-east-1.example.com/bucket/a%2Fb"
	r := makePresignedRequest(t, http.MethodGet, rawURL, 3600, testSigningTime)

	now := testSigningTime.Add(30 * time.Minute)
	v := newPresignVerifier(now, 24*time.Hour)

	if err := v.Verify(r); err != nil {
		t.Errorf("Verify with %%2F in path: unexpected error: %v", err)
	}
}

// ---- 17. ParsePresignQuery: invalid X-Amz-Expires values ----

func TestParsePresignQuery_InvalidExpires(t *testing.T) {
	base := url.Values{
		"X-Amz-Algorithm":     {sigV4Algorithm},
		"X-Amz-Credential":    {testAccessKey + "/20240101/us-east-1/s3/aws4_request"},
		"X-Amz-Date":          {testDateTime},
		"X-Amz-SignedHeaders":  {"host"},
		"X-Amz-Signature":     {"deadbeef"},
	}

	cases := []struct {
		expires string
		wantErr error
	}{
		{"0", ErrInvalidPresignExpires},
		{"-1", ErrInvalidPresignExpires},
		{"notanumber", ErrInvalidPresignExpires},
	}

	for _, tc := range cases {
		q := make(url.Values)
		for k, v := range base {
			q[k] = v
		}
		q.Set("X-Amz-Expires", tc.expires)

		_, err := ParsePresignQuery(q)
		if err == nil {
			t.Errorf("expires=%q: expected error, got nil", tc.expires)
			continue
		}
		if !errors.Is(err, tc.wantErr) {
			t.Errorf("expires=%q: expected %v, got %v", tc.expires, tc.wantErr, err)
		}
	}
}

// ---- 19. host absent from X-Amz-SignedHeaders — rejected by Verify ----

func TestPresignVerifier_HostNotSigned(t *testing.T) {
	// Build a valid request, then overwrite X-Amz-SignedHeaders to omit "host".
	// Expect failure: SigV4 requires host to be signed so the URL is bound to a
	// specific endpoint and cannot be replayed against a different server.
	r := makePresignedRequest(t, http.MethodGet,
		"http://s3.us-east-1.example.com/bucket/key",
		3600, testSigningTime)

	q := r.URL.Query()
	q.Set("X-Amz-SignedHeaders", "x-amz-date") // host deliberately absent
	r.URL.RawQuery = q.Encode()

	now := testSigningTime.Add(30 * time.Minute)
	v := newPresignVerifier(now, 24*time.Hour)

	err := v.Verify(r)
	if err == nil {
		t.Fatal("expected error when host not in X-Amz-SignedHeaders, got nil")
	}
	if !errors.Is(err, ErrHostNotSigned) {
		t.Errorf("expected ErrHostNotSigned, got %v", err)
	}
}

// ---- 20. host absent from X-Amz-SignedHeaders — rejected at ParsePresignQuery stage ----

func TestParsePresignQuery_HostRequired(t *testing.T) {
	// Verify the host check fires at parse time, not just inside Verify.
	// This documents that the enforcement is early and callers of ParsePresignQuery
	// also get the error without needing to call Verify.
	q := url.Values{
		"X-Amz-Algorithm":     {sigV4Algorithm},
		"X-Amz-Credential":    {testAccessKey + "/20240101/us-east-1/s3/aws4_request"},
		"X-Amz-Date":          {testDateTime},
		"X-Amz-Expires":       {"3600"},
		"X-Amz-SignedHeaders":  {"x-amz-date"}, // host absent
		"X-Amz-Signature":     {"deadbeef"},
	}

	_, err := ParsePresignQuery(q)
	if err == nil {
		t.Fatal("ParsePresignQuery: expected error when host absent, got nil")
	}
	if !errors.Is(err, ErrHostNotSigned) {
		t.Errorf("ParsePresignQuery: expected ErrHostNotSigned, got %v", err)
	}
}

// ---- 21. URL signed in the future is rejected (strict mode) ----

func TestPresignVerifier_FutureSignedAt(t *testing.T) {
	// The URL is signed at testSigningTime (2024-01-01 12:00 UTC).
	// "now" is 1 hour BEFORE that signing time.
	// Policy (strict mode): now.Before(signedAt) → ErrPresignNotYetValid.
	// Rationale: a future-signed URL has an effective window that starts in the
	// future and would allow pre-distribution of access tokens valid for longer
	// than the declared X-Amz-Expires duration.
	r := makePresignedRequest(t, http.MethodGet,
		"http://s3.us-east-1.example.com/bucket/key",
		3600, testSigningTime)

	now := testSigningTime.Add(-1 * time.Hour) // 1 hour before signing time
	v := newPresignVerifier(now, 24*time.Hour)

	err := v.Verify(r)
	if err == nil {
		t.Fatal("expected error for URL signed in the future, got nil")
	}
	if !errors.Is(err, ErrPresignNotYetValid) {
		t.Errorf("expected ErrPresignNotYetValid, got %v", err)
	}
}

// ---- 22. now == signedAt is valid (boundary: URL becomes valid at signing time) ----

func TestPresignVerifier_ExactSignedAt_IsValid(t *testing.T) {
	// "now" == signing time exactly.
	// now.Before(signedAt) is false when now == signedAt, so the URL must succeed.
	// This documents the boundary: the URL is valid from (and including) signedAt.
	r := makePresignedRequest(t, http.MethodGet,
		"http://s3.us-east-1.example.com/bucket/key",
		3600, testSigningTime)

	now := testSigningTime // exactly at signing time, not before
	v := newPresignVerifier(now, 24*time.Hour)

	if err := v.Verify(r); err != nil {
		t.Errorf("Verify at exact signing time: unexpected error: %v", err)
	}
}

// ---- 18. STS security token is explicitly rejected ----

func TestParsePresignQuery_SecurityTokenRejected(t *testing.T) {
	q := url.Values{
		"X-Amz-Algorithm":      {sigV4Algorithm},
		"X-Amz-Credential":     {testAccessKey + "/20240101/us-east-1/s3/aws4_request"},
		"X-Amz-Date":           {testDateTime},
		"X-Amz-Expires":        {"3600"},
		"X-Amz-SignedHeaders":   {"host"},
		"X-Amz-Signature":      {"deadbeef"},
		"X-Amz-Security-Token": {"some-sts-token"},
	}

	_, err := ParsePresignQuery(q)
	if err == nil {
		t.Fatal("expected error for X-Amz-Security-Token, got nil")
	}
	if !errors.Is(err, ErrUnsupportedPayload) {
		t.Errorf("expected ErrUnsupportedPayload, got %v", err)
	}
}
