package ui_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lukehemmin/hemmins-s3-api/internal/auth"
)

// presignRequest matches the JSON request body for POST /ui/api/buckets/{name}/objects/presign.
type presignRequest struct {
	Key            string `json:"key"`
	Method         string `json:"method"`
	ExpiresSeconds int64  `json:"expiresSeconds"`
}

// presignResponse matches the JSON response from POST /ui/api/buckets/{name}/objects/presign.
type presignResponse struct {
	URL            string `json:"url"`
	Method         string `json:"method"`
	ExpiresSeconds int64  `json:"expiresSeconds"`
}

// doPresign issues POST /ui/api/buckets/{bucket}/objects/presign with the given request body.
// Automatically fetches a CSRF token first.
func doPresign(t *testing.T, handler http.Handler, cookies []*http.Cookie, bucketName string, reqBody presignRequest) *httptest.ResponseRecorder {
	t.Helper()
	// Get a CSRF token.
	csrfRR := doCSRF(t, handler)
	if csrfRR.Code != http.StatusOK {
		t.Fatalf("failed to get CSRF token: %d", csrfRR.Code)
	}
	csrfCookie := findCSRFCookie(csrfRR)
	if csrfCookie == nil {
		t.Fatal("no CSRF cookie in response")
	}
	var csrfResp map[string]string
	if err := json.Unmarshal(csrfRR.Body.Bytes(), &csrfResp); err != nil {
		t.Fatalf("parsing CSRF response: %v", err)
	}
	token := csrfResp["token"]

	body, _ := json.Marshal(reqBody)
	reqURL := "/ui/api/buckets/" + bucketName + "/objects/presign"
	req := httptest.NewRequest(http.MethodPost, reqURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", token)
	req.AddCookie(csrfCookie)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// doPresignWithoutCSRF issues POST /ui/api/buckets/{bucket}/objects/presign without CSRF header.
func doPresignWithoutCSRF(t *testing.T, handler http.Handler, cookies []*http.Cookie, bucketName string, reqBody presignRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(reqBody)
	url := "/ui/api/buckets/" + bucketName + "/objects/presign"
	req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// Add session cookie only, not CSRF header.
	for _, c := range cookies {
		if c.Name == "hemmins_session" {
			req.AddCookie(c)
			break
		}
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// Test 1: valid session + CSRF + GET presign → 200 success
func TestPresign_GET_Success(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "presign-get-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d: %s", createRR.Code, createRR.Body.String())
	}

	// Generate presigned GET URL.
	req := presignRequest{
		Key:            "test-object.txt",
		Method:         "GET",
		ExpiresSeconds: 3600,
	}
	rr := doPresign(t, handler, cookies, "presign-get-bucket", req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp presignResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	// Verify response fields.
	if resp.Method != "GET" {
		t.Errorf("expected method 'GET', got %q", resp.Method)
	}
	if resp.ExpiresSeconds != 3600 {
		t.Errorf("expected expiresSeconds 3600, got %d", resp.ExpiresSeconds)
	}
	if resp.URL == "" {
		t.Error("URL should not be empty")
	}
}

// Test 2: valid session + CSRF + PUT presign → 200 success
func TestPresign_PUT_Success(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "presign-put-bucket")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d: %s", createRR.Code, createRR.Body.String())
	}

	// Generate presigned PUT URL.
	req := presignRequest{
		Key:            "upload/new-file.txt",
		Method:         "PUT",
		ExpiresSeconds: 1800, // 30 minutes, within test config max TTL
	}
	rr := doPresign(t, handler, cookies, "presign-put-bucket", req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp presignResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	// Verify response fields.
	if resp.Method != "PUT" {
		t.Errorf("expected method 'PUT', got %q", resp.Method)
	}
	if resp.ExpiresSeconds != 1800 {
		t.Errorf("expected expiresSeconds 1800, got %d", resp.ExpiresSeconds)
	}
	if resp.URL == "" {
		t.Error("URL should not be empty")
	}
}

// Test 3: no session → 401
func TestPresign_NoSession(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket with session.
	createRR := doCreateBucket(t, handler, cookies, "presign-nosession")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Try to generate presigned URL without session.
	body, _ := json.Marshal(presignRequest{Key: "test.txt", Method: "GET", ExpiresSeconds: 3600})
	req := httptest.NewRequest(http.MethodPost, "/ui/api/buckets/presign-nosession/objects/presign", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 4: missing CSRF → 403
func TestPresign_MissingCSRF(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "presign-nocsrf")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Try to generate presigned URL without CSRF token.
	req := presignRequest{Key: "test.txt", Method: "GET", ExpiresSeconds: 3600}
	rr := doPresignWithoutCSRF(t, handler, cookies, "presign-nocsrf", req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 5: invalid bucket name → 400
func TestPresign_InvalidBucketName(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Try with invalid bucket name (too short).
	req := presignRequest{Key: "test.txt", Method: "GET", ExpiresSeconds: 3600}
	rr := doPresign(t, handler, cookies, "ab", req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if resp["error"] != "invalid bucket name" {
		t.Errorf("expected 'invalid bucket name', got %q", resp["error"])
	}
}

// Test 6: missing bucket → 404
func TestPresign_MissingBucket(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Try with non-existent bucket.
	req := presignRequest{Key: "test.txt", Method: "GET", ExpiresSeconds: 3600}
	rr := doPresign(t, handler, cookies, "nonexistent-bucket", req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if resp["error"] != "bucket not found" {
		t.Errorf("expected 'bucket not found', got %q", resp["error"])
	}
}

// Test 7: missing key → 400
func TestPresign_MissingKey(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "presign-nokey")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Try with empty key.
	req := presignRequest{Key: "", Method: "GET", ExpiresSeconds: 3600}
	rr := doPresign(t, handler, cookies, "presign-nokey", req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if resp["error"] != "key is required" {
		t.Errorf("expected 'key is required', got %q", resp["error"])
	}
}

// Test 8: invalid method → 400
func TestPresign_InvalidMethod(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "presign-badmethod")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Try with invalid method.
	req := presignRequest{Key: "test.txt", Method: "DELETE", ExpiresSeconds: 3600}
	rr := doPresign(t, handler, cookies, "presign-badmethod", req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if resp["error"] != "method must be GET or PUT" {
		t.Errorf("expected 'method must be GET or PUT', got %q", resp["error"])
	}
}

// Test 9: expiresSeconds too large → 400
func TestPresign_ExpiresSecondsTooLarge(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "presign-bigexpires")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d", createRR.Code)
	}

	// Try with expires larger than max_presign_ttl (default 24h = 86400s, but test config uses 1h = 3600s).
	// The test config uses 1h max TTL, so 7200s should exceed it.
	req := presignRequest{Key: "test.txt", Method: "GET", ExpiresSeconds: 7200}
	rr := doPresign(t, handler, cookies, "presign-bigexpires", req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if resp["error"] != "expiresSeconds exceeds maximum allowed TTL" {
		t.Errorf("expected 'expiresSeconds exceeds maximum allowed TTL', got %q", resp["error"])
	}
}

// Test 10: generated URL contains X-Amz-* params
func TestPresign_URLContainsAmzParams(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "presign-params")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d: %s", createRR.Code, createRR.Body.String())
	}

	// Generate presigned URL.
	req := presignRequest{Key: "test-object.txt", Method: "GET", ExpiresSeconds: 600}
	rr := doPresign(t, handler, cookies, "presign-params", req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp presignResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	// Verify URL contains required X-Amz-* parameters.
	parsedURL, err := url.Parse(resp.URL)
	if err != nil {
		t.Fatalf("parsing URL: %v", err)
	}

	query := parsedURL.Query()
	requiredParams := []string{
		"X-Amz-Algorithm",
		"X-Amz-Credential",
		"X-Amz-Date",
		"X-Amz-Expires",
		"X-Amz-SignedHeaders",
		"X-Amz-Signature",
	}
	for _, param := range requiredParams {
		if query.Get(param) == "" {
			t.Errorf("URL missing required parameter: %s", param)
		}
	}

	// Verify X-Amz-Algorithm is AWS4-HMAC-SHA256.
	if query.Get("X-Amz-Algorithm") != "AWS4-HMAC-SHA256" {
		t.Errorf("expected X-Amz-Algorithm=AWS4-HMAC-SHA256, got %q", query.Get("X-Amz-Algorithm"))
	}

	// Verify X-Amz-Expires matches requested value.
	if query.Get("X-Amz-Expires") != "600" {
		t.Errorf("expected X-Amz-Expires=600, got %q", query.Get("X-Amz-Expires"))
	}

	// Verify X-Amz-SignedHeaders includes host.
	if !strings.Contains(query.Get("X-Amz-SignedHeaders"), "host") {
		t.Errorf("expected X-Amz-SignedHeaders to include 'host', got %q", query.Get("X-Amz-SignedHeaders"))
	}
}

// Test 11: round-trip verification - generated URL passes PresignVerifier
func TestPresign_RoundTripVerification(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "presign-verify")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d: %s", createRR.Code, createRR.Body.String())
	}

	// Generate presigned GET URL.
	presignReq := presignRequest{Key: "verify-object.txt", Method: "GET", ExpiresSeconds: 300}
	presignRR := doPresign(t, handler, cookies, "presign-verify", presignReq)
	if presignRR.Code != http.StatusOK {
		t.Fatalf("presign failed: %d: %s", presignRR.Code, presignRR.Body.String())
	}

	var presignResp presignResponse
	if err := json.Unmarshal(presignRR.Body.Bytes(), &presignResp); err != nil {
		t.Fatalf("parsing presign response: %v", err)
	}

	// Parse the generated URL.
	parsedURL, err := url.Parse(presignResp.URL)
	if err != nil {
		t.Fatalf("parsing presigned URL: %v", err)
	}

	// Create an HTTP request from the presigned URL.
	verifyReq := httptest.NewRequest(http.MethodGet, parsedURL.RequestURI(), nil)
	verifyReq.Host = parsedURL.Host
	verifyReq.URL.RawQuery = parsedURL.RawQuery

	// Create a PresignVerifier with the same config as the server.
	verifier := auth.PresignVerifier{
		Region:  testRegion,
		Service: "s3",
		MaxTTL:  1 * time.Hour, // Same as test config MaxPresignTTL
		GetSecret: func(accessKeyID string) (string, bool, error) {
			// Look up the secret from the test bootstrap credentials.
			if accessKeyID == testAccessKey {
				return testRootSecretKey, true, nil
			}
			return "", false, nil
		},
	}

	// Verify the presigned URL signature.
	if err := verifier.Verify(verifyReq); err != nil {
		t.Errorf("presigned URL verification failed: %v", err)
	}
}

// Test 12: key with slashes works
func TestPresign_KeyWithSlashes(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "presign-slashes")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d: %s", createRR.Code, createRR.Body.String())
	}

	// Generate presigned URL with nested key.
	req := presignRequest{Key: "path/to/nested/file.txt", Method: "GET", ExpiresSeconds: 600}
	rr := doPresign(t, handler, cookies, "presign-slashes", req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp presignResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	// Verify URL contains the key path (URL-encoded).
	if !strings.Contains(resp.URL, "path") || !strings.Contains(resp.URL, "nested") {
		t.Errorf("URL should contain key path components, got %q", resp.URL)
	}
}

// Test 13: GET method not allowed (only POST)
func TestPresign_GETMethodNotAllowed(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "presign-getmethod")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d: %s", createRR.Code, createRR.Body.String())
	}

	// Try GET request to presign endpoint.
	url := "/ui/api/buckets/presign-getmethod/objects/presign"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 14: expiresSeconds zero or negative → 400
func TestPresign_ExpiresSecondsInvalid(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "presign-invalidexp")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d: %s", createRR.Code, createRR.Body.String())
	}

	// Try with zero expires.
	req := presignRequest{Key: "test.txt", Method: "GET", ExpiresSeconds: 0}
	rr := doPresign(t, handler, cookies, "presign-invalidexp", req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if resp["error"] != "expiresSeconds must be positive" {
		t.Errorf("expected 'expiresSeconds must be positive', got %q", resp["error"])
	}

	// Try with negative expires.
	req = presignRequest{Key: "test.txt", Method: "GET", ExpiresSeconds: -100}
	rr = doPresign(t, handler, cookies, "presign-invalidexp", req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 15: lowercase method accepted (case-insensitive)
func TestPresign_LowercaseMethod(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Create a bucket.
	createRR := doCreateBucket(t, handler, cookies, "presign-lowercase")
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create bucket failed: %d: %s", createRR.Code, createRR.Body.String())
	}

	// Try with lowercase method.
	req := presignRequest{Key: "test.txt", Method: "get", ExpiresSeconds: 600}
	rr := doPresign(t, handler, cookies, "presign-lowercase", req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp presignResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	// Verify method is normalized to uppercase.
	if resp.Method != "GET" {
		t.Errorf("expected method 'GET', got %q", resp.Method)
	}
}
