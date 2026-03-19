package s3_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

// ---- 1. HEAD /existing-bucket → 200, empty body ----

func TestHeadBucket_Exists(t *testing.T) {
	handler, db := setupTestServer(t)
	insertBucket(t, db, "present-bucket", time.Now())

	r := makeSignedRequest(t, http.MethodHead, "/present-bucket", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", resp.StatusCode, body)
	}
	// Success HEAD body must be empty (RFC 7231 §4.3.2).
	if len(body) != 0 {
		t.Errorf("expected empty body for HEAD 200, got %d bytes: %s", len(body), body)
	}
}

// ---- 2. HEAD /missing-bucket → 404 NoSuchBucket ----

func TestHeadBucket_Missing(t *testing.T) {
	handler, _ := setupTestServer(t)
	// No bucket inserted — bucket definitely does not exist.

	r := makeSignedRequest(t, http.MethodHead, "/ghost-bucket", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()

	if resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("expected 404, got %d; body: %s", resp.StatusCode, body)
	}
}

// ---- 3. HEAD with invalid bucket name → 400 InvalidBucketName ----

func TestHeadBucket_InvalidName(t *testing.T) {
	handler, _ := setupTestServer(t)

	// "ab" is too short (< 3 chars).
	r := makeSignedRequest(t, http.MethodHead, "/ab", time.Now())
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

// ---- 4. Unauthenticated HEAD → 403 AccessDenied ----

func TestHeadBucket_Unauthenticated(t *testing.T) {
	handler, _ := setupTestServer(t)

	r, _ := http.NewRequest(http.MethodHead, "http://"+testHost+"/some-bucket", nil)
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

// ---- 5. Router path mapping for HEAD /{bucket} ----

func TestRouter_HeadBucket_PathMapping(t *testing.T) {
	handler, db := setupTestServer(t)
	now := time.Now()
	insertBucket(t, db, "routed-bucket", now)

	cases := []struct {
		method     string
		path       string
		wantStatus int
		desc       string
	}{
		// HEAD /{existing-bucket} → 200
		{http.MethodHead, "/routed-bucket", http.StatusOK, "HEAD /existing-bucket → 200"},
		// HEAD /{missing-bucket} → 404
		{http.MethodHead, "/no-such-bucket", http.StatusNotFound, "HEAD /missing-bucket → 404"},
		// HEAD /{bucket}/{key} → object-level → 501
		{http.MethodHead, "/routed-bucket/some-key", http.StatusNotImplemented, "HEAD /bucket/key → 501"},
		// HEAD / → service root → 501
		{http.MethodHead, "/", http.StatusNotImplemented, "HEAD / → 501"},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			r := makeSignedRequest(t, tc.method, tc.path, now)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)

			if got := w.Result().StatusCode; got != tc.wantStatus {
				t.Errorf("%s: expected %d, got %d; body: %s",
					tc.desc, tc.wantStatus, got, w.Body.String())
			}
		})
	}
}

// ---- 6. HEAD / (service root) → 501 NotImplemented ----

func TestHeadBucket_ServiceRoot_NotImplemented(t *testing.T) {
	handler, _ := setupTestServer(t)

	r := makeSignedRequest(t, http.MethodHead, "/", time.Now())
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

// ---- 7. Success response body is empty (0 bytes) ----

func TestHeadBucket_SuccessBodyEmpty(t *testing.T) {
	handler, db := setupTestServer(t)
	insertBucket(t, db, "body-check-bucket", time.Now())

	r := makeSignedRequest(t, http.MethodHead, "/body-check-bucket", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Errorf("expected 0 bytes in HEAD 200 body, got %d: %s", len(body), body)
	}

	// Content-Length (if set) should also reflect empty body.
	// net/http sets Content-Length: 0 automatically for HEAD 200 with no body.
	cl := resp.ContentLength
	if cl > 0 {
		t.Errorf("Content-Length: expected 0 or -1 (unset), got %d", cl)
	}
}

// ---- 8. Metadata BucketExists unit test ----

func TestMetadataBucketExists(t *testing.T) {
	db, err := metadata.Open(":memory:")
	if err != nil {
		t.Fatalf("metadata.Open: %v", err)
	}
	defer db.Close()

	// Non-existent bucket.
	exists, err := db.BucketExists("no-bucket")
	if err != nil {
		t.Fatalf("BucketExists(no-bucket): unexpected error: %v", err)
	}
	if exists {
		t.Error("BucketExists(no-bucket): expected false, got true")
	}

	// Insert a bucket directly.
	_, err = db.SQLDB().Exec(
		"INSERT INTO buckets (name, created_at) VALUES (?, ?)",
		"test-bucket", time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		t.Fatalf("direct insert: %v", err)
	}

	// Inserted bucket must be found.
	exists, err = db.BucketExists("test-bucket")
	if err != nil {
		t.Fatalf("BucketExists(test-bucket): unexpected error: %v", err)
	}
	if !exists {
		t.Error("BucketExists(test-bucket): expected true, got false")
	}

	// Different name must not match.
	exists, err = db.BucketExists("other-bucket")
	if err != nil {
		t.Fatalf("BucketExists(other-bucket): unexpected error: %v", err)
	}
	if exists {
		t.Error("BucketExists(other-bucket): expected false, got true")
	}
}
