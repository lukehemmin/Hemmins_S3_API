package ui_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

// doDashboard issues GET /ui/api/dashboard with the given cookies.
func doDashboard(t *testing.T, handler http.Handler, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/ui/api/dashboard", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// doBuckets issues GET /ui/api/buckets with the given cookies.
func doBuckets(t *testing.T, handler http.Handler, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/ui/api/buckets", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// Test 1: GET /ui/api/dashboard with a valid session returns 200.
func TestDashboard_ValidSession(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doDashboard(t, handler, loginRR.Result().Cookies())
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 2: GET /ui/api/dashboard without a session returns 401.
func TestDashboard_NoSession(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	rr := doDashboard(t, handler, nil)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// Test 3: dashboard stats reflect the actual DB contents.
func TestDashboard_StatsReflectDB(t *testing.T) {
	handler, db := setupTestUIServer(t, false)

	// Insert one bucket and one object.
	if err := db.CreateBucket("stats-bucket", time.Now()); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	if err := db.UpsertObject("stats-bucket", "obj.txt", metadata.PutObjectInput{
		Size:         2048,
		ETag:         "abc123",
		ContentType:  "text/plain",
		StoragePath:  "/dev/null",
		LastModified: time.Now(),
		MetadataJSON: "{}",
	}); err != nil {
		t.Fatalf("UpsertObject: %v", err)
	}

	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doDashboard(t, handler, loginRR.Result().Cookies())
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var stats struct {
		TotalBuckets           int   `json:"totalBuckets"`
		TotalObjects           int   `json:"totalObjects"`
		TotalBytes             int64 `json:"totalBytes"`
		ActiveMultipartUploads int   `json:"activeMultipartUploads"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &stats); err != nil {
		t.Fatalf("parsing dashboard response: %v", err)
	}
	if stats.TotalBuckets != 1 {
		t.Errorf("totalBuckets: got %d, want 1", stats.TotalBuckets)
	}
	if stats.TotalObjects != 1 {
		t.Errorf("totalObjects: got %d, want 1", stats.TotalObjects)
	}
	if stats.TotalBytes != 2048 {
		t.Errorf("totalBytes: got %d, want 2048", stats.TotalBytes)
	}
	if stats.ActiveMultipartUploads != 0 {
		t.Errorf("activeMultipartUploads: got %d, want 0", stats.ActiveMultipartUploads)
	}
}

// Test 4: GET /ui/api/buckets with a valid session returns 200.
func TestBuckets_ValidSession(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doBuckets(t, handler, loginRR.Result().Cookies())
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test 5: GET /ui/api/buckets without a session returns 401.
func TestBuckets_NoSession(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)
	rr := doBuckets(t, handler, nil)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// Test 6: buckets response contains name and a valid RFC3339 creationDate for each bucket.
func TestBuckets_ResponseContainsFields(t *testing.T) {
	handler, db := setupTestUIServer(t, false)

	created := time.Now().UTC().Truncate(time.Second)
	if err := db.CreateBucket("field-check-bucket", created); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}

	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login: %d", loginRR.Code)
	}

	rr := doBuckets(t, handler, loginRR.Result().Cookies())
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var items []struct {
		Name         string `json:"name"`
		CreationDate string `json:"creationDate"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &items); err != nil {
		t.Fatalf("parsing buckets response: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 bucket, got %d", len(items))
	}
	if items[0].Name != "field-check-bucket" {
		t.Errorf("name: got %q, want %q", items[0].Name, "field-check-bucket")
	}
	if items[0].CreationDate == "" {
		t.Error("creationDate must not be empty")
	}
	if _, err := time.Parse(time.RFC3339, items[0].CreationDate); err != nil {
		t.Errorf("creationDate not valid RFC3339: %q — %v", items[0].CreationDate, err)
	}
}
