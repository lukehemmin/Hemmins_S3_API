package s3_test

import (
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lukehemmin/hemmins-s3-api/internal/auth"
	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

// queryLastUsed reads last_used_at for keyID directly from the DB.
// Returns nil when the column is NULL (key has never been used).
func queryLastUsed(t *testing.T, db *metadata.DB, keyID string) *time.Time {
	t.Helper()
	var s sql.NullString
	err := db.SQLDB().QueryRow(
		"SELECT last_used_at FROM access_keys WHERE access_key = ?", keyID,
	).Scan(&s)
	if err != nil {
		t.Fatalf("queryLastUsed: %v", err)
	}
	if !s.Valid {
		return nil
	}
	ts, parseErr := time.Parse(time.RFC3339, s.String)
	if parseErr != nil {
		t.Fatalf("queryLastUsed parse: %v", parseErr)
	}
	return &ts
}

// ---- 1. Header auth success → last_used_at NULL → non-NULL ----

func TestLastUsed_HeaderAuth_UpdatesOnSuccess(t *testing.T) {
	handler, db := setupTestServer(t)

	// Precondition: last_used_at is NULL (bootstrap never marks it used).
	before := queryLastUsed(t, db, testAccessKey)
	if before != nil {
		t.Fatalf("precondition: expected last_used_at=NULL, got %v", before)
	}

	r := makeSignedRequest(t, http.MethodGet, "/", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if got := w.Result().StatusCode; got != http.StatusOK {
		body, _ := io.ReadAll(w.Result().Body)
		t.Fatalf("expected 200, got %d; body: %s", got, body)
	}

	after := queryLastUsed(t, db, testAccessKey)
	if after == nil {
		t.Error("last_used_at: expected non-NULL after successful header auth, got NULL")
	}
}

// ---- 2. Presign auth success → last_used_at updated ----

func TestLastUsed_PresignAuth_UpdatesOnSuccess(t *testing.T) {
	handler, db := setupTestServer(t)

	before := queryLastUsed(t, db, testAccessKey)
	if before != nil {
		t.Fatalf("precondition: expected last_used_at=NULL, got %v", before)
	}

	r := makePresignRequest(t, time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if got := w.Result().StatusCode; got != http.StatusOK {
		body, _ := io.ReadAll(w.Result().Body)
		t.Fatalf("expected 200, got %d; body: %s", got, body)
	}

	after := queryLastUsed(t, db, testAccessKey)
	if after == nil {
		t.Error("last_used_at: expected non-NULL after successful presign auth, got NULL")
	}
}

// ---- 3. Unauthenticated request → last_used_at unchanged (remains NULL) ----

func TestLastUsed_Unauthenticated_Unchanged(t *testing.T) {
	handler, db := setupTestServer(t)

	r, _ := http.NewRequest(http.MethodGet, "http://"+testHost+"/", nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if got := w.Result().StatusCode; got != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", got)
	}

	after := queryLastUsed(t, db, testAccessKey)
	if after != nil {
		t.Errorf("last_used_at: expected NULL after unauthenticated request, got %v", after)
	}
}

// ---- 4. Malformed Authorization → last_used_at unchanged ----

func TestLastUsed_MalformedAuth_Unchanged(t *testing.T) {
	handler, db := setupTestServer(t)

	r, _ := http.NewRequest(http.MethodGet, "http://"+testHost+"/", nil)
	r.Host = testHost
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 this-is-not-valid")
	r.Header.Set("X-Amz-Date", time.Now().UTC().Format("20060102T150405Z"))
	r.Header.Set("X-Amz-Content-Sha256",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if got := w.Result().StatusCode; got != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", got)
	}

	after := queryLastUsed(t, db, testAccessKey)
	if after != nil {
		t.Errorf("last_used_at: expected NULL after malformed auth, got %v", after)
	}
}

// ---- 5. Signature mismatch → last_used_at unchanged ----

func TestLastUsed_SignatureMismatch_Unchanged(t *testing.T) {
	handler, db := setupTestServer(t)

	now := time.Now().UTC()
	date := now.Format("20060102")
	dateTime := now.Format("20060102T150405Z")

	r, _ := http.NewRequest(http.MethodGet, "http://"+testHost+"/", nil)
	r.Host = testHost
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

	if got := w.Result().StatusCode; got != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", got)
	}

	after := queryLastUsed(t, db, testAccessKey)
	if after != nil {
		t.Errorf("last_used_at: expected NULL after signature mismatch, got %v", after)
	}
}

// NOTE: Test 6 (DB update failure simulation) is intentionally not automated here.
//
// Policy: if TouchAccessKeyLastUsed fails (e.g., DB is locked or unavailable),
// recordLastUsed() logs a warning and lets the request complete normally.
// This is documented and enforced in recordLastUsed() in auth.go.
//
// A full simulation would require either:
//   (a) closing the DB after authentication but before the update, which is
//       racy and unreliable in a unit test, or
//   (b) injecting a mock DB that returns errors — not yet in scope.
//
// The policy is explicitly documented in recordLastUsed() and enforced by the
// log.Printf (non-fatal) path. Future tests may use an error-injecting DB wrapper.
