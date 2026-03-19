package s3_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

// insertObject inserts a minimal object row into the objects table for testing.
// bucket must already exist. This helper bypasses the Object API to set up
// non-empty bucket preconditions directly.
func insertObject(t *testing.T, db *metadata.DB, bucketName, objectKey string) {
	t.Helper()
	_, err := db.SQLDB().Exec(
		`INSERT INTO objects
		 (bucket_id, object_key, size, etag, content_type, storage_path, last_modified)
		 VALUES (
		   (SELECT id FROM buckets WHERE name = ?),
		   ?, 0, 'etag', 'application/octet-stream', 'staging/test', ?
		 )`,
		bucketName, objectKey, time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		t.Fatalf("insertObject bucket=%q key=%q: %v", bucketName, objectKey, err)
	}
}

// ---- 1. DELETE /existing-empty-bucket → 204 No Content ----

func TestDeleteBucket_Success(t *testing.T) {
	handler, db := setupTestServer(t)
	insertBucket(t, db, "to-delete", time.Now())

	r := makeSignedRequest(t, http.MethodDelete, "/to-delete", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d; body: %s", resp.StatusCode, body)
	}
}

// ---- 2. DELETE /missing-bucket → 404 NoSuchBucket ----

func TestDeleteBucket_Missing(t *testing.T) {
	handler, _ := setupTestServer(t)

	r := makeSignedRequest(t, http.MethodDelete, "/ghost-bucket", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d; body: %s", resp.StatusCode, body)
	}
	if code := xmlErrorCode(t, body); code != "NoSuchBucket" {
		t.Errorf("error code: got %q, want NoSuchBucket", code)
	}
}

// ---- 3. DELETE /non-empty-bucket → 409 BucketNotEmpty ----

func TestDeleteBucket_NonEmpty(t *testing.T) {
	handler, db := setupTestServer(t)
	insertBucket(t, db, "full-bucket", time.Now())
	insertObject(t, db, "full-bucket", "some-key")

	r := makeSignedRequest(t, http.MethodDelete, "/full-bucket", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusConflict {
		t.Errorf("expected 409, got %d; body: %s", resp.StatusCode, body)
	}
	if code := xmlErrorCode(t, body); code != "BucketNotEmpty" {
		t.Errorf("error code: got %q, want BucketNotEmpty", code)
	}
}

// ---- 4. Invalid bucket name → 400 InvalidBucketName ----

func TestDeleteBucket_InvalidName(t *testing.T) {
	handler, _ := setupTestServer(t)

	// "ab" is too short (< 3 chars).
	r := makeSignedRequest(t, http.MethodDelete, "/ab", time.Now())
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

// ---- 5. Unauthenticated DELETE → 403 AccessDenied ----

func TestDeleteBucket_Unauthenticated(t *testing.T) {
	handler, _ := setupTestServer(t)

	r, _ := http.NewRequest(http.MethodDelete, "http://"+testHost+"/some-bucket", nil)
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

// ---- 6. Router path mapping for DELETE /{bucket} ----

func TestRouter_DeleteBucket_PathMapping(t *testing.T) {
	handler, db := setupTestServer(t)
	now := time.Now()
	insertBucket(t, db, "empty-routed", now)

	cases := []struct {
		method     string
		path       string
		wantStatus int
		desc       string
	}{
		// DELETE /existing-empty-bucket → 204
		{http.MethodDelete, "/empty-routed", http.StatusNoContent, "DELETE /empty-bucket → 204"},
		// DELETE /missing-bucket → 404
		{http.MethodDelete, "/no-such-bucket", http.StatusNotFound, "DELETE /missing → 404"},
		// DELETE /bucket/key → object-level → 501
		{http.MethodDelete, "/empty-routed/key", http.StatusNotImplemented, "DELETE /bucket/key → 501"},
		// DELETE / → service root → 501
		{http.MethodDelete, "/", http.StatusNotImplemented, "DELETE / → 501"},
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

// ---- 7. Success response body is empty (0 bytes) ----

func TestDeleteBucket_SuccessBodyEmpty(t *testing.T) {
	handler, db := setupTestServer(t)
	insertBucket(t, db, "body-check-del", time.Now())

	r := makeSignedRequest(t, http.MethodDelete, "/body-check-del", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Errorf("expected 0 bytes in DELETE 204 body, got %d: %s", len(body), body)
	}
}

// ---- 8. Metadata BucketIsEmpty unit test ----

func TestMetadataBucketIsEmpty(t *testing.T) {
	db, err := metadata.Open(":memory:")
	if err != nil {
		t.Fatalf("metadata.Open: %v", err)
	}
	defer db.Close()

	// Empty bucket.
	_, err = db.SQLDB().Exec(
		"INSERT INTO buckets (name, created_at) VALUES (?, ?)",
		"test-bucket", time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		t.Fatalf("insert bucket: %v", err)
	}

	empty, err := db.BucketIsEmpty("test-bucket")
	if err != nil {
		t.Fatalf("BucketIsEmpty(test-bucket): %v", err)
	}
	if !empty {
		t.Error("BucketIsEmpty(test-bucket): expected true (no objects), got false")
	}

	// Insert an object row to make it non-empty.
	_, err = db.SQLDB().Exec(
		`INSERT INTO objects
		 (bucket_id, object_key, size, etag, content_type, storage_path, last_modified)
		 VALUES (
		   (SELECT id FROM buckets WHERE name = 'test-bucket'),
		   'key.txt', 0, 'etag', 'text/plain', 'staging/x', ?
		 )`,
		time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		t.Fatalf("insert object: %v", err)
	}

	empty, err = db.BucketIsEmpty("test-bucket")
	if err != nil {
		t.Fatalf("BucketIsEmpty after insert: %v", err)
	}
	if empty {
		t.Error("BucketIsEmpty after insert: expected false, got true")
	}
}

// ---- 9. Metadata DeleteBucket helper unit test ----

func TestMetadataDeleteBucket(t *testing.T) {
	db, err := metadata.Open(":memory:")
	if err != nil {
		t.Fatalf("metadata.Open: %v", err)
	}
	defer db.Close()

	// Missing bucket → ErrBucketNotFound.
	if err := db.DeleteBucket("no-bucket"); !isErr(err, metadata.ErrBucketNotFound) {
		t.Errorf("DeleteBucket(no-bucket): expected ErrBucketNotFound, got %v", err)
	}

	// Insert bucket and object → ErrBucketNotEmpty.
	_, _ = db.SQLDB().Exec(
		"INSERT INTO buckets (name, created_at) VALUES (?, ?)",
		"occupied", time.Now().UTC().Format(time.RFC3339),
	)
	_, _ = db.SQLDB().Exec(
		`INSERT INTO objects
		 (bucket_id, object_key, size, etag, content_type, storage_path, last_modified)
		 VALUES (
		   (SELECT id FROM buckets WHERE name = 'occupied'),
		   'obj', 0, 'e', 'application/octet-stream', 'p', ?
		 )`,
		time.Now().UTC().Format(time.RFC3339),
	)
	if err := db.DeleteBucket("occupied"); !isErr(err, metadata.ErrBucketNotEmpty) {
		t.Errorf("DeleteBucket(occupied): expected ErrBucketNotEmpty, got %v", err)
	}

	// Insert an empty bucket → successful delete.
	_, _ = db.SQLDB().Exec(
		"INSERT INTO buckets (name, created_at) VALUES (?, ?)",
		"empty-one", time.Now().UTC().Format(time.RFC3339),
	)
	if err := db.DeleteBucket("empty-one"); err != nil {
		t.Errorf("DeleteBucket(empty-one): expected nil, got %v", err)
	}

	// Verify the row is actually gone.
	exists, _ := db.BucketExists("empty-one")
	if exists {
		t.Error("bucket row still present after DeleteBucket")
	}
}

// ---- 10. Idempotency check: second delete on same bucket returns NoSuchBucket ----

func TestDeleteBucket_SecondDeleteIsMissing(t *testing.T) {
	handler, db := setupTestServer(t)
	insertBucket(t, db, "once-bucket", time.Now())

	now := time.Now()

	// First delete succeeds.
	r1 := makeSignedRequest(t, http.MethodDelete, "/once-bucket", now)
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, r1)
	if w1.Result().StatusCode != http.StatusNoContent {
		t.Fatalf("first delete: expected 204, got %d", w1.Result().StatusCode)
	}

	// Second delete on the same (now-missing) bucket must return 404.
	r2 := makeSignedRequest(t, http.MethodDelete, "/once-bucket", now.Add(time.Second))
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, r2)

	resp := w2.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("second delete: expected 404, got %d; body: %s", resp.StatusCode, body)
	}
	if code := xmlErrorCode(t, body); code != "NoSuchBucket" {
		t.Errorf("error code: got %q, want NoSuchBucket", code)
	}
}

// ---- 11. Transactional atomicity: all four invariants of DeleteBucket's transaction ----

// TestMetadataDeleteBucket_AtomicTransaction verifies that DeleteBucket wraps its
// operations (SELECT id, emptiness check, DELETE, RowsAffected) in a single
// atomic transaction. Four cases are exercised:
//
//  1. Non-empty bucket → ErrBucketNotEmpty; the row must remain intact (tx rolled back).
//  2. Empty bucket → nil; the row must be absent after commit.
//  3. Bucket never existed → ErrBucketNotFound (SELECT id returns no rows).
//  4. Bucket deleted externally before DeleteBucket is called → ErrBucketNotFound
//     (simulates the concurrent-delete scenario that the RowsAffected check guards).
func TestMetadataDeleteBucket_AtomicTransaction(t *testing.T) {
	db, err := metadata.Open(":memory:")
	if err != nil {
		t.Fatalf("metadata.Open: %v", err)
	}
	defer db.Close()

	now := time.Now().UTC().Format(time.RFC3339)
	exec := func(query string, args ...interface{}) {
		t.Helper()
		if _, err := db.SQLDB().Exec(query, args...); err != nil {
			t.Fatalf("exec %q: %v", query, err)
		}
	}

	// Case 1: non-empty bucket → ErrBucketNotEmpty; row must still be present.
	exec("INSERT INTO buckets (name, created_at) VALUES (?, ?)", "at-nonempty", now)
	exec(
		`INSERT INTO objects (bucket_id, object_key, size, etag, content_type, storage_path, last_modified)
		 VALUES ((SELECT id FROM buckets WHERE name='at-nonempty'), 'k', 0, 'e', 'application/octet-stream', 'p', ?)`,
		now,
	)
	if got := db.DeleteBucket("at-nonempty"); got != metadata.ErrBucketNotEmpty {
		t.Errorf("case1: want ErrBucketNotEmpty, got %v", got)
	}
	if exists, _ := db.BucketExists("at-nonempty"); !exists {
		t.Error("case1: bucket must remain present after ErrBucketNotEmpty (tx must roll back)")
	}

	// Case 2: empty bucket → nil; row must be gone after commit.
	exec("INSERT INTO buckets (name, created_at) VALUES (?, ?)", "at-empty", now)
	if got := db.DeleteBucket("at-empty"); got != nil {
		t.Errorf("case2: want nil, got %v", got)
	}
	if exists, _ := db.BucketExists("at-empty"); exists {
		t.Error("case2: bucket row must be absent after committed delete")
	}

	// Case 3: bucket never existed → ErrBucketNotFound (SELECT id → no rows path).
	if got := db.DeleteBucket("at-never"); got != metadata.ErrBucketNotFound {
		t.Errorf("case3: want ErrBucketNotFound, got %v", got)
	}

	// Case 4: bucket deleted externally (concurrent simulation) → ErrBucketNotFound.
	// Insert then immediately delete via raw SQL; DeleteBucket must still return
	// ErrBucketNotFound rather than silently succeeding with rowsAffected=0.
	exec("INSERT INTO buckets (name, created_at) VALUES (?, ?)", "at-concurrent", now)
	exec("DELETE FROM buckets WHERE name = 'at-concurrent'")
	if got := db.DeleteBucket("at-concurrent"); got != metadata.ErrBucketNotFound {
		t.Errorf("case4: want ErrBucketNotFound after external delete, got %v", got)
	}
}

// isErr is a local helper to check errors.Is without importing "errors" at top-level
// (already imported via the test fixture helpers from list_buckets_test.go in the same package).
func isErr(err, target error) bool {
	if err == nil || target == nil {
		return err == target
	}
	return err.Error() == target.Error() || unwrapIs(err, target)
}

// unwrapIs walks the error chain checking each wrapped error.
func unwrapIs(err, target error) bool {
	type unwrapper interface{ Unwrap() error }
	for err != nil {
		if err == target {
			return true
		}
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
