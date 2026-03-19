package s3_test

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lukehemmin/hemmins-s3-api/internal/auth"
	s3 "github.com/lukehemmin/hemmins-s3-api/internal/http/s3"
	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

func setupPutObjectServer(t *testing.T) (http.Handler, *metadata.DB) {
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
	srv.SetStoragePaths(t.TempDir(), t.TempDir())
	return srv.Handler(), db
}

func bodyMD5Hex(body string) string {
	sum := md5.Sum([]byte(body))
	return hex.EncodeToString(sum[:])
}

type objectRowData struct {
	Size         int64
	ETag         string
	ContentType  string
	StoragePath  string
	MetadataJSON string
}

func queryObjectRow(t *testing.T, db *metadata.DB, bucketName, objectKey string) objectRowData {
	t.Helper()
	var row objectRowData
	err := db.SQLDB().QueryRow(`
		SELECT o.size, o.etag, o.content_type, o.storage_path, o.metadata_json
		FROM objects o
		JOIN buckets b ON o.bucket_id = b.id
		WHERE b.name = ? AND o.object_key = ?
	`, bucketName, objectKey).Scan(
		&row.Size, &row.ETag, &row.ContentType, &row.StoragePath, &row.MetadataJSON,
	)
	if err != nil {
		t.Fatalf("queryObjectRow(%q, %q): %v", bucketName, objectKey, err)
	}
	return row
}

func TestPutObject_Success(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	insertBucket(t, db, "my-bucket", time.Now())

	r := makeSignedPutRequest(t, "/my-bucket/hello.txt", "hello, world", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

func TestPutObject_ZeroByte(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	insertBucket(t, db, "my-bucket", time.Now())

	r := makeSignedPutRequest(t, "/my-bucket/zero.bin", "", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	want := `"` + bodyMD5Hex("") + `"`
	if got := w.Header().Get("ETag"); got != want {
		t.Errorf("ETag = %q, want %q", got, want)
	}
}

func TestPutObject_NoAuth(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	insertBucket(t, db, "my-bucket", time.Now())

	r, err := http.NewRequest(http.MethodPut, "http://"+testHost+"/my-bucket/key.txt", strings.NewReader("data"))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	r.Host = testHost

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "AccessDenied" {
		t.Errorf("error code = %q, want AccessDenied", code)
	}
}

func TestPutObject_InvalidAuth(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	insertBucket(t, db, "my-bucket", time.Now())

	r := makeSignedPutRequest(t, "/my-bucket/key.txt", "content", time.Now())
	orig := r.Header.Get("Authorization")
	r.Header.Set("Authorization", orig[:len(orig)-8]+"00000000")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body: %s", w.Code, w.Body.String())
	}
}

func TestPutObject_NoSuchBucket(t *testing.T) {
	handler, _ := setupPutObjectServer(t)

	r := makeSignedPutRequest(t, "/ghost-bucket/key.txt", "data", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "NoSuchBucket" {
		t.Errorf("error code = %q, want NoSuchBucket", code)
	}
}

func TestPutObject_InvalidBucketName(t *testing.T) {
	handler, _ := setupPutObjectServer(t)

	r := makeSignedPutRequest(t, "/AB/key.txt", "data", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "InvalidBucketName" {
		t.Errorf("error code = %q, want InvalidBucketName", code)
	}
}

func TestPutObject_EmptyKey(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	insertBucket(t, db, "my-bucket", time.Now())

	r := makeSignedPutRequest(t, "/my-bucket/", "data", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "InvalidRequest" {
		t.Errorf("error code = %q, want InvalidRequest", code)
	}
}

func TestPutObject_KeyWithSlashes(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	insertBucket(t, db, "my-bucket", time.Now())

	const body = "deep content"
	r := makeSignedPutRequest(t, "/my-bucket/folder/sub/file.dat", body, time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	row := queryObjectRow(t, db, "my-bucket", "folder/sub/file.dat")
	if row.ETag != bodyMD5Hex(body) {
		t.Errorf("etag = %q, want %q", row.ETag, bodyMD5Hex(body))
	}
}

func TestPutObject_ETagFormat(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	insertBucket(t, db, "my-bucket", time.Now())

	const body = "etag test content"
	r := makeSignedPutRequest(t, "/my-bucket/etag.txt", body, time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	wantHeader := `"` + bodyMD5Hex(body) + `"`
	if got := w.Header().Get("ETag"); got != wantHeader {
		t.Errorf("ETag header = %q, want %q", got, wantHeader)
	}
	row := queryObjectRow(t, db, "my-bucket", "etag.txt")
	if row.ETag != bodyMD5Hex(body) {
		t.Errorf("DB etag = %q, want raw hex %q (no quotes)", row.ETag, bodyMD5Hex(body))
	}
}

func TestPutObject_MetadataRow(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	insertBucket(t, db, "my-bucket", time.Now())

	const body = "metadata row content"
	r := makeSignedPutRequest(t, "/my-bucket/data.bin", body, time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	row := queryObjectRow(t, db, "my-bucket", "data.bin")
	if want := int64(len(body)); row.Size != want {
		t.Errorf("size = %d, want %d", row.Size, want)
	}
	if row.ETag != bodyMD5Hex(body) {
		t.Errorf("etag = %q, want %q", row.ETag, bodyMD5Hex(body))
	}
	if row.StoragePath == "" {
		t.Error("storage_path is empty")
	}
}

func TestPutObject_Overwrite(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	insertBucket(t, db, "my-bucket", time.Now())

	const key = "/my-bucket/overwrite.txt"
	const body1 = "first version"
	r1 := makeSignedPutRequest(t, key, body1, time.Now())
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, r1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first PUT: status = %d, want 200", w1.Code)
	}

	const body2 = "second version - longer content"
	r2 := makeSignedPutRequest(t, key, body2, time.Now())
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, r2)
	if w2.Code != http.StatusOK {
		t.Fatalf("second PUT: status = %d, want 200", w2.Code)
	}

	row := queryObjectRow(t, db, "my-bucket", "overwrite.txt")
	if want := int64(len(body2)); row.Size != want {
		t.Errorf("size = %d, want %d", row.Size, want)
	}
	if row.ETag != bodyMD5Hex(body2) {
		t.Errorf("etag = %q, want %q (second version)", row.ETag, bodyMD5Hex(body2))
	}

	var count int
	if err := db.SQLDB().QueryRow(`
		SELECT COUNT(*) FROM objects o JOIN buckets b ON o.bucket_id = b.id
		WHERE b.name = 'my-bucket' AND o.object_key = 'overwrite.txt'
	`).Scan(&count); err != nil {
		t.Fatalf("count query: %v", err)
	}
	if count != 1 {
		t.Errorf("row count = %d, want 1 (UPSERT must replace)", count)
	}
}

func TestPutObject_ContentType(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	insertBucket(t, db, "my-bucket", time.Now())

	r := makeSignedPutRequest(t, "/my-bucket/page.html", "<html/>", time.Now())
	r.Header.Set("Content-Type", "text/html; charset=utf-8")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	row := queryObjectRow(t, db, "my-bucket", "page.html")
	if want := "text/html; charset=utf-8"; row.ContentType != want {
		t.Errorf("content_type = %q, want %q", row.ContentType, want)
	}
}

func TestPutObject_DefaultContentType(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	insertBucket(t, db, "my-bucket", time.Now())

	r := makeSignedPutRequest(t, "/my-bucket/binary.bin", "binary data", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	row := queryObjectRow(t, db, "my-bucket", "binary.bin")
	if want := "application/octet-stream"; row.ContentType != want {
		t.Errorf("content_type = %q, want %q", row.ContentType, want)
	}
}

func TestPutObject_UserMetadata(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	insertBucket(t, db, "my-bucket", time.Now())

	r := makeSignedPutRequest(t, "/my-bucket/meta.txt", "payload", time.Now())
	r.Header.Set("X-Amz-Meta-Author", "alice")
	r.Header.Set("X-Amz-Meta-Project", "demo")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	row := queryObjectRow(t, db, "my-bucket", "meta.txt")
	var got map[string]string
	if err := json.Unmarshal([]byte(row.MetadataJSON), &got); err != nil {
		t.Fatalf("parsing metadata_json %q: %v", row.MetadataJSON, err)
	}
	if got["author"] != "alice" {
		t.Errorf("metadata[author] = %q, want alice", got["author"])
	}
	if got["project"] != "demo" {
		t.Errorf("metadata[project] = %q, want demo", got["project"])
	}
}

func TestPutObject_RoutingVsBucket(t *testing.T) {
	handler, _ := setupPutObjectServer(t)

	r := makeSignedPutRequest(t, "/new-bucket", "", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("PUT /bucket (CreateBucket): status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

// ---- Content-MD5 validation ----

func TestPutObject_ContentMD5_Correct(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	insertBucket(t, db, "my-bucket", time.Now())

	const body = "verified content"
	sum := md5.Sum([]byte(body))
	contentMD5 := base64.StdEncoding.EncodeToString(sum[:])

	r := makeSignedPutRequest(t, "/my-bucket/verified.txt", body, time.Now())
	r.Header.Set("Content-MD5", contentMD5)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

func TestPutObject_ContentMD5_Malformed(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	insertBucket(t, db, "my-bucket", time.Now())

	// "!!invalid!!" contains characters outside the base64 alphabet.
	r := makeSignedPutRequest(t, "/my-bucket/bad.txt", "data", time.Now())
	r.Header.Set("Content-MD5", "!!invalid!!")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "InvalidDigest" {
		t.Errorf("error code = %q, want InvalidDigest", code)
	}
}

func TestPutObject_ContentMD5_Mismatch(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	insertBucket(t, db, "my-bucket", time.Now())

	// Declare the MD5 of a different string so it won't match the actual body.
	wrongSum := md5.Sum([]byte("this is NOT the body"))
	contentMD5 := base64.StdEncoding.EncodeToString(wrongSum[:])

	r := makeSignedPutRequest(t, "/my-bucket/mismatch.txt", "actual body content", time.Now())
	r.Header.Set("Content-MD5", contentMD5)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "BadDigest" {
		t.Errorf("error code = %q, want BadDigest", code)
	}

	// Metadata must NOT be committed when digest mismatches.
	var count int
	if err := db.SQLDB().QueryRow(`
		SELECT COUNT(*) FROM objects o JOIN buckets b ON o.bucket_id = b.id
		WHERE b.name = 'my-bucket' AND o.object_key = 'mismatch.txt'
	`).Scan(&count); err != nil {
		t.Fatalf("count query: %v", err)
	}
	if count != 0 {
		t.Errorf("row count = %d, want 0 (metadata must not be committed on BadDigest)", count)
	}
}

func TestPutObject_ContentMD5_Absent(t *testing.T) {
	handler, db := setupPutObjectServer(t)
	insertBucket(t, db, "my-bucket", time.Now())

	// No Content-MD5 header → upload proceeds normally.
	r := makeSignedPutRequest(t, "/my-bucket/no-md5.txt", "content without md5", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

// TestPutObject_InternalError_NoLeak verifies that storage failures return a generic
// InternalError message and do not expose internal details (file paths, OS errors)
// in the XML response body. Per security-model.md section 4.3.
func TestPutObject_InternalError_NoLeak(t *testing.T) {
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

	// Point tempRoot at a non-existent directory so AtomicWrite fails with an OS error.
	// The actual error text must NOT appear in the XML response body.
	const badTempRoot = "/tmp/hemmins-test-nonexistent-dir-abc123xyz"
	srv := s3.NewServer(db, testRegion, testMasterKey)
	srv.SetStoragePaths(badTempRoot, t.TempDir())
	handler := srv.Handler()

	insertBucket(t, db, "my-bucket", time.Now())

	r := makeSignedPutRequest(t, "/my-bucket/key.txt", "data", time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "InternalError" {
		t.Errorf("error code = %q, want InternalError", code)
	}
	// The XML body must not leak the storage path or OS error details.
	body := w.Body.String()
	if strings.Contains(body, badTempRoot) {
		t.Error("InternalError response leaks internal storage path in XML body")
	}
	if strings.Contains(body, "nonexistent") {
		t.Error("InternalError response leaks internal error message in XML body")
	}
}
