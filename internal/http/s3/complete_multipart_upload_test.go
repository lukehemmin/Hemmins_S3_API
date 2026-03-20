package s3_test

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/lukehemmin/hemmins-s3-api/internal/auth"
	s3 "github.com/lukehemmin/hemmins-s3-api/internal/http/s3"
	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// setupCompleteMultipartServer creates a server configured for CompleteMultipartUpload tests.
// All three storage roots are separate TempDirs on the same filesystem.
// Returns the handler and the open metadata DB.
func setupCompleteMultipartServer(t *testing.T) (http.Handler, *metadata.DB) {
	t.Helper()
	handler, db, _ := setupCompleteMultipartServerWithRoots(t)
	return handler, db
}

// setupCompleteMultipartServerWithRoots is like setupCompleteMultipartServer but also
// returns the multipartRoot path for tests that need to inspect filesystem state.
func setupCompleteMultipartServerWithRoots(t *testing.T) (http.Handler, *metadata.DB, string) {
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

	multipartRoot := t.TempDir()
	srv := s3.NewServer(db, testRegion, testMasterKey)
	srv.SetStoragePaths(t.TempDir(), t.TempDir())
	srv.SetMultipartRoot(multipartRoot)
	srv.SetMultipartExpiry(24 * time.Hour)
	return srv.Handler(), db, multipartRoot
}

// completePartSpec is a (PartNumber, ETag) pair for building CompleteMultipartUpload XML.
// ETag may be quoted ("hex") or unquoted (hex).
type completePartSpec struct {
	PartNumber int
	ETag       string
}

// buildCompleteXML serializes a list of completePartSpec into the
// CompleteMultipartUpload XML request body.
func buildCompleteXML(parts []completePartSpec) string {
	var sb strings.Builder
	sb.WriteString("<CompleteMultipartUpload>")
	for _, p := range parts {
		fmt.Fprintf(&sb, "<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>",
			p.PartNumber, p.ETag)
	}
	sb.WriteString("</CompleteMultipartUpload>")
	return sb.String()
}

// makeSignedPostRequestWithBody builds a correctly-signed POST request with a body.
// Used to sign CompleteMultipartUpload requests that carry an XML body.
func makeSignedPostRequestWithBody(t *testing.T, path, body string, now time.Time) *http.Request {
	t.Helper()

	var bodyReader io.Reader
	var payloadHash string
	if body == "" {
		payloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	} else {
		bodyReader = strings.NewReader(body)
		payloadHash = auth.HashSHA256Hex([]byte(body))
	}

	r, err := http.NewRequest(http.MethodPost, "http://"+testHost+path, bodyReader)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	r.Host = testHost

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

// doComplete sends a CompleteMultipartUpload POST and returns the recorder.
func doComplete(t *testing.T, handler http.Handler, bucket, key, uploadID string, parts []completePartSpec, now time.Time) *httptest.ResponseRecorder {
	t.Helper()
	xmlBody := buildCompleteXML(parts)
	path := fmt.Sprintf("/%s/%s?uploadId=%s", bucket, key, uploadID)
	r := makeSignedPostRequestWithBody(t, path, xmlBody, now)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

// parseCompleteResult decodes a CompleteMultipartUploadResult XML body.
func parseCompleteResult(t *testing.T, body []byte) (bucket, key, etag, location string) {
	t.Helper()
	var result struct {
		Bucket   string `xml:"Bucket"`
		Key      string `xml:"Key"`
		ETag     string `xml:"ETag"`
		Location string `xml:"Location"`
	}
	if err := xml.Unmarshal(body, &result); err != nil {
		t.Fatalf("xml.Unmarshal CompleteMultipartUploadResult: %v\nbody: %s", err, body)
	}
	return result.Bucket, result.Key, result.ETag, result.Location
}

// uploadPartBody wraps doUploadPart and returns the quoted ETag from the response header.
func uploadPartBody(t *testing.T, handler http.Handler, bucket, key string, partNum int, uploadID, body string) string {
	t.Helper()
	w := doUploadPart(t, handler, bucket, key, partNum, uploadID, body)
	if w.Code != http.StatusOK {
		t.Fatalf("UploadPart %d: status=%d body=%s", partNum, w.Code, w.Body.String())
	}
	return w.Header().Get("ETag")
}

// multipartETagForData computes the expected AWS multipart ETag for a list of raw
// body strings (one per part). Used in tests to predict the expected ETag.
func multipartETagForData(parts ...string) string {
	h := md5.New()
	for _, p := range parts {
		sum := md5.Sum([]byte(p))
		h.Write(sum[:])
	}
	return hex.EncodeToString(h.Sum(nil)) + "-" + fmt.Sprintf("%d", len(parts))
}

// ── 1. single part complete success ──────────────────────────────────────────

func TestCompleteMultipartUpload_SinglePart_Success(t *testing.T) {
	handler, db := setupCompleteMultipartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())

	uploadID := createUpload(t, handler, "test-bucket", "single.bin")
	etag1 := uploadPartBody(t, handler, "test-bucket", "single.bin", 1, uploadID, "hello single part")

	w := doComplete(t, handler, "test-bucket", "single.bin", uploadID,
		[]completePartSpec{{1, etag1}}, time.Now())

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	bucket, key, etag, _ := parseCompleteResult(t, w.Body.Bytes())
	if bucket != "test-bucket" {
		t.Errorf("Bucket = %q, want test-bucket", bucket)
	}
	if key != "single.bin" {
		t.Errorf("Key = %q, want single.bin", key)
	}
	if etag == "" {
		t.Error("ETag is empty")
	}
	// XML namespace check.
	if !strings.Contains(w.Body.String(), "http://s3.amazonaws.com/doc/2006-03-01/") {
		t.Error("XML namespace not found in response body")
	}
}

// ── 2. multiple parts complete success ───────────────────────────────────────

func TestCompleteMultipartUpload_MultipleParts_Success(t *testing.T) {
	handler, db := setupCompleteMultipartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())

	// Part 1 must be ≥ 5 MiB (non-last part minimum). Part 2 is the last part.
	part1Data := strings.Repeat("a", 5*1024*1024)
	part2Data := "last-part-data"

	uploadID := createUpload(t, handler, "test-bucket", "multi.bin")
	etag1 := uploadPartBody(t, handler, "test-bucket", "multi.bin", 1, uploadID, part1Data)
	etag2 := uploadPartBody(t, handler, "test-bucket", "multi.bin", 2, uploadID, part2Data)

	w := doComplete(t, handler, "test-bucket", "multi.bin", uploadID,
		[]completePartSpec{{1, etag1}, {2, etag2}}, time.Now())

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	_, key, _, _ := parseCompleteResult(t, w.Body.Bytes())
	if key != "multi.bin" {
		t.Errorf("Key = %q, want multi.bin", key)
	}
}

// ── 3. PartNumber out of ascending order → InvalidPartOrder ──────────────────

func TestCompleteMultipartUpload_InvalidPartOrder(t *testing.T) {
	handler, db := setupCompleteMultipartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	insertSession(t, db, "upload-order", "test-bucket", "key.bin", time.Now().Add(24*time.Hour))
	insertPart(t, db, "upload-order", 1, "etag1", 100, time.Now())
	insertPart(t, db, "upload-order", 2, "etag2", 100, time.Now())

	// Submit parts in reverse order.
	w := doComplete(t, handler, "test-bucket", "key.bin", "upload-order",
		[]completePartSpec{{2, `"etag2"`}, {1, `"etag1"`}}, time.Now())

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "InvalidPartOrder" {
		t.Errorf("error code = %q, want InvalidPartOrder", code)
	}
}

// ── 4. ETag mismatch → InvalidPart ───────────────────────────────────────────

func TestCompleteMultipartUpload_ETagMismatch(t *testing.T) {
	handler, db := setupCompleteMultipartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	insertSession(t, db, "upload-etag", "test-bucket", "key.bin", time.Now().Add(24*time.Hour))
	insertPart(t, db, "upload-etag", 1, "deadbeefdeadbeef", 100, time.Now())

	// Submit wrong ETag for part 1.
	w := doComplete(t, handler, "test-bucket", "key.bin", "upload-etag",
		[]completePartSpec{{1, `"wrongetag"`}}, time.Now())

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "InvalidPart" {
		t.Errorf("error code = %q, want InvalidPart", code)
	}
}

// ── 5. missing part in DB → InvalidPart ──────────────────────────────────────

func TestCompleteMultipartUpload_MissingPart(t *testing.T) {
	handler, db := setupCompleteMultipartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	insertSession(t, db, "upload-missing", "test-bucket", "key.bin", time.Now().Add(24*time.Hour))
	// Only part 1 in DB; submit part 2 which doesn't exist.
	insertPart(t, db, "upload-missing", 1, "etag1", 100, time.Now())

	w := doComplete(t, handler, "test-bucket", "key.bin", "upload-missing",
		[]completePartSpec{{2, `"etag2"`}}, time.Now())

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "InvalidPart" {
		t.Errorf("error code = %q, want InvalidPart", code)
	}
}

// ── 6. non-last part < 5 MiB → EntityTooSmall ────────────────────────────────

func TestCompleteMultipartUpload_EntityTooSmall(t *testing.T) {
	handler, db := setupCompleteMultipartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	insertSession(t, db, "upload-small", "test-bucket", "key.bin", time.Now().Add(24*time.Hour))
	// Part 1 is only 1000 bytes (< 5 MiB). Part 2 is the last part (no minimum).
	insertPart(t, db, "upload-small", 1, "etag1", 1000, time.Now())
	insertPart(t, db, "upload-small", 2, "etag2", 500, time.Now())

	// ETags match DB so step 11 passes; step 12 should fail.
	w := doComplete(t, handler, "test-bucket", "key.bin", "upload-small",
		[]completePartSpec{{1, `"etag1"`}, {2, `"etag2"`}}, time.Now())

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "EntityTooSmall" {
		t.Errorf("error code = %q, want EntityTooSmall", code)
	}
}

// ── 7. expired upload → NoSuchUpload ─────────────────────────────────────────

func TestCompleteMultipartUpload_ExpiredUpload(t *testing.T) {
	handler, db := setupCompleteMultipartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	// Session expired 1 hour ago.
	insertSession(t, db, "upload-exp", "test-bucket", "key.bin", time.Now().Add(-1*time.Hour))

	w := doComplete(t, handler, "test-bucket", "key.bin", "upload-exp",
		[]completePartSpec{{1, `"etag1"`}}, time.Now())

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "NoSuchUpload" {
		t.Errorf("error code = %q, want NoSuchUpload", code)
	}
}

// ── 8. unauthenticated → AccessDenied ────────────────────────────────────────

func TestCompleteMultipartUpload_NoAuth(t *testing.T) {
	handler, db := setupCompleteMultipartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	insertSession(t, db, "upload-noauth", "test-bucket", "key.bin", time.Now().Add(24*time.Hour))

	xmlBody := buildCompleteXML([]completePartSpec{{1, `"etag1"`}})
	r, err := http.NewRequest(http.MethodPost,
		"http://"+testHost+"/test-bucket/key.bin?uploadId=upload-noauth",
		strings.NewReader(xmlBody))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	r.Host = testHost

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body: %s", w.Code, w.Body.String())
	}
	if code := xmlErrorCode(t, w.Body.Bytes()); code != "AccessDenied" {
		t.Errorf("error code = %q, want AccessDenied", code)
	}
}

// ── 9. success + GetObject returns merged content ────────────────────────────

func TestCompleteMultipartUpload_GetObjectAfterComplete(t *testing.T) {
	handler, db := setupCompleteMultipartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())

	bodyContent := "the final object body"
	uploadID := createUpload(t, handler, "test-bucket", "final.txt")
	etag1 := uploadPartBody(t, handler, "test-bucket", "final.txt", 1, uploadID, bodyContent)

	w := doComplete(t, handler, "test-bucket", "final.txt", uploadID,
		[]completePartSpec{{1, etag1}}, time.Now())
	if w.Code != http.StatusOK {
		t.Fatalf("complete status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	// GetObject should return the merged content.
	wg := doGet(t, handler, "/test-bucket/final.txt", time.Now())
	if wg.Code != http.StatusOK {
		t.Fatalf("GetObject status = %d, want 200; body: %s", wg.Code, wg.Body.String())
	}
	if got := wg.Body.String(); got != bodyContent {
		t.Errorf("GetObject body = %q, want %q", got, bodyContent)
	}
}

// ── 10. success + multipart_uploads row deleted ───────────────────────────────

func TestCompleteMultipartUpload_SessionRowDeleted(t *testing.T) {
	handler, db := setupCompleteMultipartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())

	uploadID := createUpload(t, handler, "test-bucket", "cleanup.bin")
	etag1 := uploadPartBody(t, handler, "test-bucket", "cleanup.bin", 1, uploadID, "data")

	w := doComplete(t, handler, "test-bucket", "cleanup.bin", uploadID,
		[]completePartSpec{{1, etag1}}, time.Now())
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	// multipart_uploads row must be gone.
	var count int
	if err := db.SQLDB().QueryRow(
		"SELECT COUNT(*) FROM multipart_uploads WHERE id = ?", uploadID,
	).Scan(&count); err != nil {
		t.Fatalf("querying multipart_uploads: %v", err)
	}
	if count != 0 {
		t.Errorf("multipart_uploads row count = %d, want 0 after complete", count)
	}
}

// ── 11. success + multipart_parts rows CASCADE deleted ───────────────────────

func TestCompleteMultipartUpload_PartsRowsDeleted(t *testing.T) {
	handler, db := setupCompleteMultipartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())

	uploadID := createUpload(t, handler, "test-bucket", "cascade.bin")
	etag1 := uploadPartBody(t, handler, "test-bucket", "cascade.bin", 1, uploadID, "part content")

	w := doComplete(t, handler, "test-bucket", "cascade.bin", uploadID,
		[]completePartSpec{{1, etag1}}, time.Now())
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	// multipart_parts rows must all be gone (CASCADE from session delete).
	var count int
	if err := db.SQLDB().QueryRow(
		"SELECT COUNT(*) FROM multipart_parts WHERE upload_id = ?", uploadID,
	).Scan(&count); err != nil {
		t.Fatalf("querying multipart_parts: %v", err)
	}
	if count != 0 {
		t.Errorf("multipart_parts row count = %d, want 0 after complete", count)
	}
}

// ── 12. success + staging file / upload dir cleaned up ───────────────────────

func TestCompleteMultipartUpload_StagingFilesCleanup(t *testing.T) {
	handler, db, multipartRoot := setupCompleteMultipartServerWithRoots(t)
	insertBucket(t, db, "test-bucket", time.Now())

	uploadID := createUpload(t, handler, "test-bucket", "stage.bin")
	etag1 := uploadPartBody(t, handler, "test-bucket", "stage.bin", 1, uploadID, "staged content")

	// Verify staging file exists before complete.
	uploadDir := filepath.Join(multipartRoot, uploadID)
	entries, err := os.ReadDir(uploadDir)
	if err != nil {
		t.Fatalf("ReadDir before complete: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one staging file before complete")
	}

	w := doComplete(t, handler, "test-bucket", "stage.bin", uploadID,
		[]completePartSpec{{1, etag1}}, time.Now())
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	// After complete, the upload directory must be empty or not exist.
	entries2, err2 := os.ReadDir(uploadDir)
	if err2 != nil && !os.IsNotExist(err2) {
		t.Fatalf("ReadDir after complete: %v", err2)
	}
	if err2 == nil && len(entries2) > 0 {
		t.Errorf("upload dir %q still has %d entries after complete; expected clean", uploadDir, len(entries2))
	}
}

// ── 13. multipart ETag matches AWS composite rule ────────────────────────────

func TestCompleteMultipartUpload_MultipartETagRule(t *testing.T) {
	handler, db := setupCompleteMultipartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())

	// Single-part upload (no minimum size restriction; part is both first and last).
	partData := "etag rule test data"
	uploadID := createUpload(t, handler, "test-bucket", "etag-rule.bin")
	etag1 := uploadPartBody(t, handler, "test-bucket", "etag-rule.bin", 1, uploadID, partData)

	w := doComplete(t, handler, "test-bucket", "etag-rule.bin", uploadID,
		[]completePartSpec{{1, etag1}}, time.Now())
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	_, _, responseETag, _ := parseCompleteResult(t, w.Body.Bytes())

	// Expected multipart ETag for 1 part: MD5(raw_md5(partData)) + "-1"
	expectedETag := `"` + multipartETagForData(partData) + `"`
	if responseETag != expectedETag {
		t.Errorf("ETag = %q, want %q", responseETag, expectedETag)
	}
}

// ── 14. metadata_json / Content-Type reflected on final object ────────────────

func TestCompleteMultipartUpload_MetadataPreserved(t *testing.T) {
	handler, db := setupCompleteMultipartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())

	// Initiate with Content-Type and user metadata headers.
	now := time.Now()
	path := "/test-bucket/meta-obj.bin?uploads"
	r := makeSignedPostRequest(t, path, now)
	r.Header.Set("Content-Type", "application/octet-stream+custom")
	r.Header.Set("X-Amz-Meta-Author", "alice")
	w0 := httptest.NewRecorder()
	handler.ServeHTTP(w0, r)
	if w0.Code != http.StatusOK {
		t.Fatalf("CreateMultipartUpload: status=%d body=%s", w0.Code, w0.Body.String())
	}
	_, _, uploadID := parseInitiateResult(t, w0.Body.Bytes())

	etag1 := uploadPartBody(t, handler, "test-bucket", "meta-obj.bin", 1, uploadID, "content")

	wc := doComplete(t, handler, "test-bucket", "meta-obj.bin", uploadID,
		[]completePartSpec{{1, etag1}}, now)
	if wc.Code != http.StatusOK {
		t.Fatalf("complete status = %d, want 200; body: %s", wc.Code, wc.Body.String())
	}

	// Check final object row for content_type and metadata_json.
	row := queryObjectRow(t, db, "test-bucket", "meta-obj.bin")
	if row.ContentType != "application/octet-stream+custom" {
		t.Errorf("content_type = %q, want application/octet-stream+custom", row.ContentType)
	}
	if !strings.Contains(row.MetadataJSON, "alice") {
		t.Errorf("metadata_json = %q; want it to contain author=alice", row.MetadataJSON)
	}
}

// ── 16. extra uploaded-but-unsubmitted part is cleaned up after complete ───────

func TestCompleteMultipartUpload_UnsubmittedPartCleaned(t *testing.T) {
	handler, db, multipartRoot := setupCompleteMultipartServerWithRoots(t)
	insertBucket(t, db, "test-bucket", time.Now())

	// Upload 2 parts: only part 1 will be submitted in CompleteMultipartUpload.
	// Part 1 must be ≥ 5 MiB so that it qualifies as the only submitted part
	// (and is treated as the last part, which has no minimum size restriction).
	uploadID := createUpload(t, handler, "test-bucket", "extra.bin")
	etag1 := uploadPartBody(t, handler, "test-bucket", "extra.bin", 1, uploadID,
		strings.Repeat("x", 5*1024*1024))
	// Part 2 is uploaded but will NOT be submitted.
	uploadPartBody(t, handler, "test-bucket", "extra.bin", 2, uploadID, "unsubmitted-data")

	// Both staging files must exist before complete.
	uploadDir := filepath.Join(multipartRoot, uploadID)
	entries, err := os.ReadDir(uploadDir)
	if err != nil {
		t.Fatalf("ReadDir before complete: %v", err)
	}
	if len(entries) < 2 {
		t.Fatalf("expected at least 2 staging files before complete, got %d", len(entries))
	}

	// Complete with only part 1.
	w := doComplete(t, handler, "test-bucket", "extra.bin", uploadID,
		[]completePartSpec{{1, etag1}}, time.Now())
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	// After complete, both staging files (submitted and unsubmitted) must be cleaned up.
	entries2, err2 := os.ReadDir(uploadDir)
	if err2 != nil && !os.IsNotExist(err2) {
		t.Fatalf("ReadDir after complete: %v", err2)
	}
	if err2 == nil && len(entries2) > 0 {
		t.Errorf("upload dir %q has %d entry(ies) after complete; unsubmitted part not cleaned",
			uploadDir, len(entries2))
	}
}

// ── 17. FinalizeMultipartUpload rolls back when session row is already gone ────
//
// This validates the RowsAffected atomicity invariant added to FinalizeMultipartUpload:
// if the multipart session row is missing at finalization time, the object upsert
// that ran earlier in the same transaction must be rolled back too.
// Per operations-runbook.md section 3.2.
func TestFinalizeMultipartUpload_SessionGone_AtomicRollback(t *testing.T) {
	_, db, _ := setupCompleteMultipartServerWithRoots(t)
	insertBucket(t, db, "test-bucket", time.Now())

	// Attempt to finalize without a corresponding multipart_uploads row.
	// The object upsert runs first inside the transaction, but the DELETE
	// on the missing session must detect RowsAffected == 0 and return
	// ErrUploadNotFound, causing defer tx.Rollback() to fire.
	err := db.FinalizeMultipartUpload(metadata.FinalizeMultipartUploadInput{
		BucketName: "test-bucket",
		ObjectKey:  "ghost.bin",
		ObjInput: metadata.PutObjectInput{
			Size:         42,
			ETag:         "deadbeefdeadbeefdeadbeefdeadbeef",
			ContentType:  "application/octet-stream",
			StoragePath:  "/tmp/fake-ghost-path",
			LastModified: time.Now(),
			MetadataJSON: "{}",
		},
		UploadID: "nonexistent-upload-id",
	})
	if !errors.Is(err, metadata.ErrUploadNotFound) {
		t.Fatalf("expected ErrUploadNotFound, got %v", err)
	}

	// Verify the object row was NOT created (transaction was rolled back atomically).
	var count int
	if err2 := db.SQLDB().QueryRow(
		"SELECT COUNT(*) FROM objects WHERE object_key = ?", "ghost.bin",
	).Scan(&count); err2 != nil {
		t.Fatalf("querying objects: %v", err2)
	}
	if count != 0 {
		t.Errorf("objects row count = %d, want 0 (tx must have rolled back)", count)
	}
}

// ── 15. existing handlers (Create/UploadPart/ListParts/GetObject) remain green ─

func TestCompleteMultipartUpload_ExistingHandlersUnaffected(t *testing.T) {
	handler, db := setupCompleteMultipartServer(t)
	insertBucket(t, db, "test-bucket", time.Now())
	now := time.Now()

	// PutObject + GetObject still work.
	putObject(t, handler, "/test-bucket/existing.txt", "existing content", now)
	wg := doGet(t, handler, "/test-bucket/existing.txt", now)
	if wg.Code != http.StatusOK {
		t.Fatalf("GetObject status = %d, want 200; body: %s", wg.Code, wg.Body.String())
	}

	// CreateMultipartUpload still works.
	uploadID := createUpload(t, handler, "test-bucket", "mp-obj.bin")
	if uploadID == "" {
		t.Fatal("createUpload returned empty uploadID")
	}

	// UploadPart still works.
	etag1 := uploadPartBody(t, handler, "test-bucket", "mp-obj.bin", 1, uploadID, "part data")
	if etag1 == "" {
		t.Fatal("uploadPartBody returned empty ETag")
	}

	// ListParts still works.
	wl := doListParts(t, handler, "test-bucket", "mp-obj.bin", uploadID, now)
	if wl.Code != http.StatusOK {
		t.Fatalf("ListParts status = %d, want 200; body: %s", wl.Code, wl.Body.String())
	}

	// POST without ?uploads and without ?uploadId still returns 501 NotImplemented.
	r501, err := http.NewRequest(http.MethodPost,
		"http://"+testHost+"/test-bucket/mp-obj.bin", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	r501.Host = testHost
	signRequest(t, r501, now)
	w501 := httptest.NewRecorder()
	handler.ServeHTTP(w501, r501)
	if w501.Code != http.StatusNotImplemented {
		t.Errorf("POST without params: status = %d, want 501; body: %s", w501.Code, w501.Body.String())
	}

	// CompleteMultipartUpload with nonexistent uploadId returns 404 NoSuchUpload.
	wne := doComplete(t, handler, "test-bucket", "mp-obj.bin", "nonexistent-id",
		[]completePartSpec{{1, `"abc"`}}, now)
	if wne.Code != http.StatusNotFound {
		t.Errorf("nonexistent uploadId: status = %d, want 404; body: %s", wne.Code, wne.Body.String())
	}
	if code := xmlErrorCode(t, wne.Body.Bytes()); code != "NoSuchUpload" {
		t.Errorf("error code = %q, want NoSuchUpload", code)
	}
}
