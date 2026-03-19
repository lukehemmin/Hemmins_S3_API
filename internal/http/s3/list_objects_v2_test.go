package s3_test

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

// insertObjectFull inserts an object row with explicit size and last_modified for testing.
func insertObjectFull(t *testing.T, db *metadata.DB, bucketName, objectKey string, size int64, lastMod time.Time) {
	t.Helper()
	_, err := db.SQLDB().Exec(
		`INSERT INTO objects
		 (bucket_id, object_key, size, etag, content_type, storage_path, last_modified)
		 VALUES (
		   (SELECT id FROM buckets WHERE name = ?),
		   ?, ?, 'abc123', 'application/octet-stream', 'staging/test', ?
		 )`,
		bucketName, objectKey, size, lastMod.UTC().Format(time.RFC3339),
	)
	if err != nil {
		t.Fatalf("insertObjectFull bucket=%q key=%q: %v", bucketName, objectKey, err)
	}
}

// listObjectsV2Request builds a signed GET /{bucket}?list-type=2&... request.
func listObjectsV2Request(t *testing.T, bucketName string, params url.Values, now time.Time) *http.Request {
	t.Helper()
	params.Set("list-type", "2")
	rawURL := "http://" + testHost + "/" + bucketName + "?" + params.Encode()
	r, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	r.Host = testHost
	signRequest(t, r, now)
	return r
}

// listV2Response is a minimal struct that mirrors the ListBucketV2Result XML.
type listV2Response struct {
	XMLName               xml.Name    `xml:"ListBucketResult"`
	Name                  string      `xml:"Name"`
	Prefix                string      `xml:"Prefix"`
	Delimiter             string      `xml:"Delimiter"`
	MaxKeys               int         `xml:"MaxKeys"`
	KeyCount              int         `xml:"KeyCount"`
	IsTruncated           bool        `xml:"IsTruncated"`
	ContinuationToken     string      `xml:"ContinuationToken"`
	NextContinuationToken string      `xml:"NextContinuationToken"`
	Contents              []v2Content `xml:"Contents"`
	CommonPrefixes        []v2CP      `xml:"CommonPrefixes"`
}

type v2Content struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
}

type v2CP struct {
	Prefix string `xml:"Prefix"`
}

// doListV2 performs the request and returns the parsed response.
func doListV2(t *testing.T, handler http.Handler, r *http.Request) (listV2Response, []byte, int) {
	t.Helper()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return listV2Response{}, body, resp.StatusCode
	}
	var parsed listV2Response
	if err := xml.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("xml.Unmarshal: %v\nbody: %s", err, body)
	}
	return parsed, body, resp.StatusCode
}

// ---- 1. Empty bucket returns 200 with zero objects ----

func TestListObjectsV2_EmptyBucket(t *testing.T) {
	handler, db := setupTestServer(t)
	now := time.Now()
	insertBucket(t, db, "empty-bucket", now)

	r := listObjectsV2Request(t, "empty-bucket", url.Values{}, now)
	parsed, _, status := doListV2(t, handler, r)

	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d", status)
	}
	if len(parsed.Contents) != 0 {
		t.Errorf("expected 0 contents, got %d", len(parsed.Contents))
	}
	if parsed.IsTruncated {
		t.Error("expected IsTruncated=false for empty bucket")
	}
	if parsed.KeyCount != 0 {
		t.Errorf("expected KeyCount=0, got %d", parsed.KeyCount)
	}
	if parsed.Name != "empty-bucket" {
		t.Errorf("Name: got %q, want %q", parsed.Name, "empty-bucket")
	}
}

// ---- 2. Objects returned in lexicographic order ----

func TestListObjectsV2_LexicographicOrder(t *testing.T) {
	handler, db := setupTestServer(t)
	now := time.Now()
	insertBucket(t, db, "lex-bucket", now)
	// Insert in non-alphabetical order.
	for _, key := range []string{"zebra.txt", "apple.txt", "mango.txt"} {
		insertObjectFull(t, db, "lex-bucket", key, 10, now)
	}

	r := listObjectsV2Request(t, "lex-bucket", url.Values{}, now)
	parsed, _, status := doListV2(t, handler, r)

	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d", status)
	}
	want := []string{"apple.txt", "mango.txt", "zebra.txt"}
	if len(parsed.Contents) != len(want) {
		t.Fatalf("expected %d objects, got %d", len(want), len(parsed.Contents))
	}
	for i, obj := range parsed.Contents {
		if obj.Key != want[i] {
			t.Errorf("Contents[%d].Key: got %q, want %q", i, obj.Key, want[i])
		}
	}
}

// ---- 3. prefix filter narrows results ----

func TestListObjectsV2_PrefixFilter(t *testing.T) {
	handler, db := setupTestServer(t)
	now := time.Now()
	insertBucket(t, db, "prefix-bucket", now)
	for _, key := range []string{"foo/a", "foo/b", "bar/c", "baz/d"} {
		insertObjectFull(t, db, "prefix-bucket", key, 5, now)
	}

	params := url.Values{}
	params.Set("prefix", "foo/")
	r := listObjectsV2Request(t, "prefix-bucket", params, now)
	parsed, _, status := doListV2(t, handler, r)

	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d", status)
	}
	if len(parsed.Contents) != 2 {
		t.Fatalf("expected 2 objects, got %d", len(parsed.Contents))
	}
	for _, obj := range parsed.Contents {
		if obj.Key != "foo/a" && obj.Key != "foo/b" {
			t.Errorf("unexpected key in prefix results: %q", obj.Key)
		}
	}
	if parsed.KeyCount != 2 {
		t.Errorf("KeyCount: got %d, want 2", parsed.KeyCount)
	}
}

// ---- 4. delimiter groups keys into CommonPrefixes ----

func TestListObjectsV2_DelimiterGrouping(t *testing.T) {
	handler, db := setupTestServer(t)
	now := time.Now()
	insertBucket(t, db, "delim-bucket", now)
	for _, key := range []string{"foo/a", "foo/b", "bar/c", "top.txt"} {
		insertObjectFull(t, db, "delim-bucket", key, 1, now)
	}

	params := url.Values{}
	params.Set("delimiter", "/")
	r := listObjectsV2Request(t, "delim-bucket", params, now)
	parsed, _, status := doListV2(t, handler, r)

	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d", status)
	}
	// "top.txt" is a regular object; "foo/" and "bar/" are CommonPrefixes.
	if len(parsed.Contents) != 1 {
		t.Errorf("expected 1 Contents entry, got %d", len(parsed.Contents))
	}
	if len(parsed.CommonPrefixes) != 2 {
		t.Errorf("expected 2 CommonPrefixes, got %d", len(parsed.CommonPrefixes))
	}
	// CommonPrefixes must be sorted.
	if len(parsed.CommonPrefixes) == 2 {
		if parsed.CommonPrefixes[0].Prefix != "bar/" {
			t.Errorf("CommonPrefixes[0]: got %q, want %q", parsed.CommonPrefixes[0].Prefix, "bar/")
		}
		if parsed.CommonPrefixes[1].Prefix != "foo/" {
			t.Errorf("CommonPrefixes[1]: got %q, want %q", parsed.CommonPrefixes[1].Prefix, "foo/")
		}
	}
	if parsed.KeyCount != 3 {
		t.Errorf("KeyCount: got %d, want 3", parsed.KeyCount)
	}
}

// ---- 5. max-keys truncates the result and sets IsTruncated + NextContinuationToken ----

func TestListObjectsV2_MaxKeysTruncation(t *testing.T) {
	handler, db := setupTestServer(t)
	now := time.Now()
	insertBucket(t, db, "trunc-bucket", now)
	for i := 0; i < 5; i++ {
		insertObjectFull(t, db, "trunc-bucket", fmt.Sprintf("key%02d", i), int64(i), now)
	}

	params := url.Values{}
	params.Set("max-keys", "3")
	r := listObjectsV2Request(t, "trunc-bucket", params, now)
	parsed, _, status := doListV2(t, handler, r)

	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d", status)
	}
	if len(parsed.Contents) != 3 {
		t.Errorf("expected 3 Contents entries, got %d", len(parsed.Contents))
	}
	if !parsed.IsTruncated {
		t.Error("expected IsTruncated=true")
	}
	if parsed.NextContinuationToken == "" {
		t.Error("expected non-empty NextContinuationToken")
	}
	if parsed.MaxKeys != 3 {
		t.Errorf("MaxKeys: got %d, want 3", parsed.MaxKeys)
	}
}

// ---- 6. continuation-token resumes pagination correctly ----

func TestListObjectsV2_ContinuationToken(t *testing.T) {
	handler, db := setupTestServer(t)
	now := time.Now()
	insertBucket(t, db, "page-bucket", now)
	keys := []string{"a", "b", "c", "d", "e"}
	for _, k := range keys {
		insertObjectFull(t, db, "page-bucket", k, 1, now)
	}

	// Page 1: max-keys=2
	params1 := url.Values{}
	params1.Set("max-keys", "2")
	r1 := listObjectsV2Request(t, "page-bucket", params1, now)
	p1, _, s1 := doListV2(t, handler, r1)

	if s1 != http.StatusOK {
		t.Fatalf("page1: expected 200, got %d", s1)
	}
	if len(p1.Contents) != 2 {
		t.Fatalf("page1: expected 2 objects, got %d", len(p1.Contents))
	}
	if !p1.IsTruncated {
		t.Fatal("page1: expected IsTruncated=true")
	}

	// Page 2: use NextContinuationToken from page 1.
	params2 := url.Values{}
	params2.Set("max-keys", "2")
	params2.Set("continuation-token", p1.NextContinuationToken)
	r2 := listObjectsV2Request(t, "page-bucket", params2, now)
	p2, _, s2 := doListV2(t, handler, r2)

	if s2 != http.StatusOK {
		t.Fatalf("page2: expected 200, got %d", s2)
	}
	if len(p2.Contents) != 2 {
		t.Fatalf("page2: expected 2 objects, got %d", len(p2.Contents))
	}
	if !p2.IsTruncated {
		t.Fatal("page2: expected IsTruncated=true")
	}

	// Page 3: final page.
	params3 := url.Values{}
	params3.Set("max-keys", "2")
	params3.Set("continuation-token", p2.NextContinuationToken)
	r3 := listObjectsV2Request(t, "page-bucket", params3, now)
	p3, _, s3 := doListV2(t, handler, r3)

	if s3 != http.StatusOK {
		t.Fatalf("page3: expected 200, got %d", s3)
	}
	if len(p3.Contents) != 1 {
		t.Fatalf("page3: expected 1 object, got %d", len(p3.Contents))
	}
	if p3.IsTruncated {
		t.Error("page3: expected IsTruncated=false")
	}
	if p3.NextContinuationToken != "" {
		t.Error("page3: expected empty NextContinuationToken")
	}

	// Verify all 5 keys were returned exactly once across all pages.
	allKeys := make([]string, 0, 5)
	for _, obj := range p1.Contents {
		allKeys = append(allKeys, obj.Key)
	}
	for _, obj := range p2.Contents {
		allKeys = append(allKeys, obj.Key)
	}
	for _, obj := range p3.Contents {
		allKeys = append(allKeys, obj.Key)
	}
	if len(allKeys) != 5 {
		t.Errorf("total objects across pages: got %d, want 5", len(allKeys))
	}
	for i, k := range allKeys {
		if k != keys[i] {
			t.Errorf("allKeys[%d]: got %q, want %q", i, k, keys[i])
		}
	}
}

// ---- 7. invalid continuation-token returns 400 InvalidArgument ----

func TestListObjectsV2_InvalidContinuationToken(t *testing.T) {
	handler, db := setupTestServer(t)
	now := time.Now()
	insertBucket(t, db, "tok-bucket", now)

	params := url.Values{}
	params.Set("continuation-token", "!!!not-base64!!!")
	r := listObjectsV2Request(t, "tok-bucket", params, now)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", resp.StatusCode, body)
	}
	if code := xmlErrorCode(t, body); code != "InvalidArgument" {
		t.Errorf("error code: got %q, want %q", code, "InvalidArgument")
	}
}

// ---- 8. missing bucket returns 404 NoSuchBucket ----

func TestListObjectsV2_NoSuchBucket(t *testing.T) {
	handler, _ := setupTestServer(t)
	now := time.Now()

	r := listObjectsV2Request(t, "does-not-exist", url.Values{}, now)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d; body: %s", resp.StatusCode, body)
	}
	if code := xmlErrorCode(t, body); code != "NoSuchBucket" {
		t.Errorf("error code: got %q, want %q", code, "NoSuchBucket")
	}
}

// ---- 9. unauthenticated request returns 403 AccessDenied ----

func TestListObjectsV2_Unauthenticated(t *testing.T) {
	handler, db := setupTestServer(t)
	insertBucket(t, db, "auth-bucket", time.Now())

	rawURL := "http://" + testHost + "/auth-bucket?list-type=2"
	r, _ := http.NewRequest(http.MethodGet, rawURL, nil)
	r.Host = testHost

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d; body: %s", resp.StatusCode, body)
	}
	if code := xmlErrorCode(t, body); code != "AccessDenied" {
		t.Errorf("error code: got %q, want %q", code, "AccessDenied")
	}
}

// ---- 10. max-keys value is reflected back in the XML response ----

func TestListObjectsV2_MaxKeysReflected(t *testing.T) {
	handler, db := setupTestServer(t)
	now := time.Now()
	insertBucket(t, db, "maxkeys-bucket", now)
	insertObjectFull(t, db, "maxkeys-bucket", "key1", 1, now)

	params := url.Values{}
	params.Set("max-keys", "50")
	r := listObjectsV2Request(t, "maxkeys-bucket", params, now)
	parsed, _, status := doListV2(t, handler, r)

	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d", status)
	}
	if parsed.MaxKeys != 50 {
		t.Errorf("MaxKeys: got %d, want 50", parsed.MaxKeys)
	}
	if len(parsed.Contents) != 1 {
		t.Errorf("expected 1 object, got %d", len(parsed.Contents))
	}
	if parsed.IsTruncated {
		t.Error("expected IsTruncated=false when objects fit within max-keys")
	}
}

// ---- 11. negative max-keys returns 400 InvalidArgument ----

func TestListObjectsV2_NegativeMaxKeys(t *testing.T) {
	handler, db := setupTestServer(t)
	insertBucket(t, db, "neg-bucket", time.Now())

	params := url.Values{}
	params.Set("max-keys", "-1")
	r := listObjectsV2Request(t, "neg-bucket", params, time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", resp.StatusCode, body)
	}
	if code := xmlErrorCode(t, body); code != "InvalidArgument" {
		t.Errorf("error code: got %q, want %q", code, "InvalidArgument")
	}
}

// ---- 11a. max-keys=0 returns 400 InvalidArgument ----

func TestListObjectsV2_MaxKeysZero(t *testing.T) {
	handler, db := setupTestServer(t)
	insertBucket(t, db, "zero-bucket", time.Now())

	params := url.Values{}
	params.Set("max-keys", "0")
	r := listObjectsV2Request(t, "zero-bucket", params, time.Now())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", resp.StatusCode, body)
	}
	if code := xmlErrorCode(t, body); code != "InvalidArgument" {
		t.Errorf("error code: got %q, want %q", code, "InvalidArgument")
	}
}

// ---- 11b. max-keys > 1000 is capped to 1000 in the response ----

func TestListObjectsV2_MaxKeysCap(t *testing.T) {
	handler, db := setupTestServer(t)
	now := time.Now()
	insertBucket(t, db, "cap-bucket", now)
	insertObjectFull(t, db, "cap-bucket", "key1", 1, now)

	params := url.Values{}
	params.Set("max-keys", "9999")
	r := listObjectsV2Request(t, "cap-bucket", params, now)
	parsed, _, status := doListV2(t, handler, r)

	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d", status)
	}
	if parsed.MaxKeys != 1000 {
		t.Errorf("MaxKeys: got %d, want 1000 (should be capped)", parsed.MaxKeys)
	}
	if len(parsed.Contents) != 1 {
		t.Errorf("expected 1 object, got %d", len(parsed.Contents))
	}
	if parsed.IsTruncated {
		t.Error("expected IsTruncated=false")
	}
}

// ---- 12. XML namespace and field values are correct ----

func TestListObjectsV2_XMLShape(t *testing.T) {
	handler, db := setupTestServer(t)
	now := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	insertBucket(t, db, "shape-bucket", now)
	insertObjectFull(t, db, "shape-bucket", "hello/world.txt", 42, now)

	params := url.Values{}
	params.Set("prefix", "hello/")
	r := listObjectsV2Request(t, "shape-bucket", params, now)
	_, body, status := doListV2(t, handler, r)

	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", status, body)
	}

	bodyStr := string(body)

	// XML namespace required by SDKs.
	if !containsSubstring(bodyStr, "http://s3.amazonaws.com/doc/2006-03-01/") {
		t.Error("XML namespace not found in response")
	}
	// Key must be present.
	if !containsSubstring(bodyStr, "<Key>hello/world.txt</Key>") {
		t.Errorf("Key element not found; body: %s", bodyStr)
	}
	// Size must be present.
	if !containsSubstring(bodyStr, "<Size>42</Size>") {
		t.Errorf("Size element not found; body: %s", bodyStr)
	}
	// StorageClass must be STANDARD.
	if !containsSubstring(bodyStr, "<StorageClass>STANDARD</StorageClass>") {
		t.Errorf("StorageClass element not found; body: %s", bodyStr)
	}
	// LastModified must be present and non-empty.
	if !containsSubstring(bodyStr, "<LastModified>") {
		t.Error("LastModified element not found")
	}
	// ETag must be present.
	if !containsSubstring(bodyStr, "<ETag>") {
		t.Error("ETag element not found")
	}
}

// ---- 13. Metadata layer unit test for ListObjectsV2 ----

func TestMetadataListObjectsV2_Basic(t *testing.T) {
	db, err := metadata.Open(":memory:")
	if err != nil {
		t.Fatalf("metadata.Open: %v", err)
	}
	defer db.Close()

	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	insertBucket(t, db, "meta-bucket", now)
	for _, k := range []string{"a/1", "a/2", "b/1"} {
		insertObjectFull(t, db, "meta-bucket", k, 10, now)
	}

	result, err := db.ListObjectsV2("meta-bucket", metadata.ListOptions{
		Delimiter: "/",
		MaxKeys:   1000,
	})
	if err != nil {
		t.Fatalf("ListObjectsV2: %v", err)
	}
	if len(result.Objects) != 0 {
		t.Errorf("expected 0 regular objects, got %d", len(result.Objects))
	}
	if len(result.CommonPrefixes) != 2 {
		t.Errorf("expected 2 CommonPrefixes, got %d: %v", len(result.CommonPrefixes), result.CommonPrefixes)
	}
	if result.KeyCount != 2 {
		t.Errorf("KeyCount: got %d, want 2", result.KeyCount)
	}
}

// ---- 14. Metadata layer: invalid continuation token ----

func TestMetadataListObjectsV2_InvalidToken(t *testing.T) {
	db, err := metadata.Open(":memory:")
	if err != nil {
		t.Fatalf("metadata.Open: %v", err)
	}
	defer db.Close()
	insertBucket(t, db, "tok-meta", time.Now())

	_, err = db.ListObjectsV2("tok-meta", metadata.ListOptions{
		ContinuationToken: "!!!",
	})
	if err == nil {
		t.Fatal("expected error for invalid continuation token, got nil")
	}
}

// ---- 15. continuation token round-trip: base64(lastKey) decodes correctly ----

func TestListObjectsV2_TokenRoundTrip(t *testing.T) {
	db, err := metadata.Open(":memory:")
	if err != nil {
		t.Fatalf("metadata.Open: %v", err)
	}
	defer db.Close()

	now := time.Now()
	insertBucket(t, db, "rt-bucket", now)
	for _, k := range []string{"a", "b", "c"} {
		insertObjectFull(t, db, "rt-bucket", k, 1, now)
	}

	r1, err := db.ListObjectsV2("rt-bucket", metadata.ListOptions{MaxKeys: 2})
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if !r1.IsTruncated {
		t.Fatal("expected page1 to be truncated")
	}

	// Decode the token to confirm it contains the last key of page 1.
	decoded, err := base64.StdEncoding.DecodeString(r1.NextContinuationToken)
	if err != nil {
		t.Fatalf("token is not valid base64: %v", err)
	}
	if string(decoded) != "b" {
		t.Errorf("token decoded to %q, want %q", string(decoded), "b")
	}

	r2, err := db.ListObjectsV2("rt-bucket", metadata.ListOptions{
		MaxKeys:           2,
		ContinuationToken: r1.NextContinuationToken,
	})
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if r2.IsTruncated {
		t.Error("expected page2 to be final (not truncated)")
	}
	if len(r2.Objects) != 1 || r2.Objects[0].Key != "c" {
		t.Errorf("page2 objects: got %v, want [c]", r2.Objects)
	}
}

// containsSubstring is a local helper to avoid importing strings in the test file.
func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && searchSubstring(s, sub))
}

func searchSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
