package ui_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ui "github.com/lukehemmin/hemmins-s3-api/internal/http/ui"
)

// Test 1: GET /ui/ returns HTML (not JSON 404).
// This verifies the UI shell is served correctly.
func TestUIShell_ReturnsHTML(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Errorf("expected HTML document, got: %s", body[:min(100, len(body))])
	}
	if !strings.Contains(body, "Hemmins S3") {
		t.Errorf("expected 'Hemmins S3' in response, got: %s", body[:min(200, len(body))])
	}
}

// Test 2: GET /ui/static/style.css returns CSS.
func TestUIShell_ServesCSS(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/static/style.css", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	body := rr.Body.String()
	if !strings.Contains(body, ":root") {
		t.Errorf("expected CSS content with :root, got: %s", body[:min(100, len(body))])
	}
}

// Test 3: GET /ui/static/app.js returns JavaScript.
func TestUIShell_ServesJS(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/static/app.js", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	body := rr.Body.String()
	if !strings.Contains(body, "function") {
		t.Errorf("expected JavaScript content with function, got: %s", body[:min(100, len(body))])
	}
}

// Test 4: GET /ui/api/* still returns JSON (not HTML).
// Ensures API routes are not affected by static file server.
func TestUIShell_APIRoutesStillJSON(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	// Test /ui/api/session/me (without auth → 401)
	req := httptest.NewRequest(http.MethodGet, "/ui/api/session/me", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}

	contentType := rr.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("expected application/json Content-Type, got: %s", contentType)
	}
}

// Test 5: GET /ui/unknown returns HTML shell (SPA routing).
// The UI shell should be served for any /ui/* path that is not an API route.
func TestUIShell_SPARouting(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/some/unknown/path", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for SPA route, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Errorf("expected HTML document for SPA route, got: %s", body[:min(100, len(body))])
	}
}

// Test 6: GET /ui/api/unknown returns JSON 404 (not HTML).
func TestUIShell_UnknownAPIRouteReturnsJSON404(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/api/unknown", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}

	contentType := rr.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("expected application/json Content-Type, got: %s", contentType)
	}

	body := rr.Body.String()
	if strings.Contains(body, "<!DOCTYPE html>") {
		t.Errorf("expected JSON error, got HTML: %s", body[:min(100, len(body))])
	}
}

// Test 7: setup-required state serves 503 for both HTML and API paths.
// Per security-model.md §3.2: setup-required state blocks all UI access.
func TestUIShell_SetupRequired_ReturnsServiceUnavailable(t *testing.T) {
	base, _ := setupTestUIServer(t, false)
	handler := ui.WithReadinessGate(notReady, base)

	// HTML shell request
	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for /ui/, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "setup required") {
		t.Errorf("expected 'setup required' in response, got: %s", body)
	}
}

// Test 8: When ready, /ui/ returns HTML shell.
func TestUIShell_Ready_ReturnsHTML(t *testing.T) {
	base, _ := setupTestUIServer(t, false)
	handler := ui.WithReadinessGate(alwaysReady, base)

	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	body := rr.Body.String()
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Errorf("expected HTML document, got: %s", body[:min(100, len(body))])
	}
}

// Test 9: Static assets are also gated by readiness.
func TestUIShell_SetupRequired_StaticAssetsBlocked(t *testing.T) {
	base, _ := setupTestUIServer(t, false)
	handler := ui.WithReadinessGate(notReady, base)

	req := httptest.NewRequest(http.MethodGet, "/ui/static/style.css", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for static assets in setup-required state, got %d", rr.Code)
	}
}

// Test 10: Bucket create form exists in HTML shell.
func TestUIShell_BucketCreateFormExists(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// Check for bucket create form elements
	if !strings.Contains(body, "bucket-create-form") {
		t.Error("expected bucket-create-form ID in HTML")
	}
	if !strings.Contains(body, "bucket-name-input") {
		t.Error("expected bucket-name-input ID in HTML")
	}
	if !strings.Contains(body, "bucket-create-btn") {
		t.Error("expected bucket-create-btn ID in HTML")
	}
}

// Test 11: Bucket error/success message containers exist in HTML shell.
func TestUIShell_BucketMessageContainersExist(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	if !strings.Contains(body, "buckets-error") {
		t.Error("expected buckets-error ID in HTML")
	}
	if !strings.Contains(body, "buckets-success") {
		t.Error("expected buckets-success ID in HTML")
	}
}

// Test 12: JavaScript contains bucket create/delete functions.
func TestUIShell_JSContainsBucketFunctions(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/static/app.js", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	body := rr.Body.String()

	if !strings.Contains(body, "createBucket") {
		t.Error("expected createBucket function in app.js")
	}
	if !strings.Contains(body, "deleteBucket") {
		t.Error("expected deleteBucket function in app.js")
	}
	if !strings.Contains(body, "window.deleteBucket") {
		t.Error("expected window.deleteBucket export in app.js")
	}
}

// Test 13: JavaScript uses correct API endpoints for bucket operations.
func TestUIShell_JSUsesBucketAPIEndpoints(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/static/app.js", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// Check that the JS uses the correct API endpoints
	if !strings.Contains(body, "'/ui/api/buckets'") {
		t.Error("expected POST /ui/api/buckets endpoint usage in app.js")
	}
	if !strings.Contains(body, "/ui/api/buckets/") {
		t.Error("expected DELETE /ui/api/buckets/{name} endpoint usage in app.js")
	}
}

// Test 14: CSS contains styles for bucket management UI.
func TestUIShell_CSSContainsBucketStyles(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/static/style.css", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	if !strings.Contains(body, ".btn-danger") {
		t.Error("expected .btn-danger class in CSS")
	}
	if !strings.Contains(body, ".bucket-create-form") {
		t.Error("expected .bucket-create-form class in CSS")
	}
	if !strings.Contains(body, ".form-inline") {
		t.Error("expected .form-inline class in CSS")
	}
	if !strings.Contains(body, ".success") {
		t.Error("expected .success class in CSS")
	}
}

// Test 15: Object browser navigation button is enabled.
func TestUIShell_ObjectNavEnabled(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// The objects nav button should NOT be disabled
	if strings.Contains(body, `data-section="objects" disabled`) {
		t.Error("objects nav button should not be disabled")
	}
	// Should have the objects nav button
	if !strings.Contains(body, `data-section="objects"`) {
		t.Error("expected objects nav button")
	}
}

// Test 16: Object browser section exists with required elements.
func TestUIShell_ObjectBrowserSectionExists(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// Object browser section
	if !strings.Contains(body, "section-objects") {
		t.Error("expected section-objects ID in HTML")
	}

	// Bucket select dropdown
	if !strings.Contains(body, "object-bucket-select") {
		t.Error("expected object-bucket-select ID in HTML")
	}

	// Prefix input
	if !strings.Contains(body, "object-prefix-input") {
		t.Error("expected object-prefix-input ID in HTML")
	}

	// Delimiter input
	if !strings.Contains(body, "object-delimiter-input") {
		t.Error("expected object-delimiter-input ID in HTML")
	}

	// Search button
	if !strings.Contains(body, "object-search-btn") {
		t.Error("expected object-search-btn ID in HTML")
	}

	// Objects table
	if !strings.Contains(body, "objects-table") {
		t.Error("expected objects-table ID in HTML")
	}

	// Objects tbody
	if !strings.Contains(body, "objects-tbody") {
		t.Error("expected objects-tbody ID in HTML")
	}

	// Load more button
	if !strings.Contains(body, "objects-load-more") {
		t.Error("expected objects-load-more ID in HTML")
	}
}

// Test 17: Object metadata panel exists.
func TestUIShell_ObjectMetaPanelExists(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// Meta panel
	if !strings.Contains(body, "object-meta-panel") {
		t.Error("expected object-meta-panel ID in HTML")
	}

	// Meta close button
	if !strings.Contains(body, "object-meta-close") {
		t.Error("expected object-meta-close ID in HTML")
	}

	// Meta content fields
	if !strings.Contains(body, "meta-bucket") {
		t.Error("expected meta-bucket ID in HTML")
	}
	if !strings.Contains(body, "meta-key") {
		t.Error("expected meta-key ID in HTML")
	}
	if !strings.Contains(body, "meta-size") {
		t.Error("expected meta-size ID in HTML")
	}
	if !strings.Contains(body, "meta-content-type") {
		t.Error("expected meta-content-type ID in HTML")
	}
	if !strings.Contains(body, "meta-etag") {
		t.Error("expected meta-etag ID in HTML")
	}
}

// Test 18: JavaScript contains object browser functions.
func TestUIShell_JSContainsObjectBrowserFunctions(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/static/app.js", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	body := rr.Body.String()

	// Object list function
	if !strings.Contains(body, "loadObjects") {
		t.Error("expected loadObjects function in app.js")
	}

	// Object metadata function
	if !strings.Contains(body, "showObjectMeta") {
		t.Error("expected showObjectMeta function in app.js")
	}

	// Download function
	if !strings.Contains(body, "downloadObject") {
		t.Error("expected downloadObject function in app.js")
	}

	// Navigate to prefix function
	if !strings.Contains(body, "navigateToPrefix") {
		t.Error("expected navigateToPrefix function in app.js")
	}

	// Exposed to window
	if !strings.Contains(body, "window.showObjectMeta") {
		t.Error("expected window.showObjectMeta export in app.js")
	}
	if !strings.Contains(body, "window.downloadObject") {
		t.Error("expected window.downloadObject export in app.js")
	}
	if !strings.Contains(body, "window.navigateToPrefix") {
		t.Error("expected window.navigateToPrefix export in app.js")
	}
}

// Test 19: JavaScript uses correct object API endpoints.
func TestUIShell_JSUsesObjectAPIEndpoints(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/static/app.js", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// List objects endpoint
	if !strings.Contains(body, "/objects?") {
		t.Error("expected /objects? endpoint usage in app.js")
	}

	// Object meta endpoint
	if !strings.Contains(body, "/objects/meta?key=") {
		t.Error("expected /objects/meta?key= endpoint usage in app.js")
	}

	// Object download endpoint
	if !strings.Contains(body, "/objects/download?key=") {
		t.Error("expected /objects/download?key= endpoint usage in app.js")
	}
}

// Test 20: CSS contains object browser styles.
func TestUIShell_CSSContainsObjectBrowserStyles(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/static/style.css", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	if !strings.Contains(body, ".object-browser-controls") {
		t.Error("expected .object-browser-controls class in CSS")
	}
	if !strings.Contains(body, ".object-breadcrumb") {
		t.Error("expected .object-breadcrumb class in CSS")
	}
	if !strings.Contains(body, ".meta-panel") {
		t.Error("expected .meta-panel class in CSS")
	}
	if !strings.Contains(body, ".pagination") {
		t.Error("expected .pagination class in CSS")
	}
}

// Test 21: Object breadcrumb element exists.
func TestUIShell_ObjectBreadcrumbExists(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	if !strings.Contains(body, "object-breadcrumb") {
		t.Error("expected object-breadcrumb ID in HTML")
	}
}

// Test 22: Object upload form exists in HTML shell.
func TestUIShell_ObjectUploadFormExists(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// Upload section
	if !strings.Contains(body, "object-upload-section") {
		t.Error("expected object-upload-section ID in HTML")
	}

	// Upload form
	if !strings.Contains(body, "object-upload-form") {
		t.Error("expected object-upload-form ID in HTML")
	}

	// Key input
	if !strings.Contains(body, "object-key-input") {
		t.Error("expected object-key-input ID in HTML")
	}

	// File input
	if !strings.Contains(body, "object-file-input") {
		t.Error("expected object-file-input ID in HTML")
	}

	// Upload button
	if !strings.Contains(body, "object-upload-btn") {
		t.Error("expected object-upload-btn ID in HTML")
	}
}

// Test 23: Object success message container exists.
func TestUIShell_ObjectSuccessMessageExists(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	if !strings.Contains(body, "objects-success") {
		t.Error("expected objects-success ID in HTML")
	}
}

// Test 24: JavaScript contains object upload function.
func TestUIShell_JSContainsUploadFunction(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/static/app.js", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	body := rr.Body.String()

	if !strings.Contains(body, "uploadObject") {
		t.Error("expected uploadObject function in app.js")
	}
}

// Test 25: JavaScript contains object delete function.
func TestUIShell_JSContainsDeleteFunction(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/static/app.js", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	body := rr.Body.String()

	if !strings.Contains(body, "deleteObject") {
		t.Error("expected deleteObject function in app.js")
	}

	if !strings.Contains(body, "window.deleteObject") {
		t.Error("expected window.deleteObject export in app.js")
	}
}

// Test 26: JavaScript uses correct upload API endpoint.
func TestUIShell_JSUsesUploadAPIEndpoint(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/static/app.js", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// Upload endpoint
	if !strings.Contains(body, "/objects/upload?key=") {
		t.Error("expected /objects/upload?key= endpoint usage in app.js")
	}
}

// Test 27: JavaScript uses correct delete API pattern.
func TestUIShell_JSUsesDeleteAPIPattern(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/static/app.js", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// Delete endpoint pattern (DELETE /ui/api/buckets/{bucket}/objects?key=...)
	if !strings.Contains(body, "apiCall('DELETE'") {
		t.Error("expected DELETE method call in app.js for object delete")
	}
}

// Test 28: CSS contains upload form styles.
func TestUIShell_CSSContainsUploadStyles(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/static/style.css", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	if !strings.Contains(body, ".object-upload-form") {
		t.Error("expected .object-upload-form class in CSS")
	}

	if !strings.Contains(body, ".upload-form-row") {
		t.Error("expected .upload-form-row class in CSS")
	}
}

// Test 29: JavaScript uses correct pagination parameter name (continuationToken, not continuation-token).
func TestUIShell_JSPaginationParamName(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/static/app.js", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	body := rr.Body.String()

	// Must use continuationToken (camelCase) to match backend handler.go
	if !strings.Contains(body, "continuationToken=") {
		t.Error("expected 'continuationToken=' query param in app.js for pagination")
	}

	// Must NOT use hyphenated version (legacy bug)
	if strings.Contains(body, "continuation-token=") {
		t.Error("app.js must not use 'continuation-token=' (should be 'continuationToken=')")
	}
}

// Test 30: JavaScript does not use inline onclick with user-controlled data.
// Inline onclick="func('${escapeHtml(value)}')" is unsafe when value contains quotes.
func TestUIShell_JSNoUnsafeInlineOnclick(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/static/app.js", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	body := rr.Body.String()

	// Check for unsafe patterns: onclick="...('${escapeHtml(...)}')..."
	// These break when the escaped value contains apostrophe (')
	unsafePatterns := []string{
		`onclick="window.deleteBucket('${escapeHtml(`,
		`onclick="window.deleteObject('${escapeHtml(`,
		`onclick="window.showObjectMeta('${escapeHtml(`,
		`onclick="window.downloadObject('${escapeHtml(`,
		`onclick="window.navigateToPrefix('${escapeHtml(`,
	}

	for _, pattern := range unsafePatterns {
		if strings.Contains(body, pattern) {
			t.Errorf("app.js contains unsafe inline onclick pattern: %s", pattern)
		}
	}
}

// Test 31: JavaScript uses data attributes for action binding (safe pattern).
func TestUIShell_JSUsesDataAttributesForActions(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/static/app.js", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	body := rr.Body.String()

	// Check for safe patterns using data attributes
	safePatterns := []string{
		`data-action="delete-bucket"`,
		`data-action="delete"`,
		`data-action="show-meta"`,
		`data-action="download"`,
		`data-action="navigate-prefix"`,
		`data-breadcrumb-prefix=`,
	}

	for _, pattern := range safePatterns {
		if !strings.Contains(body, pattern) {
			t.Errorf("expected safe data attribute pattern in app.js: %s", pattern)
		}
	}
}

// Test 32: Access keys section exists in HTML shell.
func TestUIShell_AccessKeysSectionExists(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// Access keys section
	if !strings.Contains(body, `id="section-access-keys"`) {
		t.Error("expected section-access-keys in HTML")
	}

	// Access key table
	if !strings.Contains(body, `id="access-keys-table"`) {
		t.Error("expected access-keys-table in HTML")
	}

	// Access key create form
	if !strings.Contains(body, `id="access-key-create-form"`) {
		t.Error("expected access-key-create-form in HTML")
	}

	// Secret display area
	if !strings.Contains(body, `id="access-key-secret-display"`) {
		t.Error("expected access-key-secret-display in HTML")
	}

	// New access key ID display
	if !strings.Contains(body, `id="new-access-key-id"`) {
		t.Error("expected new-access-key-id in HTML")
	}

	// New secret key display
	if !strings.Contains(body, `id="new-secret-key"`) {
		t.Error("expected new-secret-key in HTML")
	}

	// Nav button for access-keys should be enabled (not disabled)
	if strings.Contains(body, `data-section="access-keys" disabled`) {
		t.Error("access-keys nav button should not be disabled")
	}
}

// Test 33: JavaScript contains access key management functions.
func TestUIShell_JSContainsAccessKeyFunctions(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/static/app.js", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// Access key functions
	if !strings.Contains(body, "loadAccessKeys") {
		t.Error("expected loadAccessKeys function in app.js")
	}

	if !strings.Contains(body, "createAccessKey") {
		t.Error("expected createAccessKey function in app.js")
	}

	if !strings.Contains(body, "revokeAccessKey") {
		t.Error("expected revokeAccessKey function in app.js")
	}

	if !strings.Contains(body, "deleteAccessKey") {
		t.Error("expected deleteAccessKey function in app.js")
	}

	// Window exports for access key actions
	if !strings.Contains(body, "window.revokeAccessKey") {
		t.Error("expected window.revokeAccessKey export in app.js")
	}

	if !strings.Contains(body, "window.deleteAccessKey") {
		t.Error("expected window.deleteAccessKey export in app.js")
	}
}

// Test 34: JavaScript uses access key API endpoints.
func TestUIShell_JSUsesAccessKeyAPIEndpoints(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/static/app.js", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// List access keys endpoint
	if !strings.Contains(body, "/ui/api/access-keys") {
		t.Error("expected /ui/api/access-keys endpoint usage in app.js")
	}

	// Revoke endpoint
	if !strings.Contains(body, "/ui/api/access-keys/revoke") {
		t.Error("expected /ui/api/access-keys/revoke endpoint usage in app.js")
	}

	// Delete endpoint
	if !strings.Contains(body, "/ui/api/access-keys/delete") {
		t.Error("expected /ui/api/access-keys/delete endpoint usage in app.js")
	}
}

// Test 35: JavaScript uses data attributes for access key actions (safe pattern).
func TestUIShell_JSUsesDataAttributesForAccessKeyActions(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/static/app.js", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	body := rr.Body.String()

	// Check for safe patterns using data attributes for access keys
	safePatterns := []string{
		`data-action="revoke-key"`,
		`data-action="delete-key"`,
		`data-access-key=`,
	}

	for _, pattern := range safePatterns {
		if !strings.Contains(body, pattern) {
			t.Errorf("expected safe data attribute pattern in app.js: %s", pattern)
		}
	}
}

// Test 36: CSS contains access key management styles.
func TestUIShell_CSSContainsAccessKeyStyles(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/static/style.css", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	body := rr.Body.String()

	// Secret panel styles
	if !strings.Contains(body, ".access-key-secret-panel") {
		t.Error("expected .access-key-secret-panel class in CSS")
	}

	// Status badges
	if !strings.Contains(body, ".status-badge") {
		t.Error("expected .status-badge class in CSS")
	}

	if !strings.Contains(body, ".status-active") {
		t.Error("expected .status-active class in CSS")
	}

	if !strings.Contains(body, ".status-inactive") {
		t.Error("expected .status-inactive class in CSS")
	}

	// Type badges
	if !strings.Contains(body, ".type-badge") {
		t.Error("expected .type-badge class in CSS")
	}

	if !strings.Contains(body, ".type-root") {
		t.Error("expected .type-root class in CSS")
	}

	if !strings.Contains(body, ".type-service") {
		t.Error("expected .type-service class in CSS")
	}

	// Secret blur
	if !strings.Contains(body, ".secret-blur") {
		t.Error("expected .secret-blur class in CSS")
	}
}

// min returns the smaller of a and b.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ========== Settings Shell Tests ==========

// Test 37: Settings navigation button is enabled.
func TestUIShell_SettingsNavEnabled(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// Settings nav button should NOT be disabled
	if strings.Contains(body, `data-section="settings" disabled`) {
		t.Error("expected settings nav button to be enabled, but it is disabled")
	}

	// Settings nav button should exist without 'disabled' class
	if strings.Contains(body, `class="nav-btn disabled" data-section="settings"`) {
		t.Error("expected settings nav button to not have 'disabled' class")
	}

	// Should have the settings data-section attribute
	if !strings.Contains(body, `data-section="settings"`) {
		t.Error("expected data-section=\"settings\" in HTML")
	}
}

// Test 38: Settings section exists in HTML.
func TestUIShell_SettingsSectionExists(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	if !strings.Contains(body, `id="section-settings"`) {
		t.Error("expected section-settings ID in HTML")
	}

	if !strings.Contains(body, `id="settings-loading"`) {
		t.Error("expected settings-loading ID in HTML")
	}

	if !strings.Contains(body, `id="settings-content"`) {
		t.Error("expected settings-content ID in HTML")
	}

	if !strings.Contains(body, `id="settings-paths-tbody"`) {
		t.Error("expected settings-paths-tbody ID in HTML")
	}
}

// Test 39: Settings section contains server settings elements.
func TestUIShell_SettingsServerElementsExist(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	elements := []string{
		"settings-server-listen",
		"settings-server-public-endpoint",
		"settings-server-enable-ui",
		"settings-s3-region",
		"settings-ui-session-ttl",
		"settings-logging-level",
		"settings-gc-orphan-interval",
		"settings-config-path",
	}

	for _, id := range elements {
		if !strings.Contains(body, id) {
			t.Errorf("expected %s ID in HTML", id)
		}
	}
}

// Test 40: Settings section contains env-lock badge elements.
func TestUIShell_SettingsEnvLockBadgesExist(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// Check for env-lock-badge class
	if !strings.Contains(body, "env-lock-badge") {
		t.Error("expected env-lock-badge class in HTML")
	}

	// Check for lock badge IDs
	lockBadges := []string{
		"settings-lock-server-listen",
		"settings-lock-s3-region",
		"settings-lock-logging-level",
	}

	for _, id := range lockBadges {
		if !strings.Contains(body, id) {
			t.Errorf("expected %s ID in HTML", id)
		}
	}
}

// Test 41: JavaScript contains loadSettings function.
func TestUIShell_JSContainsLoadSettingsFunction(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/static/app.js", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// loadSettings function
	if !strings.Contains(body, "loadSettings") {
		t.Error("expected loadSettings function in app.js")
	}

	// renderSettings function
	if !strings.Contains(body, "renderSettings") {
		t.Error("expected renderSettings function in app.js")
	}

	// renderPathStatus function
	if !strings.Contains(body, "renderPathStatus") {
		t.Error("expected renderPathStatus function in app.js")
	}
}

// Test 42: JavaScript uses settings API endpoint.
func TestUIShell_JSUsesSettingsAPIEndpoint(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/static/app.js", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// Settings API endpoint
	if !strings.Contains(body, "/ui/api/settings") {
		t.Error("expected /ui/api/settings endpoint usage in app.js")
	}
}

// Test 43: JavaScript showSection handles settings.
func TestUIShell_JSShowSectionHandlesSettings(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/static/app.js", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// showSection should call loadSettings for settings section
	if !strings.Contains(body, `sectionName === 'settings'`) {
		t.Error("expected showSection to handle 'settings' section in app.js")
	}
}

// Test 44: CSS contains settings styles.
func TestUIShell_CSSContainsSettingsStyles(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/static/style.css", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// Settings card styles
	if !strings.Contains(body, ".settings-card") {
		t.Error("expected .settings-card class in CSS")
	}

	// Settings row styles
	if !strings.Contains(body, ".settings-row") {
		t.Error("expected .settings-row class in CSS")
	}

	// Env lock badge
	if !strings.Contains(body, ".env-lock-badge") {
		t.Error("expected .env-lock-badge class in CSS")
	}

	// Settings path table
	if !strings.Contains(body, ".settings-path-table") {
		t.Error("expected .settings-path-table class in CSS")
	}
}

// Test 45: Settings section contains path status table.
func TestUIShell_SettingsPathTableExists(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// Path status table
	if !strings.Contains(body, "settings-path-table") {
		t.Error("expected settings-path-table class in HTML")
	}

	// Table headers for path status
	if !strings.Contains(body, "디스크 사용량") {
		t.Error("expected '디스크 사용량' header in HTML for disk stats")
	}
}

// Test 46: JavaScript has formatDiskUsage function for disk stats.
func TestUIShell_JSHasFormatDiskUsageFunction(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/static/app.js", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// formatDiskUsage function
	if !strings.Contains(body, "formatDiskUsage") {
		t.Error("expected formatDiskUsage function in app.js")
	}

	// getPathStatusBadge function
	if !strings.Contains(body, "getPathStatusBadge") {
		t.Error("expected getPathStatusBadge function in app.js")
	}
}

// Test 47: Settings section is read-only notice displayed.
func TestUIShell_SettingsReadOnlyNoticeExists(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// Read-only notice
	if !strings.Contains(body, "읽기 전용") {
		t.Error("expected '읽기 전용' notice in HTML for settings")
	}

	// Config file mention
	if !strings.Contains(body, "config.yaml") {
		t.Error("expected config.yaml mention in settings notice")
	}
}

// ========== Password Change UI Tests ==========

// Test 48: Password change form exists in settings section.
func TestUIShell_PasswordChangeFormExists(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// Check for password change form elements
	if !strings.Contains(body, "password-change-form") {
		t.Error("expected password-change-form ID in HTML")
	}
	if !strings.Contains(body, "current-password") {
		t.Error("expected current-password input ID in HTML")
	}
	if !strings.Contains(body, "new-password") {
		t.Error("expected new-password input ID in HTML")
	}
	if !strings.Contains(body, "password-change-btn") {
		t.Error("expected password-change-btn ID in HTML")
	}
}

// Test 49: Password change error/success message containers exist.
func TestUIShell_PasswordChangeMessageContainersExist(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	if !strings.Contains(body, "password-change-error") {
		t.Error("expected password-change-error ID in HTML")
	}
	if !strings.Contains(body, "password-change-success") {
		t.Error("expected password-change-success ID in HTML")
	}
}

// Test 50: JavaScript contains password change function.
func TestUIShell_JSContainsPasswordChangeFunction(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/static/app.js", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	body := rr.Body.String()

	if !strings.Contains(body, "changePassword") {
		t.Error("expected changePassword function in app.js")
	}
	if !strings.Contains(body, "showPasswordChangeMessage") {
		t.Error("expected showPasswordChangeMessage function in app.js")
	}
}

// Test 51: JavaScript uses password change API endpoint.
func TestUIShell_JSUsesPasswordChangeAPIEndpoint(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/static/app.js", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	body := rr.Body.String()

	// Check for password change API endpoint usage
	if !strings.Contains(body, "/ui/api/account/password") {
		t.Error("expected /ui/api/account/password API endpoint in app.js")
	}
}

// Test 52: Password inputs have correct autocomplete attributes for security.
func TestUIShell_PasswordInputsHaveAutocompleteAttributes(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// Check for proper autocomplete attributes
	if !strings.Contains(body, `autocomplete="current-password"`) {
		t.Error("expected autocomplete='current-password' attribute for current password input")
	}
	if !strings.Contains(body, `autocomplete="new-password"`) {
		t.Error("expected autocomplete='new-password' attribute for new password input")
	}
}

// Test 53: JavaScript handles session invalidation after password change.
// Per security-model.md section 5.2: session invalidation after password change.
func TestUIShell_JSHandlesSessionInvalidationAfterPasswordChange(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/static/app.js", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	body := rr.Body.String()

	// After successful password change, UI should redirect to login.
	// Check that the changePassword function handles success by redirecting to login.
	if !strings.Contains(body, "showScreen('login')") {
		t.Error("expected showScreen('login') call after successful password change")
	}

	// Success message should be shown before redirect.
	if !strings.Contains(body, "비밀번호가 변경되었습니다") {
		t.Error("expected Korean success message for password change")
	}
}

// Test 54: Password change card is within settings section.
func TestUIShell_PasswordChangeCardInSettingsSection(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// Password change card ID should exist
	if !strings.Contains(body, "password-change-card") {
		t.Error("expected password-change-card ID in HTML")
	}

	// The card should have settings-card class
	if !strings.Contains(body, `class="settings-card" id="password-change-card"`) {
		t.Error("expected password-change-card to have settings-card class")
	}
}
