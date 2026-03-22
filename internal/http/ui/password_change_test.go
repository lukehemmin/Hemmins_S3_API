package ui_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lukehemmin/hemmins-s3-api/internal/auth"
	ui "github.com/lukehemmin/hemmins-s3-api/internal/http/ui"
	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

const (
	newTestPassword = "newpassword456!"
)

// doPasswordChange issues POST /ui/api/account/password with CSRF token.
func doPasswordChange(t *testing.T, handler http.Handler, cookies []*http.Cookie, currentPassword, newPassword string) *httptest.ResponseRecorder {
	t.Helper()

	// Get a fresh CSRF token.
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

	body := map[string]string{
		"currentPassword": currentPassword,
		"newPassword":     newPassword,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/ui/api/account/password", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", token)

	// Add existing cookies (session).
	for _, c := range cookies {
		req.AddCookie(c)
	}
	// Add the new CSRF cookie.
	req.AddCookie(csrfCookie)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// doPasswordChangeWithoutCSRF issues POST /ui/api/account/password WITHOUT CSRF token.
func doPasswordChangeWithoutCSRF(t *testing.T, handler http.Handler, cookies []*http.Cookie, currentPassword, newPassword string) *httptest.ResponseRecorder {
	t.Helper()

	body := map[string]string{
		"currentPassword": currentPassword,
		"newPassword":     newPassword,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/ui/api/account/password", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	for _, c := range cookies {
		req.AddCookie(c)
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// Test: valid session + valid CSRF + correct currentPassword → success
func TestPasswordChange_Success(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	// Login with original password.
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Change password.
	rr := doPasswordChange(t, handler, cookies, testAdminPassword, newTestPassword)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]bool
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if !resp["changed"] {
		t.Error("expected changed=true in response")
	}
}

// Test: DB password_hash actually changes.
func TestPasswordChange_HashUpdatedInDB(t *testing.T) {
	handler, db := setupTestUIServer(t, false)

	// Login with original password.
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Get original hash.
	userBefore, err := db.LookupUIUser(testAdminUsername)
	if err != nil {
		t.Fatalf("LookupUIUser before: %v", err)
	}
	hashBefore := userBefore.PasswordHash

	// Change password.
	rr := doPasswordChange(t, handler, cookies, testAdminPassword, newTestPassword)
	if rr.Code != http.StatusOK {
		t.Fatalf("password change failed: %d: %s", rr.Code, rr.Body.String())
	}

	// Get new hash.
	userAfter, err := db.LookupUIUser(testAdminUsername)
	if err != nil {
		t.Fatalf("LookupUIUser after: %v", err)
	}
	hashAfter := userAfter.PasswordHash

	if hashAfter == hashBefore {
		t.Error("password_hash did not change in DB")
	}

	// Verify the new hash is a valid argon2id hash for the new password.
	match, err := auth.VerifyPassword(newTestPassword, hashAfter)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !match {
		t.Error("new password hash does not match new password")
	}
}

// Test: old password fails login, new password succeeds after change.
func TestPasswordChange_OldPasswordFailsNewSucceeds(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	// Login with original password.
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Change password.
	rr := doPasswordChange(t, handler, cookies, testAdminPassword, newTestPassword)
	if rr.Code != http.StatusOK {
		t.Fatalf("password change failed: %d: %s", rr.Code, rr.Body.String())
	}

	// Try to login with old password — should fail.
	oldLoginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if oldLoginRR.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for old password, got %d", oldLoginRR.Code)
	}

	// Login with new password — should succeed.
	newLoginRR := doLogin(t, handler, testAdminUsername, newTestPassword)
	if newLoginRR.Code != http.StatusOK {
		t.Errorf("expected 200 for new password, got %d: %s", newLoginRR.Code, newLoginRR.Body.String())
	}
}

// Test: no session → 401.
func TestPasswordChange_NoSession_Returns401(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	// Attempt password change without any session cookie.
	rr := doPasswordChange(t, handler, nil, testAdminPassword, newTestPassword)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Test: missing CSRF → 403.
func TestPasswordChange_MissingCSRF_Returns403(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	// Login first.
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Attempt password change without CSRF.
	rr := doPasswordChangeWithoutCSRF(t, handler, cookies, testAdminPassword, newTestPassword)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing error response: %v", err)
	}
	if !strings.Contains(resp["error"], "CSRF") {
		t.Errorf("expected CSRF error message, got %q", resp["error"])
	}
}

// Test: wrong currentPassword → 403.
func TestPasswordChange_WrongCurrentPassword_Returns403(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	// Login first.
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Attempt password change with wrong current password.
	rr := doPasswordChange(t, handler, cookies, "wrongpassword", newTestPassword)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing error response: %v", err)
	}
	if !strings.Contains(resp["error"], "current password") {
		t.Errorf("expected current password error message, got %q", resp["error"])
	}
}

// Test: empty newPassword → 400.
func TestPasswordChange_EmptyNewPassword_Returns400(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	// Login first.
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Attempt password change with empty new password.
	rr := doPasswordChange(t, handler, cookies, testAdminPassword, "")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing error response: %v", err)
	}
	if !strings.Contains(resp["error"], "newPassword") {
		t.Errorf("expected newPassword error message, got %q", resp["error"])
	}
}

// Test: empty currentPassword → 400.
func TestPasswordChange_EmptyCurrentPassword_Returns400(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	// Login first.
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Attempt password change with empty current password.
	rr := doPasswordChange(t, handler, cookies, "", newTestPassword)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing error response: %v", err)
	}
	if !strings.Contains(resp["error"], "currentPassword") {
		t.Errorf("expected currentPassword error message, got %q", resp["error"])
	}
}

// Test: current session is invalidated after password change.
func TestPasswordChange_CurrentSessionInvalidated(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	// Login.
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Verify session is valid by calling /me.
	meReq := httptest.NewRequest(http.MethodGet, "/ui/api/session/me", nil)
	for _, c := range cookies {
		meReq.AddCookie(c)
	}
	meRR := httptest.NewRecorder()
	handler.ServeHTTP(meRR, meReq)
	if meRR.Code != http.StatusOK {
		t.Fatalf("session not valid before password change: %d", meRR.Code)
	}

	// Change password.
	changeRR := doPasswordChange(t, handler, cookies, testAdminPassword, newTestPassword)
	if changeRR.Code != http.StatusOK {
		t.Fatalf("password change failed: %d: %s", changeRR.Code, changeRR.Body.String())
	}

	// Try to use the same session — should be invalidated.
	meReq2 := httptest.NewRequest(http.MethodGet, "/ui/api/session/me", nil)
	for _, c := range cookies {
		meReq2.AddCookie(c)
	}
	meRR2 := httptest.NewRecorder()
	handler.ServeHTTP(meRR2, meReq2)

	if meRR2.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 after password change, got %d", meRR2.Code)
	}
}

// Test: all sessions for the user are invalidated, not just the current one.
func TestPasswordChange_AllSessionsInvalidated(t *testing.T) {
	// Need to create a custom server with a shared session store to test multiple sessions.
	db, err := setupTestDB(t)
	if err != nil {
		t.Fatalf("setupTestDB: %v", err)
	}

	store := ui.NewSessionStore(12*time.Hour, 30*time.Minute)
	srv := ui.NewServer(db, store, false)
	handler := srv.Handler()

	// Create two sessions by logging in twice.
	loginRR1 := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR1.Code != http.StatusOK {
		t.Fatalf("first login failed: %d", loginRR1.Code)
	}
	cookies1 := loginRR1.Result().Cookies()

	loginRR2 := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR2.Code != http.StatusOK {
		t.Fatalf("second login failed: %d", loginRR2.Code)
	}
	cookies2 := loginRR2.Result().Cookies()

	// Verify both sessions are valid.
	for i, cookies := range [][]*http.Cookie{cookies1, cookies2} {
		meReq := httptest.NewRequest(http.MethodGet, "/ui/api/session/me", nil)
		for _, c := range cookies {
			meReq.AddCookie(c)
		}
		meRR := httptest.NewRecorder()
		handler.ServeHTTP(meRR, meReq)
		if meRR.Code != http.StatusOK {
			t.Fatalf("session %d not valid before password change: %d", i+1, meRR.Code)
		}
	}

	// Change password using session 1.
	changeRR := doPasswordChange(t, handler, cookies1, testAdminPassword, newTestPassword)
	if changeRR.Code != http.StatusOK {
		t.Fatalf("password change failed: %d: %s", changeRR.Code, changeRR.Body.String())
	}

	// Both sessions should be invalidated.
	for i, cookies := range [][]*http.Cookie{cookies1, cookies2} {
		meReq := httptest.NewRequest(http.MethodGet, "/ui/api/session/me", nil)
		for _, c := range cookies {
			meReq.AddCookie(c)
		}
		meRR := httptest.NewRecorder()
		handler.ServeHTTP(meRR, meReq)
		if meRR.Code != http.StatusUnauthorized {
			t.Errorf("session %d: expected 401 after password change, got %d", i+1, meRR.Code)
		}
	}
}

// Test: method not allowed for non-POST.
func TestPasswordChange_MethodNotAllowed(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	// Login first.
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(method, "/ui/api/account/password", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: expected 405, got %d", method, rr.Code)
		}
	}
}

// Test: response clears session and CSRF cookies.
func TestPasswordChange_ClearsCookies(t *testing.T) {
	handler, _ := setupTestUIServer(t, false)

	// Login.
	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	cookies := loginRR.Result().Cookies()

	// Change password.
	changeRR := doPasswordChange(t, handler, cookies, testAdminPassword, newTestPassword)
	if changeRR.Code != http.StatusOK {
		t.Fatalf("password change failed: %d: %s", changeRR.Code, changeRR.Body.String())
	}

	// Check that session cookie is cleared.
	sessionCookie := findSessionCookie(changeRR)
	if sessionCookie != nil && sessionCookie.Value != "" && sessionCookie.MaxAge != -1 {
		t.Errorf("expected session cookie to be cleared, got value=%q maxAge=%d", sessionCookie.Value, sessionCookie.MaxAge)
	}

	// Check that CSRF cookie is cleared.
	csrfCookie := findCSRFCookie(changeRR)
	if csrfCookie != nil && csrfCookie.Value != "" && csrfCookie.MaxAge != -1 {
		t.Errorf("expected CSRF cookie to be cleared, got value=%q maxAge=%d", csrfCookie.Value, csrfCookie.MaxAge)
	}
}

// setupTestDB creates a bootstrapped DB for multi-session tests.
func setupTestDB(t *testing.T) (*metadata.DB, error) {
	t.Helper()
	db, err := metadata.Open(":memory:")
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { db.Close() })

	pwHash, err := auth.HashPassword(testAdminPassword)
	if err != nil {
		return nil, err
	}
	ciphertext, err := auth.EncryptSecret(testMasterKey, testRootSecretKey)
	if err != nil {
		return nil, err
	}
	if err := db.Bootstrap(testAdminUsername, pwHash, testAccessKey, ciphertext); err != nil {
		return nil, err
	}
	return db, nil
}
