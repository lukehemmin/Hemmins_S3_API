package ui_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	ui "github.com/lukehemmin/hemmins-s3-api/internal/http/ui"
)

// notReady and alwaysReady are helper isReady funcs for gate tests.
var notReady = func() bool { return false }
var alwaysReady = func() bool { return true }

// doRawLogin issues POST /ui/api/session/login WITHOUT fetching CSRF token first.
// Used for gate tests where the gate returns 503 for all requests including CSRF.
func doRawLogin(t *testing.T, handler http.Handler, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	req := httptest.NewRequest(http.MethodPost, "/ui/api/session/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// TestGate_NotReady_Login: setup-required state → /ui/api/session/login returns 503.
// Without the gate, an empty DB returns 401 "invalid credentials", which falsely implies
// bootstrap succeeded but credentials are wrong. 503 "setup required" is unambiguous.
// Per security-model.md §3.2.
func TestGate_NotReady_Login(t *testing.T) {
	base, _ := setupTestUIServer(t, false)
	handler := ui.WithReadinessGate(notReady, base)

	// Use raw login to avoid fetching CSRF first (which would also return 503).
	rr := doRawLogin(t, handler, testAdminUsername, testAdminPassword)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestGate_NotReady_Me: setup-required state → /ui/api/session/me returns 503.
func TestGate_NotReady_Me(t *testing.T) {
	base, _ := setupTestUIServer(t, false)
	handler := ui.WithReadinessGate(notReady, base)

	rr := doMe(t, handler, nil)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestGate_NotReady_Dashboard: setup-required state → /ui/api/dashboard returns 503.
func TestGate_NotReady_Dashboard(t *testing.T) {
	base, _ := setupTestUIServer(t, false)
	handler := ui.WithReadinessGate(notReady, base)

	rr := doDashboard(t, handler, nil)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestGate_NotReady_CSRF: setup-required state → /ui/api/session/csrf returns 503.
func TestGate_NotReady_CSRF(t *testing.T) {
	base, _ := setupTestUIServer(t, false)
	handler := ui.WithReadinessGate(notReady, base)

	req := httptest.NewRequest(http.MethodGet, "/ui/api/session/csrf", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestGate_Ready_LoginPassesThrough: when ready, login reaches the normal handler.
func TestGate_Ready_LoginPassesThrough(t *testing.T) {
	base, _ := setupTestUIServer(t, false)
	handler := ui.WithReadinessGate(alwaysReady, base)

	rr := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestGate_Ready_DashboardPassesThrough: when ready, dashboard reaches the normal handler.
func TestGate_Ready_DashboardPassesThrough(t *testing.T) {
	base, _ := setupTestUIServer(t, false)
	handler := ui.WithReadinessGate(alwaysReady, base)

	loginRR := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRR.Code)
	}

	rr := doDashboard(t, handler, loginRR.Result().Cookies())
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestGate_ReadinessTransition: gate is dynamic — once isReady flips to true, requests succeed.
func TestGate_ReadinessTransition(t *testing.T) {
	base, _ := setupTestUIServer(t, false)

	ready := false
	handler := ui.WithReadinessGate(func() bool { return ready }, base)

	// Before ready: 503 (use raw login to avoid CSRF fetch).
	rr := doRawLogin(t, handler, testAdminUsername, testAdminPassword)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("before ready: expected 503, got %d", rr.Code)
	}

	// Flip to ready.
	ready = true

	// After ready: normal handler takes over (CSRF is now available).
	rr2 := doLogin(t, handler, testAdminUsername, testAdminPassword)
	if rr2.Code != http.StatusOK {
		t.Errorf("after ready: expected 200, got %d: %s", rr2.Code, rr2.Body.String())
	}
}
