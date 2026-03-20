// Package ui implements the management UI session API.
// Per system-architecture.md section 7.2 and security-model.md section 6:
// state-changing requests require CSRF protection.
package ui

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
)

const (
	csrfCookieName = "hemmins_csrf"
	csrfHeaderName = "X-CSRF-Token"
	csrfTokenBytes = 32 // 256-bit CSRF token
)

// generateCSRFToken creates a cryptographically random CSRF token.
func generateCSRFToken() (string, error) {
	b := make([]byte, csrfTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// setCSRFCookie writes the CSRF token as a cookie.
// Per security-model.md section 6 and 7:
//   - SameSite=Lax for CSRF mitigation
//   - Secure flag when public_endpoint is https://
//   - NOT HttpOnly: browser JS must read the cookie value to send it as a header
//
// Design decision: HttpOnly=false for CSRF cookie.
// Rationale: Double-submit cookie pattern requires the browser client to
// read the cookie value and include it in the X-CSRF-Token header.
// If HttpOnly=true, JavaScript cannot read the cookie, making the pattern impossible.
// The session cookie remains HttpOnly; only the CSRF cookie is readable by JS.
func setCSRFCookie(w http.ResponseWriter, token string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false, // Must be readable by JS for double-submit pattern
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
	})
}

// clearCSRFCookie removes the CSRF cookie by setting Max-Age=0.
func clearCSRFCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
		MaxAge:   -1,
	})
}

// validateCSRF checks the double-submit cookie pattern.
// Returns true if the X-CSRF-Token header matches the hemmins_csrf cookie.
// Per security-model.md section 6: state-changing requests require CSRF protection.
//
// Policy:
//   - Both cookie and header must be present
//   - Cookie and header values must match exactly
//   - Empty values are rejected
func validateCSRF(r *http.Request) bool {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}

	header := r.Header.Get(csrfHeaderName)
	if header == "" {
		return false
	}

	// Constant-time comparison is not strictly necessary here because
	// the token is random and attacker cannot learn partial matches,
	// but we use simple equality for clarity.
	return cookie.Value == header
}

// requireCSRF is a middleware helper that validates CSRF for POST requests.
// Returns true if validation passes; writes 403 JSON and returns false otherwise.
// Use this before processing state-changing operations.
func (s *Server) requireCSRF(w http.ResponseWriter, r *http.Request) bool {
	if !validateCSRF(r) {
		writeJSONError(w, http.StatusForbidden, "CSRF validation failed")
		return false
	}
	return true
}
