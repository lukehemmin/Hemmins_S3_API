package auth

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// presignMaxAllowedTTL is the AWS S3 hard upper bound for X-Amz-Expires (7 days).
// Used as the fallback when PresignVerifier.MaxTTL is not configured.
const presignMaxAllowedTTL = 7 * 24 * time.Hour

// Sentinel errors for presigned URL verification.
// Callers should use errors.Is to inspect failure type.
var (
	// ErrMissingPresignParam is returned when a required presigned URL query
	// parameter (X-Amz-Algorithm, X-Amz-Credential, etc.) is absent.
	ErrMissingPresignParam = errors.New("missing required presigned URL parameter")

	// ErrExpiredPresignURL is returned when the current time is past
	// X-Amz-Date + X-Amz-Expires.
	ErrExpiredPresignURL = errors.New("presigned URL has expired")

	// ErrPresignTTLExceeded is returned when X-Amz-Expires exceeds the
	// configured maximum allowed TTL (PresignVerifier.MaxTTL or the 7-day AWS limit).
	ErrPresignTTLExceeded = errors.New("X-Amz-Expires exceeds maximum allowed TTL")

	// ErrInvalidPresignExpires is returned when X-Amz-Expires is absent, not an
	// integer, zero, or negative.
	ErrInvalidPresignExpires = errors.New("X-Amz-Expires must be a positive integer")

	// ErrHostNotSigned is returned when X-Amz-SignedHeaders does not include "host".
	// Per SigV4 spec, host is a mandatory signed header: it binds the presigned URL
	// to the specific endpoint and prevents cross-endpoint signature reuse.
	ErrHostNotSigned = errors.New("X-Amz-SignedHeaders must include \"host\"")

	// ErrPresignNotYetValid is returned when the current time is before the signing
	// time (X-Amz-Date). Policy: strict mode — no clock-skew tolerance. A URL
	// signed in the future has a signing time that has not yet elapsed, which could
	// extend the effective validity window beyond what X-Amz-Expires declares.
	ErrPresignNotYetValid = errors.New("presigned URL is not yet valid (signed in the future)")
)

// ParsedPresign holds the fields parsed from a presigned S3 URL's query parameters.
type ParsedPresign struct {
	AccessKeyID    string
	Date           string   // YYYYMMDD from X-Amz-Credential scope
	Region         string
	Service        string
	DateTime       string   // X-Amz-Date value (YYYYMMDDTHHMMSSZ)
	ExpiresSeconds int64    // X-Amz-Expires as seconds
	SignedHeaders  []string // lowercase, from X-Amz-SignedHeaders; sorted per SigV4
	Signature      string   // X-Amz-Signature
	PayloadHash    string   // X-Amz-Content-Sha256 if present, otherwise "UNSIGNED-PAYLOAD"
}

// ParsePresignQuery parses and validates the presigned URL query parameters from q.
//
// Required parameters: X-Amz-Algorithm, X-Amz-Credential, X-Amz-Date,
// X-Amz-Expires, X-Amz-SignedHeaders, X-Amz-Signature.
//
// X-Amz-Security-Token (STS session tokens) is not supported in MVP and is
// rejected explicitly so clients receive a clear error rather than "key not found".
//
// X-Amz-Content-Sha256 is optional; absent means UNSIGNED-PAYLOAD.
func ParsePresignQuery(q url.Values) (*ParsedPresign, error) {
	// STS session tokens are not supported in MVP.
	// Per s3-compatibility-matrix.md: explicit failure, no silent fallback.
	if q.Get("X-Amz-Security-Token") != "" {
		return nil, fmt.Errorf("%w: X-Amz-Security-Token (STS session tokens) are not supported", ErrUnsupportedPayload)
	}

	// Algorithm — must be AWS4-HMAC-SHA256.
	algo := q.Get("X-Amz-Algorithm")
	if algo == "" {
		return nil, fmt.Errorf("%w: X-Amz-Algorithm", ErrMissingPresignParam)
	}
	if algo != sigV4Algorithm {
		return nil, fmt.Errorf("%w: algorithm %q is not supported, want %q",
			ErrMalformedAuthorization, algo, sigV4Algorithm)
	}

	// Credential — AKID/YYYYMMDD/region/service/aws4_request.
	cred := q.Get("X-Amz-Credential")
	if cred == "" {
		return nil, fmt.Errorf("%w: X-Amz-Credential", ErrMissingPresignParam)
	}
	credParts := strings.Split(cred, "/")
	if len(credParts) != 5 {
		return nil, fmt.Errorf("%w: X-Amz-Credential must have 5 slash-separated parts, got %d",
			ErrMalformedCredential, len(credParts))
	}
	for i, part := range credParts[:4] {
		if part == "" {
			return nil, fmt.Errorf("%w: empty field at index %d in X-Amz-Credential",
				ErrMalformedCredential, i)
		}
	}
	if credParts[4] != sigV4Terminator {
		return nil, fmt.Errorf("%w: expected terminator %q in X-Amz-Credential, got %q",
			ErrMalformedCredential, sigV4Terminator, credParts[4])
	}

	// Date — YYYYMMDDTHHMMSSZ.
	dateTime := q.Get("X-Amz-Date")
	if dateTime == "" {
		return nil, fmt.Errorf("%w: X-Amz-Date", ErrMissingPresignParam)
	}

	// Expires — positive integer seconds.
	expiresStr := q.Get("X-Amz-Expires")
	if expiresStr == "" {
		return nil, fmt.Errorf("%w: X-Amz-Expires", ErrMissingPresignParam)
	}
	expiresSeconds, err := strconv.ParseInt(expiresStr, 10, 64)
	if err != nil || expiresSeconds <= 0 {
		return nil, fmt.Errorf("%w: got %q", ErrInvalidPresignExpires, expiresStr)
	}

	// SignedHeaders — semicolon-separated list.
	signedHeadersStr := q.Get("X-Amz-SignedHeaders")
	if signedHeadersStr == "" {
		return nil, fmt.Errorf("%w: X-Amz-SignedHeaders", ErrMissingPresignParam)
	}
	signedHeaders := strings.Split(signedHeadersStr, ";")
	for i, h := range signedHeaders {
		signedHeaders[i] = strings.ToLower(strings.TrimSpace(h))
	}
	// Per SigV4 spec: "host" is a mandatory signed header for presigned URLs.
	// It binds the URL to the specific endpoint, preventing cross-endpoint reuse.
	// Reject at parse stage so callers always get a clear, early error.
	hasHost := false
	for _, h := range signedHeaders {
		if h == "host" {
			hasHost = true
			break
		}
	}
	if !hasHost {
		return nil, fmt.Errorf("%w: got %q", ErrHostNotSigned, signedHeadersStr)
	}

	// Signature.
	signature := q.Get("X-Amz-Signature")
	if signature == "" {
		return nil, fmt.Errorf("%w: X-Amz-Signature", ErrMissingPresignParam)
	}

	// Payload hash: presigned URLs default to UNSIGNED-PAYLOAD per
	// s3-compatibility-matrix.md section 5.1. Streaming mode is not supported.
	payloadHash := q.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		payloadHash = "UNSIGNED-PAYLOAD"
	}
	if payloadHash == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" {
		return nil, fmt.Errorf("%w: STREAMING-AWS4-HMAC-SHA256-PAYLOAD", ErrUnsupportedPayload)
	}

	return &ParsedPresign{
		AccessKeyID:    credParts[0],
		Date:           credParts[1],
		Region:         credParts[2],
		Service:        credParts[3],
		DateTime:       dateTime,
		ExpiresSeconds: expiresSeconds,
		SignedHeaders:  signedHeaders,
		Signature:      signature,
		PayloadHash:    payloadHash,
	}, nil
}

// PresignVerifier verifies SigV4 presigned URL signatures (query-parameter based auth).
// It implements the presigned GET and PUT flows defined in s3-compatibility-matrix.md.
//
// Construct by setting fields directly. Region, Service, and GetSecret are required.
// MaxTTL and Now are optional (default: 7-day AWS limit; time.Now).
type PresignVerifier struct {
	// Region is the configured S3 region (per s3-compatibility-matrix.md section 2.2).
	// Credential scope region must match exactly; mismatch is a hard failure.
	Region string

	// Service is the AWS service name in the credential scope; always "s3" for S3 API.
	Service string

	// MaxTTL is the maximum allowed X-Amz-Expires duration.
	// Zero value falls back to the AWS S3 hard limit (7 days = 604800s).
	MaxTTL time.Duration

	// GetSecret retrieves the plaintext secret for an access key ID.
	// Per security-model.md section 4.3: the secret must never be logged.
	GetSecret SecretProvider

	// Now returns the current time for expiry validation.
	// Set to a fixed function in tests for determinism. Defaults to time.Now.
	Now func() time.Time
}

func (v *PresignVerifier) currentTime() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *PresignVerifier) effectiveMaxTTL() time.Duration {
	if v.MaxTTL > 0 {
		return v.MaxTTL
	}
	return presignMaxAllowedTTL
}

// Verify verifies the SigV4 presigned URL signature on r.
//
// The request must carry the presigned parameters as query parameters.
// The Authorization header is NOT used; query params take precedence.
//
// Verification order:
//  1. Parse and validate all query parameters (includes host-in-SignedHeaders check)
//  2. Validate region and service against server configuration
//  3. Validate X-Amz-Date format; credential scope date must match
//  4. Not-yet-valid check: reject URLs signed in the future (strict mode)
//  5. TTL check: X-Amz-Expires must not exceed MaxTTL
//  6. Expiry check: URL must not be past its expiry time
//  7. Build canonical headers from X-Amz-SignedHeaders
//  8. Build canonical query string excluding X-Amz-Signature
//  9. Build canonical URI from raw (escaped) request path
// 10. Compute canonical request and string-to-sign
// 11. Look up secret and verify key is active
// 12. Compare computed signature with X-Amz-Signature (constant-time)
//
// Returns nil on success. Per security-model.md section 4.3: secrets are never logged.
func (v *PresignVerifier) Verify(r *http.Request) error {
	q := r.URL.Query()

	// 1. Parse presign query parameters.
	parsed, err := ParsePresignQuery(q)
	if err != nil {
		return err
	}

	// 2. Validate region and service.
	if parsed.Region != v.Region {
		return fmt.Errorf("%w: got %q, want %q", ErrWrongRegion, parsed.Region, v.Region)
	}
	if parsed.Service != v.Service {
		return fmt.Errorf("%w: got %q, want %q", ErrWrongService, parsed.Service, v.Service)
	}

	// 3. Parse and validate X-Amz-Date; date component must match credential scope.
	signedAt, err := time.Parse(sigV4DateTimeFormat, parsed.DateTime)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMalformedDate, err)
	}
	signedAt = signedAt.UTC()
	if signedAt.Format(sigV4DateFormat) != parsed.Date {
		return fmt.Errorf("%w: credential date %q does not match X-Amz-Date date %q",
			ErrMalformedCredential, parsed.Date, signedAt.Format(sigV4DateFormat))
	}

	// Compute current time once; used for both the not-yet-valid and expiry checks.
	now := v.currentTime().UTC()

	// 4. Not-yet-valid check (strict mode): reject URLs whose signing time has not
	// yet been reached. A URL signed in the future extends the effective window
	// beyond what X-Amz-Expires declares, and binds credentials to a time the
	// server has not verified. No clock-skew tolerance is applied; correct system
	// time is the client's responsibility.
	if now.Before(signedAt) {
		return fmt.Errorf("%w: signed at %s (now %s)",
			ErrPresignNotYetValid,
			signedAt.Format(time.RFC3339),
			now.Format(time.RFC3339))
	}

	// 5. Validate X-Amz-Expires: must not exceed MaxTTL.
	expiresDur := time.Duration(parsed.ExpiresSeconds) * time.Second
	if expiresDur > v.effectiveMaxTTL() {
		return fmt.Errorf("%w: %v exceeds maximum %v",
			ErrPresignTTLExceeded, expiresDur, v.effectiveMaxTTL())
	}

	// 6. Expiry check: URL must not be past its expiry time.
	expiresAt := signedAt.Add(expiresDur)
	if now.After(expiresAt) {
		return fmt.Errorf("%w: expired at %s (now %s)",
			ErrExpiredPresignURL,
			expiresAt.Format(time.RFC3339),
			now.Format(time.RFC3339))
	}

	// 7. Build canonical headers from the signed headers list.
	canonHdrs, signedHdrsStr, err := CanonicalHeaders(r, parsed.SignedHeaders)
	if err != nil {
		return err
	}

	// 8. Build canonical query string excluding X-Amz-Signature.
	// Per AWS SigV4 presign spec: the signature itself must not be part of the
	// canonical query string used to compute the signature.
	canonQuery := canonicalQueryStringExcluding(q, "X-Amz-Signature")

	// 9. Build canonical URI from the raw (escaped) request path.
	// Uses the same S3 no-double-encode contract as the header-based verifier.
	canonURI := CanonicalURI(requestRawPath(r))

	// 10. Build canonical request and string-to-sign.
	canonReq := CanonicalRequest(r.Method, canonURI, canonQuery, canonHdrs, signedHdrsStr, parsed.PayloadHash)
	scope := CredentialScope(parsed.Date, v.Region, v.Service)
	sts := StringToSign(parsed.DateTime, scope, HashSHA256Hex([]byte(canonReq)))

	// 11. Look up plaintext secret. Must NOT be logged — per security-model.md section 4.3.
	secret, isActive, err := v.GetSecret(parsed.AccessKeyID)
	if err != nil {
		return fmt.Errorf("looking up access key: %w", err)
	}
	if !isActive {
		return fmt.Errorf("%w: %q", ErrInactiveKey, parsed.AccessKeyID)
	}

	// 12. Derive signing key, compute expected signature, compare constant-time.
	signingKey := DeriveSigningKey(secret, parsed.Date, v.Region, v.Service)
	expectedSig := ComputeSignature(signingKey, sts)
	if subtle.ConstantTimeCompare([]byte(expectedSig), []byte(parsed.Signature)) != 1 {
		return ErrSignatureMismatch
	}
	return nil
}

// canonicalQueryStringExcluding builds the SigV4 canonical query string from q,
// omitting the key named excludeKey.
//
// Used for presigned URL verification where X-Amz-Signature must be excluded from
// the canonical query it was computed over.
func canonicalQueryStringExcluding(q url.Values, excludeKey string) string {
	if len(q) == 0 {
		return ""
	}
	filtered := make(url.Values, len(q))
	for k, vs := range q {
		if k != excludeKey {
			filtered[k] = vs
		}
	}
	return CanonicalQueryString(filtered)
}
