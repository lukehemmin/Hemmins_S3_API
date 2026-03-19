package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// SigV4 algorithm identifier and scope terminator per AWS documentation.
const (
	sigV4Algorithm     = "AWS4-HMAC-SHA256"
	sigV4Terminator    = "aws4_request"
	sigV4DateFormat    = "20060102"
	sigV4DateTimeFormat = "20060102T150405Z"
)

// Sentinel errors returned by ParseAuthorization and Verifier.Verify.
// Callers should use errors.Is to inspect failure type.
var (
	// ErrMalformedAuthorization is returned when the Authorization header cannot be parsed.
	ErrMalformedAuthorization = errors.New("malformed Authorization header")
	// ErrMalformedCredential is returned when the credential scope has an unexpected format.
	ErrMalformedCredential = errors.New("malformed credential scope")
	// ErrMissingSignedHeader is returned when a header listed in SignedHeaders is absent.
	ErrMissingSignedHeader = errors.New("signed header missing from request")
	// ErrWrongRegion is returned when the credential region does not match the server region.
	// Per s3-compatibility-matrix.md section 2.2: single region only.
	ErrWrongRegion = errors.New("credential scope region mismatch")
	// ErrWrongService is returned when the credential service does not match "s3".
	ErrWrongService = errors.New("credential scope service mismatch")
	// ErrInactiveKey is returned when the access key is inactive or does not exist.
	// Per security-model.md section 5.1: disabled keys must not authenticate new requests.
	ErrInactiveKey = errors.New("access key is inactive or does not exist")
	// ErrSignatureMismatch is returned when the computed signature does not match the provided one.
	ErrSignatureMismatch = errors.New("signature does not match")
	// ErrUnsupportedPayload is returned for payload signing modes not supported in MVP.
	// Per s3-compatibility-matrix.md section 5.1: STREAMING-AWS4-HMAC-SHA256-PAYLOAD is excluded.
	ErrUnsupportedPayload = errors.New("unsupported payload signing mode")
	// ErrMissingDateHeader is returned when the x-amz-date header is absent.
	ErrMissingDateHeader = errors.New("x-amz-date header is required")
	// ErrMalformedDate is returned when the x-amz-date value cannot be parsed.
	ErrMalformedDate = errors.New("malformed x-amz-date value")
	// ErrMissingPayloadHash is returned when the X-Amz-Content-Sha256 header is absent
	// from a header-based SigV4 request. The header is a required part of the signing
	// contract for header-based auth per s3-compatibility-matrix.md section 5.1.
	ErrMissingPayloadHash = errors.New("x-amz-content-sha256 header is required for header-based SigV4")
)

// ParsedAuth holds the fields extracted from a SigV4 Authorization header.
type ParsedAuth struct {
	AccessKeyID   string
	Date          string   // YYYYMMDD extracted from Credential scope
	Region        string
	Service       string
	SignedHeaders []string // lowercase, sorted (as received)
	Signature     string
}

// ParseAuthorization parses an AWS Signature Version 4 Authorization header value.
//
// Expected format (per AWS SigV4 spec):
//
//	AWS4-HMAC-SHA256 Credential=AKID/YYYYMMDD/region/service/aws4_request, SignedHeaders=hdr1;hdr2, Signature=hexsig
//
// Returns ErrMalformedAuthorization wrapping ErrMalformedCredential for bad credential scope.
func ParseAuthorization(header string) (*ParsedAuth, error) {
	prefix := sigV4Algorithm + " "
	if !strings.HasPrefix(header, prefix) {
		return nil, fmt.Errorf("%w: expected algorithm prefix %q", ErrMalformedAuthorization, sigV4Algorithm)
	}
	rest := strings.TrimPrefix(header, prefix)

	kv := parseAuthKVPairs(rest)

	credential, ok := kv["Credential"]
	if !ok || credential == "" {
		return nil, fmt.Errorf("%w: missing Credential", ErrMalformedAuthorization)
	}
	signedHeadersStr, ok := kv["SignedHeaders"]
	if !ok || signedHeadersStr == "" {
		return nil, fmt.Errorf("%w: missing SignedHeaders", ErrMalformedAuthorization)
	}
	signature, ok := kv["Signature"]
	if !ok || signature == "" {
		return nil, fmt.Errorf("%w: missing Signature", ErrMalformedAuthorization)
	}

	// Parse credential scope: AKID/YYYYMMDD/region/service/aws4_request
	credParts := strings.Split(credential, "/")
	if len(credParts) != 5 {
		return nil, fmt.Errorf("%w: %w: expected 5 slash-separated parts, got %d",
			ErrMalformedAuthorization, ErrMalformedCredential, len(credParts))
	}
	if credParts[4] != sigV4Terminator {
		return nil, fmt.Errorf("%w: %w: expected terminator %q, got %q",
			ErrMalformedAuthorization, ErrMalformedCredential, sigV4Terminator, credParts[4])
	}
	for i, part := range credParts[:4] {
		if part == "" {
			return nil, fmt.Errorf("%w: %w: empty field at position %d in credential",
				ErrMalformedAuthorization, ErrMalformedCredential, i)
		}
	}

	signedHeaders := strings.Split(signedHeadersStr, ";")
	for i, h := range signedHeaders {
		signedHeaders[i] = strings.ToLower(strings.TrimSpace(h))
	}

	return &ParsedAuth{
		AccessKeyID:   credParts[0],
		Date:          credParts[1],
		Region:        credParts[2],
		Service:       credParts[3],
		SignedHeaders:  signedHeaders,
		Signature:     signature,
	}, nil
}

// parseAuthKVPairs splits "Key=Value, Key=Value, ..." into a map.
// Pairs are separated by ", " (comma-space) per the SigV4 Authorization header format.
func parseAuthKVPairs(s string) map[string]string {
	result := make(map[string]string)
	for _, part := range strings.Split(s, ", ") {
		part = strings.TrimSpace(part)
		idx := strings.IndexByte(part, '=')
		if idx < 0 {
			continue
		}
		result[part[:idx]] = part[idx+1:]
	}
	return result
}

// sigV4Encode percent-encodes s for use in SigV4 canonical forms.
// Unreserved characters (A–Z, a–z, 0–9, -, _, ., ~) are left as-is.
// Every other byte is encoded as %XX using uppercase hex.
// Per AWS SigV4 specification, URI encoding section.
func sigV4Encode(s string) string {
	var buf strings.Builder
	for i := 0; i < len(s); i++ {
		b := s[i]
		if isUnreservedByte(b) {
			buf.WriteByte(b)
		} else {
			fmt.Fprintf(&buf, "%%%02X", b)
		}
	}
	return buf.String()
}

func isUnreservedByte(b byte) bool {
	return (b >= 'A' && b <= 'Z') ||
		(b >= 'a' && b <= 'z') ||
		(b >= '0' && b <= '9') ||
		b == '-' || b == '_' || b == '.' || b == '~'
}

// CanonicalURI returns the S3 canonical URI for inclusion in the canonical request.
//
// S3-specific contract: the canonical URI is the already-escaped path as-is.
// AWS S3 SDK sets DisableURIPathEscaping=true, meaning the raw/escaped request path
// is used directly without additional percent-encoding. Re-encoding an already-escaped
// path produces double-encoding (%20 → %2520, %2F → %252F), which breaks verification
// for any object key that requires percent-encoding.
//
// The caller MUST pass an already-escaped path — r.URL.RawPath or r.URL.EscapedPath().
// Passing r.URL.Path (decoded) produces an incorrect canonical URI for any key that
// contains characters requiring encoding (spaces, non-ASCII bytes, etc.).
//
// An empty path is normalized to "/".
func CanonicalURI(escapedPath string) string {
	if escapedPath == "" {
		return "/"
	}
	if !strings.HasPrefix(escapedPath, "/") {
		escapedPath = "/" + escapedPath
	}
	return escapedPath
}

// CanonicalQueryString builds the sorted, percent-encoded query string for the canonical request.
// Keys and values are both encoded with sigV4Encode.
// Keys are sorted lexicographically; values within the same key are sorted.
// Returns "" when values is empty or nil.
func CanonicalQueryString(values url.Values) string {
	if len(values) == 0 {
		return ""
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(values))
	for _, k := range keys {
		vals := make([]string, len(values[k]))
		copy(vals, values[k])
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, sigV4Encode(k)+"="+sigV4Encode(v))
		}
	}
	return strings.Join(parts, "&")
}

// CanonicalHeaders builds the canonical headers block and the signed-headers string.
// signedHeaderNames is the list from the Authorization header (already lowercase).
// Headers are sorted lexicographically, lowercased, and values are trimmed.
// The returned canonHeaders string ends with '\n' (each header line ends with '\n').
// Returns ErrMissingSignedHeader if any signed header is absent from the request.
func CanonicalHeaders(r *http.Request, signedHeaderNames []string) (canonHeaders, signedHeaders string, err error) {
	sorted := make([]string, len(signedHeaderNames))
	copy(sorted, signedHeaderNames)
	sort.Strings(sorted)

	var sb strings.Builder
	for _, name := range sorted {
		var val string
		if name == "host" {
			val = r.Host
			if val == "" {
				val = r.Header.Get("Host")
			}
		} else {
			vals := r.Header.Values(name) // case-insensitive lookup
			if len(vals) == 0 {
				return "", "", fmt.Errorf("%w: %q", ErrMissingSignedHeader, name)
			}
			trimmed := make([]string, len(vals))
			for i, v := range vals {
				trimmed[i] = strings.TrimSpace(v)
			}
			val = strings.Join(trimmed, ",")
		}
		sb.WriteString(name)
		sb.WriteByte(':')
		sb.WriteString(strings.TrimSpace(val))
		sb.WriteByte('\n')
	}
	return sb.String(), strings.Join(sorted, ";"), nil
}

// HashSHA256Hex returns the lowercase hex-encoded SHA-256 hash of data.
// Called with nil data, returns the hash of the empty byte sequence.
func HashSHA256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// CanonicalRequest assembles the six-field SigV4 canonical request string.
// headers must end with '\n' (each individual header line ends with '\n').
// The resulting string is: method\nuri\nquery\nheaders\nsignedHeaders\npayloadHash
// Per https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
func CanonicalRequest(method, uri, query, headers, signedHeaders, payloadHash string) string {
	return strings.Join([]string{method, uri, query, headers, signedHeaders, payloadHash}, "\n")
}

// CredentialScope builds the SigV4 credential scope string: YYYYMMDD/region/service/aws4_request.
func CredentialScope(date, region, service string) string {
	return strings.Join([]string{date, region, service, sigV4Terminator}, "/")
}

// StringToSign builds the SigV4 string-to-sign.
//   - datetime: ISO 8601 basic format, e.g. "20240101T120000Z"
//   - credentialScope: from CredentialScope()
//   - canonicalRequestHash: HashSHA256Hex([]byte(canonicalRequest))
func StringToSign(datetime, credentialScope, canonicalRequestHash string) string {
	return strings.Join([]string{sigV4Algorithm, datetime, credentialScope, canonicalRequestHash}, "\n")
}

// DeriveSigningKey derives the SigV4 signing key from the plaintext secret access key
// and the date/region/service scope components.
//
// The derivation is:
//
//	kDate    = HMAC-SHA256("AWS4" + secret, date)
//	kRegion  = HMAC-SHA256(kDate,  region)
//	kService = HMAC-SHA256(kRegion, service)
//	kSigning = HMAC-SHA256(kService, "aws4_request")
func DeriveSigningKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte(sigV4Terminator))
}

// ComputeSignature computes the final HMAC-SHA256 signature over stringToSign and
// returns it as a lowercase hex string.
func ComputeSignature(signingKey []byte, stringToSign string) string {
	return hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))
}

// hmacSHA256 computes HMAC-SHA256(key, data).
func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// SecretProvider is a function that looks up the plaintext secret access key and
// active status for a given access key ID. The returned secret must NEVER be logged.
//
//   - Returns (secret, true, nil)  for an active key.
//   - Returns ("", false, nil)     when the key does not exist (treated as inactive).
//   - Returns ("", false, err)     on lookup or decryption errors.
//
// Per security-model.md sections 4.2 and 4.3.
type SecretProvider func(accessKeyID string) (secret string, isActive bool, err error)

// Verifier holds the configuration for SigV4 Authorization header verification.
// Construct by setting fields directly; all fields are required.
type Verifier struct {
	// Region is the configured S3 region (cfg.S3.Region).
	// Per s3-compatibility-matrix.md section 2.2: single region; mismatch is rejected.
	Region string
	// Service is the AWS service name in the credential scope, always "s3" for S3 API.
	Service string
	// GetSecret retrieves the plaintext secret for an access key ID.
	GetSecret SecretProvider
}

// Verify verifies the SigV4 Authorization header on r.
//
// Returns nil on success. On failure returns an error wrapping one of the sentinel
// errors in this package (ErrMalformedAuthorization, ErrWrongRegion, etc.).
//
// Per security-model.md section 8: callers should log signature failures as audit events.
// Per security-model.md section 4.3: this function never logs secret values.
func (v *Verifier) Verify(r *http.Request) error {
	// 1. Parse Authorization header.
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return fmt.Errorf("%w: Authorization header missing", ErrMalformedAuthorization)
	}
	parsed, err := ParseAuthorization(authHeader)
	if err != nil {
		return err
	}

	// 2. Validate region and service in credential scope.
	// Per s3-compatibility-matrix.md section 2.2: single region only; mismatch is hard failure.
	if parsed.Region != v.Region {
		return fmt.Errorf("%w: got %q, want %q", ErrWrongRegion, parsed.Region, v.Region)
	}
	if parsed.Service != v.Service {
		return fmt.Errorf("%w: got %q, want %q", ErrWrongService, parsed.Service, v.Service)
	}

	// 3. Parse and validate x-amz-date.
	amzDate := r.Header.Get("X-Amz-Date")
	if amzDate == "" {
		return ErrMissingDateHeader
	}
	t, err := time.Parse(sigV4DateTimeFormat, amzDate)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMalformedDate, err)
	}
	// The date in the credential scope must match the date in x-amz-date.
	if dateStr := t.UTC().Format(sigV4DateFormat); dateStr != parsed.Date {
		return fmt.Errorf("%w: Authorization date %q does not match x-amz-date date %q",
			ErrMalformedCredential, parsed.Date, dateStr)
	}

	// 4. Validate X-Amz-Content-Sha256 payload hash.
	// Per s3-compatibility-matrix.md section 5.1: the header is part of the signing
	// contract for header-based SigV4 and must be present. Silent fallback to empty-body
	// hash would allow a request signed with an actual body hash to be accepted with any
	// body, breaking the integrity guarantee.
	payloadHash := r.Header.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		return ErrMissingPayloadHash
	}
	if payloadHash == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" {
		// Per s3-compatibility-matrix.md section 5.1: not supported in MVP.
		return fmt.Errorf("%w: STREAMING-AWS4-HMAC-SHA256-PAYLOAD", ErrUnsupportedPayload)
	}
	// UNSIGNED-PAYLOAD and actual SHA-256 hex hashes are both valid values.

	// 5. Build canonical request from actual request data.
	canonHdrs, signedHdrsStr, err := CanonicalHeaders(r, parsed.SignedHeaders)
	if err != nil {
		return err
	}
	canonURI := CanonicalURI(requestRawPath(r))
	canonQuery := CanonicalQueryString(r.URL.Query())
	canonReq := CanonicalRequest(r.Method, canonURI, canonQuery, canonHdrs, signedHdrsStr, payloadHash)

	// 6. Build string-to-sign.
	scope := CredentialScope(parsed.Date, v.Region, v.Service)
	sts := StringToSign(amzDate, scope, HashSHA256Hex([]byte(canonReq)))

	// 7. Look up plaintext secret. Secret must NOT be logged — per security-model.md 4.3.
	secret, isActive, err := v.GetSecret(parsed.AccessKeyID)
	if err != nil {
		return fmt.Errorf("looking up access key: %w", err)
	}
	if !isActive {
		return fmt.Errorf("%w: %q", ErrInactiveKey, parsed.AccessKeyID)
	}

	// 8. Derive signing key and compute expected signature.
	signingKey := DeriveSigningKey(secret, parsed.Date, v.Region, v.Service)
	expectedSig := ComputeSignature(signingKey, sts)

	// 9. Constant-time comparison to prevent timing side-channel attacks.
	if subtle.ConstantTimeCompare([]byte(expectedSig), []byte(parsed.Signature)) != 1 {
		return ErrSignatureMismatch
	}
	return nil
}

// requestRawPath returns the raw (percent-encoded) request path for use in
// canonical URI construction. Go's r.URL.Path is decoded, which would cause
// double-encoding of already-percent-encoded sequences (e.g. %20 → %2520) and
// would silently misparse %2F as a path separator instead of a literal character.
//
// Preference order:
//  1. r.URL.RawPath — set by the Go HTTP server when Path != RawPath (i.e. when
//     there are percent-encoded characters that change after decoding).
//  2. r.URL.EscapedPath() — returns RawPath when it is a valid encoding of Path,
//     otherwise re-encodes Path. Covers the common case where RawPath is empty.
func requestRawPath(r *http.Request) string {
	if r.URL.RawPath != "" {
		return r.URL.RawPath
	}
	return r.URL.EscapedPath()
}
