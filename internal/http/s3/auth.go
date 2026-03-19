package s3

import (
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/lukehemmin/hemmins-s3-api/internal/auth"
	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

// ErrMultipleAuthMechanisms is returned when a request simultaneously carries both
// an Authorization header (header-based SigV4) and X-Amz-Algorithm query parameter
// (presigned URL SigV4). Accepting either silently would be overly permissive;
// only one authentication mechanism may be used per request.
// Per s3-compatibility-matrix.md section 9.2: ambiguous requests return InvalidRequest.
var ErrMultipleAuthMechanisms = errors.New(
	"both Authorization header and presigned query parameters provided; " +
		"only one authentication mechanism may be used",
)

// recordLastUsed updates last_used_at for accessKeyID after a successful authentication.
//
// Policy (per security-model.md section 5.1 and this codebase's availability contract):
//   - Called only on successful authentication — never on failure.
//   - If the DB UPDATE fails, a warning is logged but the request is NOT aborted.
//     Rationale: usage tracking is an operational/audit feature. The signature has
//     already been cryptographically verified; failing the entire authenticated request
//     because of a metadata write error would harm availability for no security gain.
//   - The access key ID (public part of the credential) is safe to include in logs.
//     The secret key is never passed here and must NEVER be logged.
func recordLastUsed(db *metadata.DB, accessKeyID string) {
	if err := db.TouchAccessKeyLastUsed(accessKeyID); err != nil {
		log.Printf("warn: failed to update last_used_at for access key %q: %v", accessKeyID, err)
	}
}

// makeSecretProvider returns an auth.SecretProvider backed by the metadata DB.
// Secrets are stored AES-256-GCM encrypted; this function decrypts on lookup.
// Per security-model.md sections 4.2 and 4.3: plaintext secret must NEVER be logged.
func makeSecretProvider(db *metadata.DB, masterKey string) auth.SecretProvider {
	return func(accessKeyID string) (string, bool, error) {
		rec, err := db.LookupAccessKey(accessKeyID)
		if errors.Is(err, metadata.ErrAccessKeyNotFound) {
			return "", false, nil
		}
		if err != nil {
			return "", false, fmt.Errorf("looking up access key: %w", err)
		}
		if rec.Status != "active" {
			return "", false, nil
		}
		plaintext, err := auth.DecryptSecret(masterKey, rec.SecretCiphertext)
		if err != nil {
			return "", false, fmt.Errorf("decrypting secret: %w", err)
		}
		return plaintext, true, nil
	}
}

// authenticate verifies SigV4 authentication on r (header-based or presigned).
// Exactly one authentication mechanism must be present per request.
// If both Authorization header and X-Amz-Algorithm query parameter are present
// simultaneously, the request is rejected with InvalidRequest.
// On success, records last_used_at via recordLastUsed and returns the access key ID and true.
// On failure, writes an S3 XML error and returns "", false.
// Per security-model.md 4.3: auth failures are logged as audit events without secrets.
func authenticate(
	w http.ResponseWriter,
	r *http.Request,
	v *auth.Verifier,
	pv *auth.PresignVerifier,
	db *metadata.DB,
) (accessKeyID string, ok bool) {
	q := r.URL.Query()

	hasPresign := q.Has("X-Amz-Algorithm")
	hasHeader := r.Header.Get("Authorization") != ""

	// Reject ambiguous requests carrying both auth mechanisms simultaneously.
	// Silently preferring one mechanism over the other would be overly permissive
	// and could mask client mis-configuration.
	if hasPresign && hasHeader {
		writeError(w, r, http.StatusForbidden, "InvalidRequest", ErrMultipleAuthMechanisms.Error())
		return "", false
	}

	if hasPresign {
		// Presigned URL flow.
		if err := pv.Verify(r); err != nil {
			code, msg := authErrToS3(err)
			writeError(w, r, http.StatusForbidden, code, msg)
			return "", false
		}
		parsed, err := auth.ParsePresignQuery(q)
		if err != nil {
			writeError(w, r, http.StatusForbidden, "InvalidRequest", err.Error())
			return "", false
		}
		recordLastUsed(db, parsed.AccessKeyID)
		return parsed.AccessKeyID, true
	}

	if hasHeader {
		// Header-based SigV4 flow.
		if err := v.Verify(r); err != nil {
			code, msg := authErrToS3(err)
			writeError(w, r, http.StatusForbidden, code, msg)
			return "", false
		}
		parsed, err := auth.ParseAuthorization(r.Header.Get("Authorization"))
		if err != nil {
			writeError(w, r, http.StatusForbidden, "InvalidRequest", err.Error())
			return "", false
		}
		recordLastUsed(db, parsed.AccessKeyID)
		return parsed.AccessKeyID, true
	}

	writeError(w, r, http.StatusForbidden, "AccessDenied", "No authentication provided.")
	return "", false
}

// authErrToS3 maps auth sentinel errors to S3 error code + message pairs.
// Unrecognized errors fall through to a generic AccessDenied.
func authErrToS3(err error) (code, message string) {
	switch {
	case errors.Is(err, auth.ErrSignatureMismatch):
		return "SignatureDoesNotMatch",
			"The request signature we calculated does not match the signature you provided."
	case errors.Is(err, auth.ErrInactiveKey):
		return "InvalidAccessKeyId",
			"The access key ID you provided does not exist in our records."
	case errors.Is(err, auth.ErrMalformedAuthorization),
		errors.Is(err, auth.ErrMalformedCredential),
		errors.Is(err, auth.ErrMissingDateHeader),
		errors.Is(err, auth.ErrMalformedDate),
		errors.Is(err, auth.ErrMissingPayloadHash),
		errors.Is(err, auth.ErrMissingSignedHeader):
		return "InvalidRequest", err.Error()
	case errors.Is(err, auth.ErrWrongRegion), errors.Is(err, auth.ErrWrongService):
		return "AuthorizationHeaderMalformed", err.Error()
	case errors.Is(err, auth.ErrExpiredPresignURL):
		return "AccessDenied", "Request has expired."
	case errors.Is(err, auth.ErrPresignNotYetValid):
		return "AccessDenied", "Request is not yet valid."
	case errors.Is(err, auth.ErrHostNotSigned):
		return "InvalidRequest", err.Error()
	case errors.Is(err, ErrMultipleAuthMechanisms):
		return "InvalidRequest", err.Error()
	default:
		return "AccessDenied", "Access denied."
	}
}
