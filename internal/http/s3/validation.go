package s3

import (
	"errors"
	"net"
	"strings"
)

// ErrInvalidBucketName is returned by ValidateBucketName when the name violates
// any of the S3 bucket naming rules.
// Per s3-compatibility-matrix.md section 2.3.
var ErrInvalidBucketName = errors.New("invalid bucket name")

// ValidateBucketName enforces S3 bucket naming rules.
// Rules per s3-compatibility-matrix.md section 2.3:
//   - Length 3–63
//   - Only lowercase letters (a–z), digits (0–9), hyphens (-), and dots (.)
//   - Must not start or end with - or .
//   - Must not contain ..
//   - Must not be formatted as an IP address (e.g. 192.168.1.1)
//
// Exported for use by the UI bucket create API to avoid duplicate validation logic.
func ValidateBucketName(name string) error {
	if len(name) < 3 || len(name) > 63 {
		return ErrInvalidBucketName
	}

	first, last := name[0], name[len(name)-1]
	if first == '-' || first == '.' || last == '-' || last == '.' {
		return ErrInvalidBucketName
	}

	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.') {
			return ErrInvalidBucketName
		}
	}

	if strings.Contains(name, "..") {
		return ErrInvalidBucketName
	}

	// IP address format check: reject names like "192.168.1.1".
	// net.ParseIP covers both IPv4 dotted-decimal and IPv6 formats.
	// Since bucket names may only contain a-z, 0-9, -, and ., only IPv4
	// dotted-decimal is practically reachable here.
	if net.ParseIP(name) != nil {
		return ErrInvalidBucketName
	}

	return nil
}
