package s3

import (
	"encoding/xml"
	"net/http"
)

// ErrorResponse is the S3-compatible XML error envelope.
// Per s3-compatibility-matrix.md section 9.1 and AWS S3 API reference.
type ErrorResponse struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	Resource  string   `xml:"Resource"`
	RequestID string   `xml:"RequestId"`
}

// writeError writes an S3-compatible XML error response with the given HTTP status,
// S3 error code, and human-readable message.
// Per product-spec.md section 5.5: unsupported or failed operations must return
// S3 XML errors, never silent 200s or plain-text errors.
func writeError(w http.ResponseWriter, r *http.Request, statusCode int, code, message string) {
	body, err := xml.Marshal(&ErrorResponse{
		Code:      code,
		Message:   message,
		Resource:  r.URL.Path,
		RequestID: "0000000000000001",
	})
	if err != nil {
		http.Error(w, "internal error marshaling error response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(statusCode)
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(body)
}
