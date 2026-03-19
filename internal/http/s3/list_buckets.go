package s3

import (
	"encoding/xml"
	"net/http"
)

// handleListBuckets implements GET Service (ListBuckets).
// Per s3-compatibility-matrix.md section 3 and product-spec.md section 5.1.
//
// Flow: authenticate → query metadata → marshal XML → respond 200.
// On any auth or internal failure the corresponding S3 XML error is returned.
func (s *Server) handleListBuckets(w http.ResponseWriter, r *http.Request) {
	_, ok := authenticate(w, r, s.verifier, s.pVerifier, s.db)
	if !ok {
		return
	}

	buckets, err := s.db.ListBuckets()
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"An internal error occurred retrieving the bucket list.")
		return
	}

	result := ListAllMyBucketsResult{
		Owner: s3Owner{
			ID:          "s3-owner",
			DisplayName: "s3-owner",
		},
	}
	for _, b := range buckets {
		result.Buckets.Bucket = append(result.Buckets.Bucket, s3Bucket{
			Name:         b.Name,
			CreationDate: b.CreatedAt.UTC().Format(s3TimeFormat),
		})
	}

	body, err := xml.Marshal(&result)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "InternalError",
			"An internal error occurred encoding the response.")
		return
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(body)
}
