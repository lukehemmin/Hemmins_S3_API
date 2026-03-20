package metadata

import "fmt"

// DashboardStats holds the aggregate counts shown on the admin dashboard.
// All four values are computed in a single SQL query to minimise round-trips.
// Per product-spec.md section 7.2.
type DashboardStats struct {
	TotalBuckets           int   `json:"totalBuckets"`
	TotalObjects           int   `json:"totalObjects"`
	TotalBytes             int64 `json:"totalBytes"`
	ActiveMultipartUploads int   `json:"activeMultipartUploads"`
}

// GetDashboardStats returns aggregate storage statistics for the admin dashboard.
// Per product-spec.md section 7.2: total buckets, objects, bytes, and active multipart uploads.
func (db *DB) GetDashboardStats() (DashboardStats, error) {
	var stats DashboardStats
	err := db.sqldb.QueryRow(`
		SELECT
			(SELECT COUNT(*)               FROM buckets)            AS total_buckets,
			(SELECT COUNT(*)               FROM objects)            AS total_objects,
			(SELECT COALESCE(SUM(size), 0) FROM objects)            AS total_bytes,
			(SELECT COUNT(*)               FROM multipart_uploads)  AS active_multipart_uploads
	`).Scan(
		&stats.TotalBuckets,
		&stats.TotalObjects,
		&stats.TotalBytes,
		&stats.ActiveMultipartUploads,
	)
	if err != nil {
		return DashboardStats{}, fmt.Errorf("querying dashboard stats: %w", err)
	}
	return stats, nil
}
