package metadata

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// RecoveryConfig holds the paths and policy parameters needed for startup recovery.
type RecoveryConfig struct {
	TempRoot      string
	ObjectRoot    string
	MultipartRoot string
	// OrphanGracePeriod is the minimum age a temp file must have before it is
	// removed during startup recovery. This corresponds to gc.orphan_grace_period
	// in the configuration. A zero value removes all matching temp files regardless
	// of age (conservative startup-only mode).
	// Per operations-runbook.md section 4.1: temp files are orphan candidates
	// after the grace period.
	OrphanGracePeriod time.Duration
}

// StartupRecovery performs startup consistency checks and cleanup.
// Must be called after the database is opened and before marking the server ready.
// Per operations-runbook.md section 4.2.
//
// What this function handles:
//   - Stale upload temp files (pre-rename, interrupted uploads): files older than
//     RecoveryConfig.OrphanGracePeriod are removed. Files newer than the grace
//     period are logged but preserved. Per operations-runbook.md section 4.1:
//     "temp_root files → move to orphan candidate after grace period."
//   - SQLite integrity check: failure returns a fatal error, preventing the server
//     from marking itself ready. Per operations-runbook.md section 5.2.
//   - DB rows with missing blob (metadata without file): marked as corrupt (is_corrupt=1).
//     Per operations-runbook.md section 5.1 and system-architecture.md section 6.3.
//   - SQLite WAL leftovers: handled automatically by SQLite on Open.
//
// What is deferred to the periodic GC phase (not yet implemented):
//   - Orphan blobs (file on disk but no DB row): requires full filesystem scan,
//     deferred to the GC scanner running at gc.orphan_scan_interval.
//   - Expired multipart uploads: deferred to GC (gc.multipart_expiry).
//   - Quarantine/lost+found for blob-only orphans per operations-runbook.md section 4.2.
func StartupRecovery(db *DB, cfg RecoveryConfig) error {
	// Step 1: Remove stale temp files from interrupted uploads.
	// Per operations-runbook.md section 4.1.
	if err := cleanTempRoot(cfg.TempRoot, cfg.OrphanGracePeriod); err != nil {
		log.Printf("warning: startup: temp root cleanup failed: %v", err)
	}

	// Step 2: SQLite integrity check.
	// Per operations-runbook.md section 5.2 and system-architecture.md section 6.3.
	if err := db.IntegrityCheck(context.Background()); err != nil {
		return fmt.Errorf("startup: database integrity check failed: %w", err)
	}

	// Step 3: Scan for objects whose blob file is missing and mark them corrupt.
	// Per operations-runbook.md section 5.1.
	if err := markMissingBlobsCorrupt(db); err != nil {
		log.Printf("warning: startup: corrupt blob scan failed: %v", err)
	}

	return nil
}

// cleanTempRoot removes stale hemmins upload temp files from tempRoot.
// Only removes files matching known hemmins temp prefixes; never touches other files.
//
// gracePeriod controls which files are removed:
//   - gracePeriod == 0: all matching files are removed (server known to be stopped)
//   - gracePeriod > 0: only files older than gracePeriod are removed; newer files
//     are logged but preserved per operations-runbook.md section 4.1
func cleanTempRoot(tempRoot string, gracePeriod time.Duration) error {
	entries, err := os.ReadDir(tempRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading temp root %q: %w", tempRoot, err)
	}

	now := time.Now()
	var removed, skipped int
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, ".hemmins-upload-") && !strings.HasPrefix(name, ".hemmins-writecheck-") {
			continue
		}

		path := filepath.Join(tempRoot, name)
		info, err := e.Info()
		if err != nil {
			continue
		}
		age := now.Sub(info.ModTime())

		if gracePeriod > 0 && age < gracePeriod {
			skipped++
			log.Printf("startup: preserving recent temp file %q (age: %s, grace period: %s)",
				path, age.Round(time.Second), gracePeriod)
			continue
		}

		if err := os.Remove(path); err != nil {
			log.Printf("warning: startup: cannot remove stale temp file %q: %v", path, err)
		} else {
			removed++
			log.Printf("startup: removed stale temp file %q (age: %s)", path, age.Round(time.Second))
		}
	}

	if removed > 0 {
		log.Printf("startup: cleaned %d stale temp file(s) from %s", removed, tempRoot)
	}
	if skipped > 0 {
		log.Printf("startup: preserved %d recent temp file(s) in %s (within grace period %s)",
			skipped, tempRoot, gracePeriod)
	}
	return nil
}

// markMissingBlobsCorrupt finds all object rows whose storage_path file does not exist
// on disk and marks them with is_corrupt=1.
// Per system-architecture.md section 6.3.
func markMissingBlobsCorrupt(db *DB) error {
	rows, err := db.sqldb.Query(
		"SELECT id, storage_path FROM objects WHERE is_corrupt = 0",
	)
	if err != nil {
		return fmt.Errorf("querying objects: %w", err)
	}
	defer rows.Close()

	var corruptIDs []int64
	for rows.Next() {
		var id int64
		var path string
		if err := rows.Scan(&id, &path); err != nil {
			return fmt.Errorf("scanning object row: %w", err)
		}
		if _, err := os.Stat(path); os.IsNotExist(err) {
			corruptIDs = append(corruptIDs, id)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterating objects: %w", err)
	}

	if len(corruptIDs) == 0 {
		return nil
	}

	tx, err := db.sqldb.Begin()
	if err != nil {
		return fmt.Errorf("beginning corrupt-mark transaction: %w", err)
	}
	stmt, err := tx.Prepare("UPDATE objects SET is_corrupt = 1 WHERE id = ?")
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("preparing corrupt-mark statement: %w", err)
	}
	defer stmt.Close()

	for _, id := range corruptIDs {
		if _, err := stmt.Exec(id); err != nil {
			tx.Rollback()
			return fmt.Errorf("marking object %d corrupt: %w", id, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing corrupt-mark: %w", err)
	}

	log.Printf("startup: marked %d object(s) as corrupt (missing blob file)", len(corruptIDs))
	return nil
}
