package storage

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// WriteResult holds metadata about a successfully written object.
type WriteResult struct {
	Size int64
}

// AtomicWrite streams r to a temporary file in tempRoot, then atomically renames
// it to destPath. Returns the number of bytes written.
//
// Durability sequence per system-architecture.md section 6.1 and
// operations-runbook.md section 3.1:
//
//  1. Stream data to temp file in tempRoot
//  2. fsync(temp file)
//  3. rename(temp → destPath)
//  4. fsync(parent directory of destPath)
//
// The caller MUST commit the corresponding database record only after this
// function returns nil. This ordering ensures that a crash before DB commit
// leaves an orphan blob (recoverable), not a DB record without a blob.
func AtomicWrite(ctx context.Context, tempRoot, destPath string, r io.Reader) (WriteResult, error) {
	destDir := filepath.Dir(destPath)
	if err := os.MkdirAll(destDir, 0750); err != nil {
		return WriteResult{}, fmt.Errorf("creating destination directory %q: %w", destDir, err)
	}

	tmp, err := os.CreateTemp(tempRoot, ".hemmins-upload-*")
	if err != nil {
		return WriteResult{}, fmt.Errorf("creating temp file in %q: %w", tempRoot, err)
	}
	tmpPath := tmp.Name()

	committed := false
	defer func() {
		if !committed {
			tmp.Close()
			os.Remove(tmpPath)
		}
	}()

	size, err := copyWithContext(ctx, tmp, r)
	if err != nil {
		return WriteResult{}, fmt.Errorf("writing object data: %w", err)
	}

	if err := tmp.Sync(); err != nil {
		return WriteResult{}, fmt.Errorf("fsync temp file %q: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return WriteResult{}, fmt.Errorf("closing temp file %q: %w", tmpPath, err)
	}

	if err := os.Rename(tmpPath, destPath); err != nil {
		return WriteResult{}, fmt.Errorf("renaming %q to %q: %w", tmpPath, destPath, err)
	}

	if err := syncDir(destDir); err != nil {
		return WriteResult{}, fmt.Errorf("fsync destination directory %q: %w", destDir, err)
	}

	committed = true
	return WriteResult{Size: size}, nil
}

// StoragePath returns the blob file path for an object given the object root and object ID.
// Uses a two-level directory sharding scheme to avoid large flat directories.
// Per system-architecture.md section 3: objects/<ab>/<cd>/<objectID>.blob
func StoragePath(objectRoot, objectID string) string {
	if len(objectID) >= 4 {
		return filepath.Join(objectRoot, objectID[:2], objectID[2:4], objectID+".blob")
	}
	return filepath.Join(objectRoot, objectID+".blob")
}

// copyWithContext copies from src to dst in 32 KiB chunks, honouring context cancellation.
func copyWithContext(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, fmt.Errorf("upload cancelled: %w", err)
		}
		n, readErr := src.Read(buf)
		if n > 0 {
			written, writeErr := dst.Write(buf[:n])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return total, readErr
		}
	}
	return total, nil
}

// syncDir opens dir and calls Sync() to flush directory entries to disk.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
