//go:build unix

// Package ui implements the management UI session API.
// This file provides Unix-specific filesystem statistics.
// Per product-spec.md section 7.4: disk usage and free space for settings screen.
package ui

import (
	"syscall"
)

// getDiskStats returns filesystem capacity information for the given path.
// On Unix, this uses statfs(2) to get block-level statistics.
// Returns zero-valued diskStats if the path is inaccessible (syscall error is not exposed).
func getDiskStats(path string) diskStats {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		// Path does not exist or is not accessible.
		// Return zero values instead of exposing raw syscall errors.
		return diskStats{}
	}

	// Bsize is the fundamental block size.
	// Blocks is the total data blocks in the filesystem.
	// Bavail is free blocks available to unprivileged users.
	// Bfree is total free blocks (includes reserved for root).
	// We use Bavail for freeBytes to reflect what the application can actually use.
	totalBytes := uint64(stat.Bsize) * stat.Blocks
	freeBytes := uint64(stat.Bsize) * stat.Bavail
	usedBytes := totalBytes - freeBytes

	return diskStats{
		TotalBytes: totalBytes,
		FreeBytes:  freeBytes,
		UsedBytes:  usedBytes,
	}
}
