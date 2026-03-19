//go:build !windows

package config

import "syscall"

// sameFilesystem reports whether two paths reside on the same filesystem
// by comparing their device IDs via stat(2).
// Both paths must exist before calling this function.
func sameFilesystem(path1, path2 string) (bool, error) {
	var st1, st2 syscall.Stat_t
	if err := syscall.Stat(path1, &st1); err != nil {
		return false, err
	}
	if err := syscall.Stat(path2, &st2); err != nil {
		return false, err
	}
	return st1.Dev == st2.Dev, nil
}
