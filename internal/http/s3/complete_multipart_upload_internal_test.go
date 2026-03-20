// Package s3 internal tests for sequentialFileReader.
// Uses package s3 (not s3_test) so that unexported types are accessible.
package s3

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestSequentialFileReader_ReadsPartsSequentially verifies that
// sequentialFileReader concatenates the content of all files in order.
func TestSequentialFileReader_ReadsPartsSequentially(t *testing.T) {
	dir := t.TempDir()
	contents := []string{"hello", " world", " foo"}
	paths := make([]string, len(contents))
	expected := ""
	for i, c := range contents {
		p := filepath.Join(dir, fmt.Sprintf("part-%d", i))
		if err := os.WriteFile(p, []byte(c), 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		paths[i] = p
		expected += c
	}

	sr := newSequentialFileReader(paths)
	defer sr.Close()

	got, err := io.ReadAll(sr)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != expected {
		t.Errorf("got %q, want %q", string(got), expected)
	}

	// Subsequent Read after EOF must return io.EOF immediately.
	n, err2 := sr.Read(make([]byte, 4))
	if n != 0 || err2 != io.EOF {
		t.Errorf("Read after EOF: n=%d err=%v; want n=0 err=io.EOF", n, err2)
	}
}

// TestSequentialFileReader_EmptyPaths verifies that an empty paths list
// returns io.EOF on the first Read call.
func TestSequentialFileReader_EmptyPaths(t *testing.T) {
	sr := newSequentialFileReader(nil)
	defer sr.Close()

	n, err := sr.Read(make([]byte, 8))
	if n != 0 || err != io.EOF {
		t.Errorf("Read on empty paths: n=%d err=%v; want n=0 err=io.EOF", n, err)
	}
}

// TestSequentialFileReader_CloseIsIdempotent verifies that calling Close
// more than once does not panic or return an error.
func TestSequentialFileReader_CloseIsIdempotent(t *testing.T) {
	sr := newSequentialFileReader(nil)
	if err := sr.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := sr.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}
