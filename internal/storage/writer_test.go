package storage

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAtomicWrite_Basic(t *testing.T) {
	dir := t.TempDir()
	tempRoot := filepath.Join(dir, "tmp")
	destRoot := filepath.Join(dir, "objects")
	if err := os.MkdirAll(tempRoot, 0750); err != nil {
		t.Fatal(err)
	}

	destPath := filepath.Join(destRoot, "ab", "cd", "abcdef.blob")
	data := []byte("hello world content")

	result, err := AtomicWrite(context.Background(), tempRoot, destPath, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("AtomicWrite: %v", err)
	}
	if result.Size != int64(len(data)) {
		t.Errorf("size: got %d, want %d", result.Size, len(data))
	}

	got, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("reading dest file: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("content mismatch: got %q, want %q", got, data)
	}
}

func TestAtomicWrite_NoTempFileRemainsOnSuccess(t *testing.T) {
	dir := t.TempDir()
	tempRoot := filepath.Join(dir, "tmp")
	if err := os.MkdirAll(tempRoot, 0750); err != nil {
		t.Fatal(err)
	}
	destPath := filepath.Join(dir, "objects", "final.blob")

	_, err := AtomicWrite(context.Background(), tempRoot, destPath, strings.NewReader("data"))
	if err != nil {
		t.Fatalf("AtomicWrite: %v", err)
	}

	entries, err := os.ReadDir(tempRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".hemmins-upload-") {
			t.Errorf("stale temp file remains: %s", e.Name())
		}
	}
}

func TestAtomicWrite_CancelledContext(t *testing.T) {
	dir := t.TempDir()
	tempRoot := filepath.Join(dir, "tmp")
	if err := os.MkdirAll(tempRoot, 0750); err != nil {
		t.Fatal(err)
	}
	destPath := filepath.Join(dir, "objects", "final.blob")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := AtomicWrite(ctx, tempRoot, destPath, strings.NewReader("data"))
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}

	if _, statErr := os.Stat(destPath); !os.IsNotExist(statErr) {
		t.Error("dest file should not exist after cancelled write")
	}

	entries, _ := os.ReadDir(tempRoot)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".hemmins-upload-") {
			t.Errorf("temp file not cleaned up on cancel: %s", e.Name())
		}
	}
}

func TestAtomicWrite_CreatesDestDir(t *testing.T) {
	dir := t.TempDir()
	tempRoot := filepath.Join(dir, "tmp")
	if err := os.MkdirAll(tempRoot, 0750); err != nil {
		t.Fatal(err)
	}

	destPath := filepath.Join(dir, "new", "nested", "dir", "file.blob")
	_, err := AtomicWrite(context.Background(), tempRoot, destPath, strings.NewReader("x"))
	if err != nil {
		t.Fatalf("AtomicWrite with nested dest: %v", err)
	}

	if _, err := os.Stat(destPath); err != nil {
		t.Errorf("dest file not found: %v", err)
	}
}

func TestStoragePath_Sharding(t *testing.T) {
	cases := []struct {
		objectID string
		wantSufx string
	}{
		{"abcdef1234", "ab/cd/abcdef1234.blob"},
		{"ab", "ab.blob"},
		{"abc", "abc.blob"},
	}
	for _, tc := range cases {
		got := StoragePath("/data/objects", tc.objectID)
		if !strings.HasSuffix(got, tc.wantSufx) {
			t.Errorf("StoragePath(%q): got %q, want suffix %q", tc.objectID, got, tc.wantSufx)
		}
	}
}
