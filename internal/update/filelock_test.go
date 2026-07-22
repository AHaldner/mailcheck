package update

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFileLockContendsAcrossDescriptors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "update.lock")
	first, err := acquireFileLock(path)
	if err != nil {
		t.Fatalf("acquireFileLock(first) error = %v", err)
	}
	t.Cleanup(func() { _ = first.release() })

	second, err := acquireFileLock(path)
	if !errors.Is(err, ErrLockContended) {
		if second != nil {
			_ = second.release()
		}
		t.Fatalf("acquireFileLock(second) error = %v, want ErrLockContended", err)
	}
}

func TestFileLockReleaseKeepsFileAndAllowsSuccessor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "update.lock")
	first, err := acquireFileLock(path)
	if err != nil {
		t.Fatalf("acquireFileLock(first) error = %v", err)
	}
	if err := first.release(); err != nil {
		t.Fatalf("release(first) error = %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("Stat(lock file) error = %v, want persistent lock file", err)
	}

	second, err := acquireFileLock(path)
	if err != nil {
		t.Fatalf("acquireFileLock(successor) error = %v", err)
	}
	if err := second.release(); err != nil {
		t.Fatalf("release(successor) error = %v", err)
	}
}

func TestFileLockDescriptorCloseAllowsSuccessor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "update.lock")
	first, err := acquireFileLock(path)
	if err != nil {
		t.Fatalf("acquireFileLock(first) error = %v", err)
	}
	if err := first.file.Close(); err != nil {
		t.Fatalf("Close(owner descriptor) error = %v", err)
	}

	second, err := acquireFileLock(path)
	if err != nil {
		t.Fatalf("acquireFileLock(successor) error = %v after owner descriptor close", err)
	}
	if err := second.release(); err != nil {
		t.Fatalf("release(successor) error = %v", err)
	}
}
