package update

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

func TestReplacerReplaceInstallsExecutable(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "mailcheck")
	if err := os.WriteFile(executable, []byte("old"), 0o700); err != nil {
		t.Fatalf("WriteFile(old executable) error = %v", err)
	}

	err := NewReplacer().Replace(executable, []byte("new"))
	if err != nil {
		t.Fatalf("Replace() error = %v", err)
	}

	got, err := os.ReadFile(executable)
	if err != nil {
		t.Fatalf("ReadFile(executable) error = %v", err)
	}
	if string(got) != "new" {
		t.Fatalf("executable = %q, want new", got)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(executable)
		if err != nil {
			t.Fatalf("Stat(executable) error = %v", err)
		}
		if got := info.Mode().Perm(); got != 0o755 {
			t.Fatalf("executable permissions = %o, want 755", got)
		}
	}
	assertNoReplacementFiles(t, directory)
}

func TestReplacerReplaceRestoresOriginalWhenInstallFails(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "mailcheck")
	if err := os.WriteFile(executable, []byte("old"), 0o755); err != nil {
		t.Fatalf("WriteFile(old executable) error = %v", err)
	}

	installErr := errors.New("injected install failure")
	calls := 0
	replacer := NewReplacer()
	replacer.Rename = func(old, new string) error {
		calls++
		if calls == 2 {
			return installErr
		}
		return os.Rename(old, new)
	}

	err := replacer.Replace(executable, []byte("new"))
	if err == nil {
		t.Fatal("Replace() error = nil")
	}
	if !errors.Is(err, installErr) {
		t.Fatalf("Replace() error = %v, want install error", err)
	}

	got, err := os.ReadFile(executable)
	if err != nil {
		t.Fatalf("ReadFile(executable) error = %v", err)
	}
	if string(got) != "old" {
		t.Fatalf("executable = %q, want old", got)
	}
	assertNoReplacementFiles(t, directory)
}

func TestReplacerReplaceRetainsBackupWhenRollbackFails(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "mailcheck")
	if err := os.WriteFile(executable, []byte("old"), 0o755); err != nil {
		t.Fatalf("WriteFile(old executable) error = %v", err)
	}

	installErr := errors.New("injected install failure")
	rollbackErr := errors.New("injected rollback failure")
	calls := 0
	replacer := NewReplacer()
	replacer.Rename = func(old, new string) error {
		calls++
		switch calls {
		case 2:
			return installErr
		case 3:
			return rollbackErr
		default:
			return os.Rename(old, new)
		}
	}

	err := replacer.Replace(executable, []byte("new"))
	if !errors.Is(err, installErr) {
		t.Fatalf("Replace() error = %v, want install error", err)
	}
	if !errors.Is(err, rollbackErr) {
		t.Fatalf("Replace() error = %v, want rollback error", err)
	}

	backups := replacementBackupFiles(t, directory)
	if len(backups) != 1 {
		t.Fatalf("backup files = %v, want one", backups)
	}
	got, err := os.ReadFile(backups[0])
	if err != nil {
		t.Fatalf("ReadFile(backup) error = %v", err)
	}
	if string(got) != "old" {
		t.Fatalf("backup = %q, want old", got)
	}
}

func TestReplacerReplaceReturnsNonWindowsBackupRemovalFailure(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "mailcheck")
	if err := os.WriteFile(executable, []byte("old"), 0o755); err != nil {
		t.Fatalf("WriteFile(old executable) error = %v", err)
	}

	removeErr := errors.New("injected backup removal failure")
	calls := 0
	replacer := NewReplacer()
	replacer.GOOS = "linux"
	replacer.Remove = func(path string) error {
		calls++
		if calls == 2 {
			return removeErr
		}
		return os.Remove(path)
	}

	err := replacer.Replace(executable, []byte("new"))
	if !errors.Is(err, removeErr) {
		t.Fatalf("Replace() error = %v, want backup removal error", err)
	}
}

func TestReplacerReplaceDefersWindowsSharingViolation(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "mailcheck")
	if err := os.WriteFile(executable, []byte("old"), 0o755); err != nil {
		t.Fatalf("WriteFile(old executable) error = %v", err)
	}

	calls := 0
	replacer := NewReplacer()
	replacer.GOOS = "windows"
	replacer.Remove = func(path string) error {
		calls++
		if calls == 2 {
			return &os.PathError{Op: "remove", Path: path, Err: syscall.Errno(32)}
		}
		return os.Remove(path)
	}

	if err := replacer.Replace(executable, []byte("new")); err != nil {
		t.Fatalf("Replace() error = %v", err)
	}
	backups := replacementBackupFiles(t, directory)
	if len(backups) != 1 {
		t.Fatalf("backup files = %v, want one deferred backup", backups)
	}
}

func TestReplacerReplaceReturnsUnrelatedWindowsBackupRemovalFailure(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "mailcheck")
	if err := os.WriteFile(executable, []byte("old"), 0o755); err != nil {
		t.Fatalf("WriteFile(old executable) error = %v", err)
	}

	removeErr := os.ErrPermission
	calls := 0
	replacer := NewReplacer()
	replacer.GOOS = "windows"
	replacer.Remove = func(path string) error {
		calls++
		if calls == 2 {
			return removeErr
		}
		return os.Remove(path)
	}

	err := replacer.Replace(executable, []byte("new"))
	if !errors.Is(err, removeErr) {
		t.Fatalf("Replace() error = %v, want backup removal error", err)
	}
}

func assertNoReplacementFiles(t *testing.T, directory string) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(directory, ".mailcheck-upgrade-*"))
	if err != nil {
		t.Fatalf("Glob(replacement files) error = %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("replacement files remain: %v", files)
	}
}

func replacementBackupFiles(t *testing.T, directory string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(directory, ".mailcheck-upgrade-backup-*"))
	if err != nil {
		t.Fatalf("Glob(backup files) error = %v", err)
	}
	return files
}
