package update

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
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

	calls := 0
	replacer := NewReplacer()
	replacer.Rename = func(old, new string) error {
		calls++
		if calls == 2 {
			return errors.New("injected install failure")
		}
		return os.Rename(old, new)
	}

	err := replacer.Replace(executable, []byte("new"))
	if err == nil {
		t.Fatal("Replace() error = nil")
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
