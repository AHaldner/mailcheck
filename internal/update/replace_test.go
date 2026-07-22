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

func TestReplacerReplaceFromReaderFailurePreservesOriginalAndCleansStage(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "mailcheck")
	if err := os.WriteFile(executable, []byte("old"), 0o700); err != nil {
		t.Fatalf("WriteFile(old executable) error = %v", err)
	}

	readErr := errors.New("injected source read failure")
	err := NewReplacer().ReplaceFrom(executable, &partialErrorReader{data: []byte("partial"), err: readErr})
	if !errors.Is(err, readErr) {
		t.Fatalf("ReplaceFrom() error = %v, want source read error", err)
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

func TestReplacerReplaceRecoversBackupAfterRollbackFailureOnNextCall(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "mailcheck")
	if err := os.WriteFile(executable, []byte("old"), 0o755); err != nil {
		t.Fatalf("WriteFile(old executable) error = %v", err)
	}

	calls := 0
	first := NewReplacer()
	first.Rename = func(old, new string) error {
		calls++
		if calls == 2 {
			return errors.New("injected install failure")
		}
		if calls == 3 {
			return errors.New("injected rollback failure")
		}
		return os.Rename(old, new)
	}
	if err := first.Replace(executable, []byte("new")); err == nil {
		t.Fatal("first Replace() error = nil, want install and rollback failure")
	}
	if _, err := os.Stat(executable); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("executable stat error = %v, want not exist after rollback failure", err)
	}

	if err := NewReplacer().Replace(executable, []byte("newer")); err != nil {
		t.Fatalf("second Replace() error = %v", err)
	}
	got, err := os.ReadFile(executable)
	if err != nil {
		t.Fatalf("ReadFile(executable) error = %v", err)
	}
	if string(got) != "newer" {
		t.Fatalf("executable = %q, want newer", got)
	}
	assertNoReplacementFiles(t, directory)
}

func TestReplacerReplaceSerializesOverlappingCalls(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "mailcheck")
	if err := os.WriteFile(executable, []byte("old"), 0o755); err != nil {
		t.Fatalf("WriteFile(old executable) error = %v", err)
	}

	installStarted := make(chan struct{})
	releaseInstall := make(chan struct{})
	renameCalls := 0
	first := NewReplacer()
	first.Rename = func(old, new string) error {
		renameCalls++
		if renameCalls == 2 {
			close(installStarted)
			<-releaseInstall
		}
		return os.Rename(old, new)
	}
	firstResult := make(chan error, 1)
	go func() {
		firstResult <- first.Replace(executable, []byte("first"))
	}()
	<-installStarted

	secondErr := NewReplacer().Replace(executable, []byte("second"))
	requireErrorContains(t, secondErr, "replacement already in progress")
	close(releaseInstall)
	if err := <-firstResult; err != nil {
		t.Fatalf("first Replace() error = %v", err)
	}

	got, err := os.ReadFile(executable)
	if err != nil {
		t.Fatalf("ReadFile(executable) error = %v", err)
	}
	if string(got) != "first" {
		t.Fatalf("executable = %q, want first", got)
	}
	assertNoReplacementFiles(t, directory)
}

func TestReplacerReplaceReturnsNonWindowsBackupRemovalFailure(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "mailcheck")
	if err := os.WriteFile(executable, []byte("old"), 0o755); err != nil {
		t.Fatalf("WriteFile(old executable) error = %v", err)
	}

	removeErr := errors.New("injected backup removal failure")
	backupPath := replacementBackupPath(executable)
	replacer := NewReplacer()
	replacer.GOOS = "linux"
	replacer.Remove = func(path string) error {
		if path == backupPath {
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

	backupPath := replacementBackupPath(executable)
	replacer := NewReplacer()
	replacer.GOOS = "windows"
	replacer.Remove = func(path string) error {
		if path == backupPath {
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

func TestReplacementBackupPathIsDeterministic(t *testing.T) {
	executable := filepath.Join("root", "bin", "mailcheck.exe")
	want := filepath.Join("root", "bin", ".mailcheck-upgrade-backup-mailcheck.exe")

	if got := replacementBackupPath(executable); got != want {
		t.Fatalf("replacementBackupPath() = %q, want %q", got, want)
	}
	if got := replacementBackupPath(executable); got != want {
		t.Fatalf("second replacementBackupPath() = %q, want %q", got, want)
	}
}

func TestReplacerReplaceCleansDeferredWindowsBackupOnNextCall(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "mailcheck.exe")
	if err := os.WriteFile(executable, []byte("old"), 0o755); err != nil {
		t.Fatalf("WriteFile(old executable) error = %v", err)
	}
	backupPath := filepath.Join(directory, ".mailcheck-upgrade-backup-mailcheck.exe")

	deferred := false
	replacer := NewReplacer()
	replacer.GOOS = "windows"
	replacer.Remove = func(path string) error {
		if path == backupPath {
			if _, err := os.Stat(path); err == nil && !deferred {
				deferred = true
				return &os.PathError{Op: "remove", Path: path, Err: syscall.Errno(32)}
			}
		}
		return os.Remove(path)
	}

	if err := replacer.Replace(executable, []byte("new")); err != nil {
		t.Fatalf("first Replace() error = %v", err)
	}
	if !deferred {
		t.Fatal("first Replace() did not defer the sharing-locked backup")
	}
	if got, err := os.ReadFile(backupPath); err != nil || string(got) != "old" {
		t.Fatalf("deferred backup = %q, %v; want old", got, err)
	}

	replacer.Remove = os.Remove
	if err := replacer.Replace(executable, []byte("newer")); err != nil {
		t.Fatalf("second Replace() error = %v", err)
	}
	if _, err := os.Stat(backupPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale backup stat error = %v, want not exist", err)
	}
	if got, err := os.ReadFile(executable); err != nil || string(got) != "newer" {
		t.Fatalf("executable = %q, %v; want newer", got, err)
	}
}

func TestReplacerReplaceReturnsUnrelatedStaleBackupCleanupFailure(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "mailcheck")
	backupPath := filepath.Join(directory, ".mailcheck-upgrade-backup-mailcheck")
	if err := os.WriteFile(executable, []byte("old"), 0o755); err != nil {
		t.Fatalf("WriteFile(old executable) error = %v", err)
	}
	if err := os.WriteFile(backupPath, []byte("stale"), 0o755); err != nil {
		t.Fatalf("WriteFile(stale backup) error = %v", err)
	}

	removeErr := os.ErrPermission
	replacer := NewReplacer()
	replacer.Remove = func(path string) error {
		if path == backupPath {
			return removeErr
		}
		return os.Remove(path)
	}

	err := replacer.Replace(executable, []byte("new"))
	if !errors.Is(err, removeErr) {
		t.Fatalf("Replace() error = %v, want stale backup cleanup error", err)
	}
	if got, readErr := os.ReadFile(executable); readErr != nil || string(got) != "old" {
		t.Fatalf("executable = %q, %v; want old", got, readErr)
	}
	if got, readErr := os.ReadFile(backupPath); readErr != nil || string(got) != "stale" {
		t.Fatalf("stale backup = %q, %v; want stale", got, readErr)
	}
}

func TestReplacerReplaceReturnsUnrelatedWindowsBackupRemovalFailure(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "mailcheck")
	if err := os.WriteFile(executable, []byte("old"), 0o755); err != nil {
		t.Fatalf("WriteFile(old executable) error = %v", err)
	}

	removeErr := os.ErrPermission
	backupPath := replacementBackupPath(executable)
	replacer := NewReplacer()
	replacer.GOOS = "windows"
	replacer.Remove = func(path string) error {
		if path == backupPath {
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

type partialErrorReader struct {
	data []byte
	err  error
}

func (r *partialErrorReader) Read(destination []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	written := copy(destination, r.data)
	r.data = r.data[written:]
	return written, nil
}
