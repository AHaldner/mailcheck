package update

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

// Replacer installs a verified executable while preserving the previous one
// until installation succeeds.
type Replacer struct {
	Rename func(string, string) error
	Remove func(string) error
	GOOS   string
}

// NewReplacer returns a Replacer backed by the operating system filesystem.
func NewReplacer() Replacer {
	return Replacer{
		Rename: os.Rename,
		Remove: os.Remove,
		GOOS:   runtime.GOOS,
	}
}

// Replace atomically installs binary at executablePath, restoring the original
// executable if installing the staged file fails.
func (r Replacer) Replace(executablePath string, binary []byte) (result error) {
	rename := r.Rename
	if rename == nil {
		rename = os.Rename
	}
	remove := r.Remove
	if remove == nil {
		remove = os.Remove
	}
	goos := r.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}

	directory := filepath.Dir(executablePath)
	stage, err := os.CreateTemp(directory, ".mailcheck-upgrade-*")
	if err != nil {
		return fmt.Errorf("create staged executable: %w", err)
	}
	stagePath := stage.Name()
	defer func() {
		if err := remove(stagePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, fmt.Errorf("remove staged executable: %w", err))
		}
	}()

	if _, err := stage.Write(binary); err != nil {
		closeErr := stage.Close()
		if closeErr != nil {
			return errors.Join(
				fmt.Errorf("write staged executable: %w", err),
				fmt.Errorf("close staged executable: %w", closeErr),
			)
		}
		return fmt.Errorf("write staged executable: %w", err)
	}
	if err := stage.Sync(); err != nil {
		closeErr := stage.Close()
		if closeErr != nil {
			return errors.Join(
				fmt.Errorf("sync staged executable: %w", err),
				fmt.Errorf("close staged executable: %w", closeErr),
			)
		}
		return fmt.Errorf("sync staged executable: %w", err)
	}
	if err := stage.Close(); err != nil {
		return fmt.Errorf("close staged executable: %w", err)
	}
	if err := os.Chmod(stagePath, 0o755); err != nil {
		return fmt.Errorf("set staged executable permissions: %w", err)
	}

	backup, err := os.CreateTemp(directory, ".mailcheck-upgrade-backup-*")
	if err != nil {
		return fmt.Errorf("create executable backup path: %w", err)
	}
	backupPath := backup.Name()
	if err := backup.Close(); err != nil {
		cleanupErr := remove(backupPath)
		if cleanupErr != nil && !errors.Is(cleanupErr, os.ErrNotExist) {
			return errors.Join(
				fmt.Errorf("close executable backup path: %w", err),
				fmt.Errorf("remove executable backup path: %w", cleanupErr),
			)
		}
		return fmt.Errorf("close executable backup path: %w", err)
	}
	if err := remove(backupPath); err != nil {
		return fmt.Errorf("prepare executable backup path: %w", err)
	}

	if err := rename(executablePath, backupPath); err != nil {
		return fmt.Errorf("move executable to backup: %w", err)
	}
	if err := rename(stagePath, executablePath); err != nil {
		rollbackErr := rename(backupPath, executablePath)
		if rollbackErr != nil {
			return errors.Join(
				fmt.Errorf("install staged executable: %w", err),
				fmt.Errorf("restore executable from backup: %w", rollbackErr),
			)
		}
		return fmt.Errorf("install staged executable: %w", err)
	}

	if err := remove(backupPath); err != nil {
		if goos == "windows" && errors.Is(err, syscall.Errno(32)) {
			return nil
		}
		return fmt.Errorf("remove executable backup: %w", err)
	}
	return nil
}
