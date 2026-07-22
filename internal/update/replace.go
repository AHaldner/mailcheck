package update

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

const replacementLockLease = 5 * time.Minute

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
	return r.ReplaceFrom(executablePath, bytes.NewReader(binary))
}

// ReplaceFrom streams source into a same-directory staged file, then atomically
// installs it while preserving the previous executable until installation succeeds.
func (r Replacer) ReplaceFrom(executablePath string, source io.Reader) (result error) {
	lock, ok := acquireDirectoryLease(replacementLockPath(executablePath), time.Now(), replacementLockLease)
	if !ok {
		return fmt.Errorf("replacement already in progress or replacement lock is unavailable")
	}
	defer func() {
		if err := lock.release(); err != nil {
			result = errors.Join(result, fmt.Errorf("release replacement lock: %w", err))
		}
	}()

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
	backupPath := replacementBackupPath(executablePath)
	if err := prepareExecutableForReplacement(executablePath, backupPath, rename, remove); err != nil {
		return err
	}

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

	if _, err := io.Copy(stage, source); err != nil {
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

func replacementBackupPath(executablePath string) string {
	return filepath.Join(filepath.Dir(executablePath), ".mailcheck-upgrade-backup-"+filepath.Base(executablePath))
}

func replacementLockPath(executablePath string) string {
	return filepath.Join(filepath.Dir(executablePath), ".mailcheck-upgrade-lock-"+filepath.Base(executablePath))
}

func prepareExecutableForReplacement(
	executablePath string,
	backupPath string,
	rename func(string, string) error,
	remove func(string) error,
) error {
	_, backupErr := os.Stat(backupPath)
	if errors.Is(backupErr, os.ErrNotExist) {
		if _, err := os.Stat(executablePath); err != nil {
			return fmt.Errorf("inspect current executable: %w", err)
		}
		return nil
	}
	if backupErr != nil {
		return fmt.Errorf("inspect stale executable backup: %w", backupErr)
	}

	if _, err := os.Stat(executablePath); err == nil {
		if err := remove(backupPath); err != nil {
			return fmt.Errorf("remove stale executable backup: %w", err)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect current executable before backup recovery: %w", err)
	}

	if err := rename(backupPath, executablePath); err != nil {
		return fmt.Errorf("restore executable from stale backup: %w", err)
	}
	return nil
}
