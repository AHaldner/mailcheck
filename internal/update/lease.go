package update

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	directoryLeaseOwnerPrefix = "owner-"
	directoryLeaseStalePrefix = "stale-"
)

type directoryLease struct {
	path  string
	token string
}

func acquireDirectoryLease(path string, now time.Time, lease time.Duration) (directoryLease, bool) {
	for range 3 {
		lock, err := createDirectoryLease(path)
		if err == nil {
			return lock, true
		}
		if !errors.Is(err, os.ErrExist) || !removeStaleDirectoryLease(path, now, lease) {
			return directoryLease{}, false
		}
	}

	return directoryLease{}, false
}

func createDirectoryLease(path string) (directoryLease, error) {
	identity := make([]byte, 16)
	if _, err := rand.Read(identity); err != nil {
		return directoryLease{}, err
	}
	token := hex.EncodeToString(identity)

	if err := os.Mkdir(path, 0o700); err != nil {
		return directoryLease{}, err
	}
	ownerPath := filepath.Join(path, directoryLeaseOwnerName(token))
	file, err := os.OpenFile(ownerPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		_ = os.Remove(path)
		return directoryLease{}, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(ownerPath)
		_ = os.Remove(path)
		return directoryLease{}, err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(ownerPath)
		_ = os.Remove(path)
		return directoryLease{}, err
	}

	return directoryLease{path: path, token: token}, nil
}

func removeStaleDirectoryLease(path string, now time.Time, lease time.Duration) bool {
	info, err := os.Stat(path)
	if err != nil || now.Before(info.ModTime()) || now.Sub(info.ModTime()) <= lease {
		return false
	}
	if !info.IsDir() {
		return false
	}

	entries, err := os.ReadDir(path)
	if err != nil || len(entries) > 1 {
		return false
	}
	if len(entries) == 0 {
		return os.Remove(path) == nil
	}

	entryName := entries[0].Name()
	if entries[0].IsDir() {
		return false
	}

	var stalePath string
	switch {
	case strings.HasPrefix(entryName, directoryLeaseOwnerPrefix):
		token := strings.TrimPrefix(entryName, directoryLeaseOwnerPrefix)
		if !validDirectoryLeaseToken(token) {
			return false
		}
		ownerPath := filepath.Join(path, entryName)
		stalePath = filepath.Join(path, directoryLeaseStaleName(token))
		if err := os.Rename(ownerPath, stalePath); err != nil {
			return false
		}
	case strings.HasPrefix(entryName, directoryLeaseStalePrefix):
		token := strings.TrimPrefix(entryName, directoryLeaseStalePrefix)
		if !validDirectoryLeaseToken(token) {
			return false
		}
		stalePath = filepath.Join(path, entryName)
	default:
		return false
	}

	if err := os.Remove(stalePath); err != nil {
		return false
	}
	return os.Remove(path) == nil
}

func (l directoryLease) release() error {
	if err := os.Remove(filepath.Join(l.path, directoryLeaseOwnerName(l.token))); err != nil {
		return err
	}
	return os.Remove(l.path)
}

func directoryLeaseOwnerName(token string) string {
	return directoryLeaseOwnerPrefix + token
}

func directoryLeaseStaleName(token string) string {
	return directoryLeaseStalePrefix + token
}

func validDirectoryLeaseToken(token string) bool {
	decoded, err := hex.DecodeString(token)
	return err == nil && len(decoded) == 16
}
