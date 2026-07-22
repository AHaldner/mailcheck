package update

import (
	"errors"
	"fmt"
	"os"
)

// ErrLockContended reports that another descriptor currently owns a file lock.
var ErrLockContended = errors.New("file lock is contended")

type fileLock struct {
	file *os.File
}

func acquireFileLock(path string) (*fileLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file %q: %w", path, err)
	}
	if err := tryLockFile(file); err != nil {
		closeErr := file.Close()
		if closeErr != nil {
			return nil, errors.Join(
				fmt.Errorf("lock file %q: %w", path, err),
				fmt.Errorf("close unowned lock file %q: %w", path, closeErr),
			)
		}
		return nil, fmt.Errorf("lock file %q: %w", path, err)
	}
	return &fileLock{file: file}, nil
}

func (l *fileLock) release() error {
	unlockErr := unlockFile(l.file)
	closeErr := l.file.Close()
	if unlockErr != nil {
		unlockErr = fmt.Errorf("unlock file %q: %w", l.file.Name(), unlockErr)
	}
	if closeErr != nil {
		closeErr = fmt.Errorf("close lock file %q: %w", l.file.Name(), closeErr)
	}
	return errors.Join(unlockErr, closeErr)
}
