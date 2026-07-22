package update

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	noticeCacheLifetime = 24 * time.Hour
)

type noticeCache struct {
	CheckedAt       time.Time `json:"checked_at"`
	LatestVersion   string    `json:"latest_version"`
	NotifiedVersion string    `json:"notified_version"`
}

// NoticeChecker checks for a newer release using a best-effort daily cache.
type NoticeChecker struct {
	Now       func() time.Time
	CachePath string
	Latest    func(context.Context) (string, error)
}

// NewNoticeChecker returns a NoticeChecker backed by GitHub and the user cache.
func NewNoticeChecker(currentVersion string) NoticeChecker {
	cacheDirectory, err := os.UserCacheDir()
	cachePath := ""
	if err == nil {
		cachePath = filepath.Join(cacheDirectory, "mailcheck", "update.json")
	}

	client := ReleaseClient{
		HTTP:      &http.Client{Timeout: 2 * time.Second},
		LatestURL: latestReleaseURL,
		UserAgent: "mailcheck/" + currentVersion,
	}
	return NoticeChecker{
		Now:       time.Now,
		CachePath: cachePath,
		Latest: func(ctx context.Context) (string, error) {
			release, err := client.Latest(ctx)
			return release.TagName, err
		},
	}
}

// Check returns a one-time notice when a newer release is available.
// Cache and release lookup failures are intentionally silent.
func (c NoticeChecker) Check(ctx context.Context, currentVersion string) string {
	if !StableVersion(currentVersion) {
		return ""
	}

	lock, err := acquireNoticeLock(c.CachePath)
	if err != nil {
		return ""
	}
	defer func() { _ = lock.release() }()

	now := time.Now()
	if c.Now != nil {
		now = c.Now()
	}
	state, _ := readNoticeCache(c.CachePath)
	if !state.CheckedAt.IsZero() && !now.Before(state.CheckedAt) && now.Sub(state.CheckedAt) < noticeCacheLifetime {
		return ""
	}

	state.CheckedAt = now
	if c.Latest == nil {
		_ = writeNoticeCache(c.CachePath, state)
		return ""
	}
	latestVersion, err := c.Latest(ctx)
	if err != nil {
		_ = writeNoticeCache(c.CachePath, state)
		return ""
	}

	comparison, err := CompareVersions(currentVersion, latestVersion)
	if err != nil {
		_ = writeNoticeCache(c.CachePath, state)
		return ""
	}
	state.LatestVersion = latestVersion
	if comparison >= 0 || latestVersion == state.NotifiedVersion {
		_ = writeNoticeCache(c.CachePath, state)
		return ""
	}

	state.NotifiedVersion = latestVersion
	if err := writeNoticeCache(c.CachePath, state); err != nil {
		return ""
	}
	return fmt.Sprintf(`A new mailcheck version is available: %s (current: %s). Run "mailcheck upgrade".`, latestVersion, currentVersion)
}

func acquireNoticeLock(cachePath string) (*fileLock, error) {
	if cachePath == "" {
		return nil, os.ErrInvalid
	}

	directory := filepath.Dir(cachePath)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, err
	}

	return acquireFileLock(cachePath + ".lock")
}

func readNoticeCache(path string) (noticeCache, error) {
	if path == "" {
		return noticeCache{}, os.ErrNotExist
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return noticeCache{}, err
	}
	var state noticeCache
	if err := json.Unmarshal(data, &state); err != nil {
		return noticeCache{}, err
	}
	return state, nil
}

func writeNoticeCache(path string, state noticeCache) error {
	if path == "" {
		return os.ErrInvalid
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return err
	}

	temporary, err := os.CreateTemp(directory, ".mailcheck-update-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	closed := false
	defer func() {
		if !closed {
			_ = temporary.Close()
		}
		_ = os.Remove(temporaryPath)
	}()

	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if err := json.NewEncoder(temporary).Encode(state); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		closed = true
		return err
	}
	closed = true
	return os.Rename(temporaryPath, path)
}
