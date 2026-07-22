package update

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

const updateNotice = `A new mailcheck version is available: v1.3.0 (current: v1.2.3). Run "mailcheck upgrade".`

var noticeNow = time.Date(2026, time.July, 22, 12, 0, 0, 0, time.UTC)

func TestNoticeCheckerSkipsInvalidCurrentVersion(t *testing.T) {
	requests := 0
	checker := testNoticeChecker(t, noticeNow, func(context.Context) (string, error) {
		requests++
		return "v1.3.0", nil
	})

	if got := checker.Check(context.Background(), "dev"); got != "" {
		t.Fatalf("Check() = %q, want empty notice", got)
	}
	if requests != 0 {
		t.Fatalf("latest requests = %d, want 0", requests)
	}
	if _, err := os.Stat(checker.CachePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cache stat error = %v, want not exist", err)
	}
}

func TestNoticeCheckerSkipsNonStableCurrentVersionBeforeCacheOrLatest(t *testing.T) {
	for _, currentVersion := range []string{"v1.3.0-rc.1", "v1.3.0-12-gabcdef-dirty"} {
		t.Run(currentVersion, func(t *testing.T) {
			nowCalls := 0
			latestCalls := 0
			checker := NoticeChecker{
				Now: func() time.Time {
					nowCalls++
					return noticeNow
				},
				CachePath: filepath.Join(t.TempDir(), "mailcheck", "update.json"),
				Latest: func(context.Context) (string, error) {
					latestCalls++
					return "v1.3.0", nil
				},
			}

			if got := checker.Check(context.Background(), currentVersion); got != "" {
				t.Errorf("Check() = %q, want empty notice", got)
			}
			if nowCalls != 0 {
				t.Errorf("clock reads = %d, want 0 before cache activity", nowCalls)
			}
			if latestCalls != 0 {
				t.Errorf("latest calls = %d, want 0", latestCalls)
			}
			if _, err := os.Stat(checker.CachePath); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("cache stat error = %v, want not exist", err)
			}
		})
	}
}

func TestNoticeCheckerAnnouncesFirstNewerRelease(t *testing.T) {
	requests := 0
	checker := testNoticeChecker(t, noticeNow, func(context.Context) (string, error) {
		requests++
		return "v1.3.0", nil
	})

	if got := checker.Check(context.Background(), "v1.2.3"); got != updateNotice {
		t.Fatalf("Check() = %q, want %q", got, updateNotice)
	}
	if requests != 1 {
		t.Fatalf("latest requests = %d, want 1", requests)
	}

	state := readTestNoticeCache(t, checker.CachePath)
	if !state.CheckedAt.Equal(noticeNow) || state.LatestVersion != "v1.3.0" || state.NotifiedVersion != "v1.3.0" {
		t.Fatalf("cache = %#v, want checked/latest/notified state", state)
	}
}

func TestNoticeCheckerSecondRunWithinDaySkipsRequestAndNotice(t *testing.T) {
	now := noticeNow
	requests := 0
	checker := NoticeChecker{
		Now:       func() time.Time { return now },
		CachePath: filepath.Join(t.TempDir(), "mailcheck", "update.json"),
		Latest: func(context.Context) (string, error) {
			requests++
			return "v1.3.0", nil
		},
	}

	if got := checker.Check(context.Background(), "v1.2.3"); got != updateNotice {
		t.Fatalf("first Check() = %q, want %q", got, updateNotice)
	}
	now = now.Add(23*time.Hour + 59*time.Minute)

	if got := checker.Check(context.Background(), "v1.2.3"); got != "" {
		t.Fatalf("second Check() = %q, want empty notice", got)
	}
	if requests != 1 {
		t.Fatalf("latest requests = %d, want 1", requests)
	}
}

func TestNoticeCheckerOverlappingChecksMakeOneRequestAndNotice(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "mailcheck", "update.json")
	latestStarted := make(chan struct{}, 1)
	releaseLatest := make(chan struct{})
	var latestCalls atomic.Int32
	checker := NoticeChecker{
		Now:       func() time.Time { return noticeNow },
		CachePath: cachePath,
		Latest: func(context.Context) (string, error) {
			latestCalls.Add(1)
			select {
			case latestStarted <- struct{}{}:
			default:
			}
			<-releaseLatest
			return "v1.3.0", nil
		},
	}

	firstResult := make(chan string, 1)
	go func() {
		firstResult <- checker.Check(context.Background(), "v1.2.3")
	}()
	<-latestStarted

	secondResult := make(chan string, 1)
	go func() {
		secondResult <- checker.Check(context.Background(), "v1.2.3")
	}()
	select {
	case got := <-secondResult:
		if got != "" {
			t.Fatalf("overlapping Check() = %q, want empty notice", got)
		}
	case <-time.After(time.Second):
		close(releaseLatest)
		t.Fatal("overlapping Check() waited for the live checker")
	}

	close(releaseLatest)
	if got := <-firstResult; got != updateNotice {
		t.Fatalf("first Check() = %q, want %q", got, updateNotice)
	}
	if got := latestCalls.Load(); got != 1 {
		t.Fatalf("latest calls = %d, want 1", got)
	}
}

func TestNoticeCheckerContendedLockSkipsClockCacheAndLatest(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "mailcheck", "update.json")
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o700); err != nil {
		t.Fatal(err)
	}
	owner, err := acquireFileLock(cachePath + ".lock")
	if err != nil {
		t.Fatalf("acquireFileLock(owner) error = %v", err)
	}
	t.Cleanup(func() { _ = owner.release() })

	clockCalls := 0
	latestCalls := 0
	checker := NoticeChecker{
		Now: func() time.Time {
			clockCalls++
			return noticeNow
		},
		CachePath: cachePath,
		Latest: func(context.Context) (string, error) {
			latestCalls++
			return "v1.3.0", nil
		},
	}

	if got := checker.Check(context.Background(), "v1.2.3"); got != "" {
		t.Fatalf("Check() = %q, want empty notice", got)
	}
	if clockCalls != 0 {
		t.Fatalf("clock calls = %d, want 0", clockCalls)
	}
	if latestCalls != 0 {
		t.Fatalf("latest calls = %d, want 0", latestCalls)
	}
	if _, err := os.Stat(cachePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cache stat error = %v, want not exist", err)
	}
}

func TestNoticeCheckerStaleCacheRequestsSameReleaseWithoutRenotifying(t *testing.T) {
	requests := 0
	checker := testNoticeChecker(t, noticeNow, func(context.Context) (string, error) {
		requests++
		return "v1.3.0", nil
	})
	writeTestNoticeCache(t, checker.CachePath, noticeCache{
		CheckedAt:       noticeNow.Add(-24 * time.Hour),
		LatestVersion:   "v1.3.0",
		NotifiedVersion: "v1.3.0",
	})

	if got := checker.Check(context.Background(), "v1.2.3"); got != "" {
		t.Fatalf("Check() = %q, want empty notice", got)
	}
	if requests != 1 {
		t.Fatalf("latest requests = %d, want 1", requests)
	}
	state := readTestNoticeCache(t, checker.CachePath)
	if !state.CheckedAt.Equal(noticeNow) || state.NotifiedVersion != "v1.3.0" {
		t.Fatalf("cache = %#v, want refreshed check with preserved notified version", state)
	}
}

func TestNoticeCheckerStaleCacheAnnouncesLaterRelease(t *testing.T) {
	checker := testNoticeChecker(t, noticeNow, func(context.Context) (string, error) {
		return "v1.3.0", nil
	})
	writeTestNoticeCache(t, checker.CachePath, noticeCache{
		CheckedAt:       noticeNow.Add(-48 * time.Hour),
		LatestVersion:   "v1.2.4",
		NotifiedVersion: "v1.2.4",
	})

	if got := checker.Check(context.Background(), "v1.2.3"); got != updateNotice {
		t.Fatalf("Check() = %q, want %q", got, updateNotice)
	}
	state := readTestNoticeCache(t, checker.CachePath)
	if state.LatestVersion != "v1.3.0" || state.NotifiedVersion != "v1.3.0" {
		t.Fatalf("cache = %#v, want later release persisted", state)
	}
}

func TestNoticeCheckerDoesNotAnnounceEqualOrOlderRelease(t *testing.T) {
	for _, latest := range []string{"v1.2.3", "v1.2.2"} {
		t.Run(latest, func(t *testing.T) {
			checker := testNoticeChecker(t, noticeNow, func(context.Context) (string, error) {
				return latest, nil
			})

			if got := checker.Check(context.Background(), "v1.2.3"); got != "" {
				t.Fatalf("Check() = %q, want empty notice", got)
			}
			state := readTestNoticeCache(t, checker.CachePath)
			if state.LatestVersion != latest || state.NotifiedVersion != "" {
				t.Fatalf("cache = %#v, want latest version without notification", state)
			}
		})
	}
}

func TestNoticeCheckerFailedRequestIsSilentAndThrottled(t *testing.T) {
	requests := 0
	checker := testNoticeChecker(t, noticeNow, func(context.Context) (string, error) {
		requests++
		return "", errors.New("network unavailable")
	})
	writeTestNoticeCache(t, checker.CachePath, noticeCache{
		CheckedAt:       noticeNow.Add(-48 * time.Hour),
		LatestVersion:   "v1.3.0",
		NotifiedVersion: "v1.3.0",
	})

	if got := checker.Check(context.Background(), "v1.2.3"); got != "" {
		t.Fatalf("first Check() = %q, want empty notice", got)
	}
	if got := checker.Check(context.Background(), "v1.2.3"); got != "" {
		t.Fatalf("second Check() = %q, want empty notice", got)
	}
	if requests != 1 {
		t.Fatalf("latest requests = %d, want 1", requests)
	}
	state := readTestNoticeCache(t, checker.CachePath)
	if !state.CheckedAt.Equal(noticeNow) || state.LatestVersion != "v1.3.0" || state.NotifiedVersion != "v1.3.0" {
		t.Fatalf("cache = %#v, want refreshed check with release state preserved", state)
	}
}

func TestNoticeCheckerMalformedCacheRecoversSilently(t *testing.T) {
	checker := testNoticeChecker(t, noticeNow, func(context.Context) (string, error) {
		return "v1.3.0", nil
	})
	if err := os.MkdirAll(filepath.Dir(checker.CachePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(checker.CachePath, []byte(`{"checked_at":`), 0o600); err != nil {
		t.Fatal(err)
	}

	if got := checker.Check(context.Background(), "v1.2.3"); got != updateNotice {
		t.Fatalf("Check() = %q, want %q", got, updateNotice)
	}
	state := readTestNoticeCache(t, checker.CachePath)
	if state.LatestVersion != "v1.3.0" || state.NotifiedVersion != "v1.3.0" {
		t.Fatalf("cache = %#v, want recovered state", state)
	}
}

func TestNoticeCheckerClockRollbackForcesRequest(t *testing.T) {
	requests := 0
	checker := testNoticeChecker(t, noticeNow, func(context.Context) (string, error) {
		requests++
		return "v1.3.0", nil
	})
	writeTestNoticeCache(t, checker.CachePath, noticeCache{
		CheckedAt:       noticeNow.Add(time.Hour),
		LatestVersion:   "v1.3.0",
		NotifiedVersion: "v1.3.0",
	})

	if got := checker.Check(context.Background(), "v1.2.3"); got != "" {
		t.Fatalf("Check() = %q, want empty notice", got)
	}
	if requests != 1 {
		t.Fatalf("latest requests = %d, want 1", requests)
	}
	if got := readTestNoticeCache(t, checker.CachePath).CheckedAt; !got.Equal(noticeNow) {
		t.Fatalf("checked_at = %v, want %v", got, noticeNow)
	}
}

func TestNoticeCheckerUnwritableCacheIsSilent(t *testing.T) {
	root := t.TempDir()
	parentFile := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(parentFile, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	latestCalls := 0
	checker := NoticeChecker{
		Now:       func() time.Time { return noticeNow },
		CachePath: filepath.Join(parentFile, "update.json"),
		Latest: func(context.Context) (string, error) {
			latestCalls++
			return "v1.3.0", nil
		},
	}

	if got := checker.Check(context.Background(), "v1.2.3"); got != "" {
		t.Fatalf("Check() = %q, want empty notice", got)
	}
	if latestCalls != 0 {
		t.Fatalf("latest calls = %d, want 0", latestCalls)
	}
}

func TestNoticeCheckerCacheCommitFailureDoesNotEmitNotice(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "update.json")
	if err := os.Mkdir(cachePath, 0o700); err != nil {
		t.Fatal(err)
	}
	latestCalls := 0
	checker := NoticeChecker{
		Now:       func() time.Time { return noticeNow },
		CachePath: cachePath,
		Latest: func(context.Context) (string, error) {
			latestCalls++
			return "v1.3.0", nil
		},
	}

	if got := checker.Check(context.Background(), "v1.2.3"); got != "" {
		t.Fatalf("Check() = %q, want empty notice after cache commit failure", got)
	}
	if latestCalls != 1 {
		t.Fatalf("latest calls = %d, want 1", latestCalls)
	}
}

func TestNoticeCheckerWritesPrivateModesAndLeavesNoTemporaryFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not enforced on Windows")
	}
	root := t.TempDir()
	checker := NoticeChecker{
		Now:       func() time.Time { return noticeNow },
		CachePath: filepath.Join(root, "mailcheck", "update.json"),
		Latest: func(context.Context) (string, error) {
			return "v1.3.0", nil
		},
	}

	if got := checker.Check(context.Background(), "v1.2.3"); got != updateNotice {
		t.Fatalf("Check() = %q, want %q", got, updateNotice)
	}
	directoryInfo, err := os.Stat(filepath.Dir(checker.CachePath))
	if err != nil {
		t.Fatal(err)
	}
	if got := directoryInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("cache directory mode = %04o, want 0700", got)
	}
	fileInfo, err := os.Stat(checker.CachePath)
	if err != nil {
		t.Fatal(err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("cache file mode = %04o, want 0600", got)
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(checker.CachePath), ".mailcheck-update-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary cache files = %v, want none", matches)
	}
}

func TestNewNoticeCheckerUsesProductionDefaults(t *testing.T) {
	checker := NewNoticeChecker("v1.2.3")
	cacheDirectory, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	if checker.CachePath != filepath.Join(cacheDirectory, "mailcheck", "update.json") {
		t.Fatalf("CachePath = %q, want mailcheck/update.json under user cache", checker.CachePath)
	}
	if checker.Now == nil || checker.Latest == nil {
		t.Fatal("NewNoticeChecker() returned nil dependency")
	}
}

func testNoticeChecker(t *testing.T, now time.Time, latest func(context.Context) (string, error)) NoticeChecker {
	t.Helper()
	return NoticeChecker{
		Now:       func() time.Time { return now },
		CachePath: filepath.Join(t.TempDir(), "mailcheck", "update.json"),
		Latest:    latest,
	}
}

func writeTestNoticeCache(t *testing.T, path string, state noticeCache) {
	t.Helper()
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readTestNoticeCache(t *testing.T, path string) noticeCache {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state noticeCache
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("decode cache: %v", err)
	}
	return state
}
