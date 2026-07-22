package update

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"
)

const (
	latestReleaseURL  = "https://api.github.com/repos/AHaldner/mailcheck/releases/latest"
	maxChecksumsBytes = 1 << 20
)

// Result describes the installed version before and after an upgrade attempt.
type Result struct {
	From    string
	To      string
	Changed bool
}

// Upgrader discovers, verifies, and installs a newer mailcheck release.
type Upgrader struct {
	Client         ReleaseClient
	GOOS           string
	GOARCH         string
	ExecutablePath func() (string, error)
	Replace        func(string, []byte) error
}

// NewUpgrader returns an Upgrader backed by GitHub and the local executable.
func NewUpgrader(currentVersion string) Upgrader {
	replacer := NewReplacer()
	return Upgrader{
		Client: ReleaseClient{
			HTTP:      &http.Client{Timeout: 2 * time.Second},
			LatestURL: latestReleaseURL,
			UserAgent: "mailcheck/" + currentVersion,
		},
		GOOS:           runtime.GOOS,
		GOARCH:         runtime.GOARCH,
		ExecutablePath: os.Executable,
		Replace:        replacer.Replace,
	}
}

// Upgrade installs the latest stable release when it is newer than currentVersion.
func (u Upgrader) Upgrade(ctx context.Context, currentVersion string) (Result, error) {
	result := Result{From: currentVersion, To: currentVersion}
	if !ValidVersion(currentVersion) {
		return result, fmt.Errorf("current version %q is not a tagged release build", currentVersion)
	}

	release, err := u.Client.Latest(ctx)
	if err != nil {
		return result, fmt.Errorf("fetch latest release: %w", err)
	}

	comparison, err := CompareVersions(currentVersion, release.TagName)
	if err != nil {
		return result, fmt.Errorf("compare release versions: %w", err)
	}
	if comparison >= 0 {
		return result, nil
	}

	archiveName, err := AssetName(release.TagName, u.GOOS, u.GOARCH)
	if err != nil {
		return result, fmt.Errorf("select release asset: %w", err)
	}
	archiveURL, ok := release.Assets[archiveName]
	if !ok || archiveURL == "" {
		return result, fmt.Errorf("latest release is missing required asset %q", archiveName)
	}
	checksumsURL, ok := release.Assets["checksums.txt"]
	if !ok || checksumsURL == "" {
		return result, fmt.Errorf("latest release is missing required asset %q", "checksums.txt")
	}

	archive, err := u.Client.Download(ctx, archiveURL, maxArchiveBytes)
	if err != nil {
		return result, fmt.Errorf("download release archive %q: %w", archiveName, err)
	}
	checksums, err := u.Client.Download(ctx, checksumsURL, maxChecksumsBytes)
	if err != nil {
		return result, fmt.Errorf("download release checksums: %w", err)
	}
	if err := VerifyChecksum(archiveName, archive, checksums); err != nil {
		return result, fmt.Errorf("verify release archive: %w", err)
	}

	binary, err := ExtractExecutable(archiveName, archive)
	if err != nil {
		return result, fmt.Errorf("extract release executable: %w", err)
	}
	executablePath, err := u.ExecutablePath()
	if err != nil {
		return result, fmt.Errorf("resolve current executable path: %w", err)
	}
	if err := u.Replace(executablePath, binary); err != nil {
		return result, fmt.Errorf("replace current executable: %w", err)
	}

	result.To = release.TagName
	result.Changed = true
	return result, nil
}
