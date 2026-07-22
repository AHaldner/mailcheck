package update

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	Client          ReleaseClient
	GOOS            string
	GOARCH          string
	TempDir         string
	DownloadArchive func(context.Context, string, int64, io.Writer) (int64, error)
	ExecutablePath  func() (string, error)
	Replace         func(string, io.Reader) error
}

// NewUpgrader returns an Upgrader backed by GitHub and the local executable.
func NewUpgrader(currentVersion string) Upgrader {
	replacer := NewReplacer()
	client := ReleaseClient{
		HTTP:      &http.Client{Timeout: 2 * time.Second},
		LatestURL: latestReleaseURL,
		UserAgent: "mailcheck/" + currentVersion,
	}
	return Upgrader{
		Client:          client,
		GOOS:            runtime.GOOS,
		GOARCH:          runtime.GOARCH,
		DownloadArchive: client.DownloadTo,
		ExecutablePath:  os.Executable,
		Replace:         replacer.ReplaceFrom,
	}
}

// Upgrade installs the latest stable release when it is newer than currentVersion.
func (u Upgrader) Upgrade(ctx context.Context, currentVersion string) (result Result, resultErr error) {
	result = Result{From: currentVersion, To: currentVersion}
	if !StableVersion(currentVersion) {
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

	archive, err := os.CreateTemp(u.TempDir, "mailcheck-upgrade-archive-*")
	if err != nil {
		return result, fmt.Errorf("create temporary release archive: %w", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, cleanupUpgradeTemporary(archive, "release archive"))
	}()

	downloadArchive := u.DownloadArchive
	if downloadArchive == nil {
		downloadArchive = u.Client.DownloadTo
	}
	archiveSize, err := downloadArchive(ctx, archiveURL, maxArchiveBytes, archive)
	if err != nil {
		return result, fmt.Errorf("download release archive %q: %w", archiveName, err)
	}
	if archiveSize < 0 || archiveSize > maxArchiveBytes {
		return result, fmt.Errorf("download release archive %q: archive exceeds maximum size of %d bytes", archiveName, maxArchiveBytes)
	}
	checksums, err := u.Client.Download(ctx, checksumsURL, maxChecksumsBytes)
	if err != nil {
		return result, fmt.Errorf("download release checksums: %w", err)
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return result, fmt.Errorf("rewind release archive for verification: %w", err)
	}
	if err := verifyChecksumReader(archiveName, archive, checksums); err != nil {
		return result, fmt.Errorf("verify release archive: %w", err)
	}

	executable, err := os.CreateTemp(u.TempDir, "mailcheck-upgrade-executable-*")
	if err != nil {
		return result, fmt.Errorf("create temporary release executable: %w", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, cleanupUpgradeTemporary(executable, "release executable"))
	}()

	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return result, fmt.Errorf("rewind release archive for extraction: %w", err)
	}
	if err := extractExecutableTo(archiveName, archive, archiveSize, executable, productionExtractionLimits); err != nil {
		return result, fmt.Errorf("extract release executable: %w", err)
	}
	executablePath, err := u.ExecutablePath()
	if err != nil {
		return result, fmt.Errorf("resolve current executable path: %w", err)
	}
	if _, err := executable.Seek(0, io.SeekStart); err != nil {
		return result, fmt.Errorf("rewind release executable for replacement: %w", err)
	}
	if err := u.Replace(executablePath, executable); err != nil {
		return result, fmt.Errorf("replace current executable: %w", err)
	}

	result.To = release.TagName
	result.Changed = true
	return result, nil
}

func cleanupUpgradeTemporary(file *os.File, description string) error {
	closeErr := file.Close()
	removeErr := os.Remove(file.Name())
	if errors.Is(removeErr, os.ErrNotExist) {
		removeErr = nil
	}
	if closeErr != nil {
		closeErr = fmt.Errorf("close temporary %s: %w", description, closeErr)
	}
	if removeErr != nil {
		removeErr = fmt.Errorf("remove temporary %s: %w", description, removeErr)
	}
	return errors.Join(closeErr, removeErr)
}
