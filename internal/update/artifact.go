package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

const (
	maxArchiveBytes    = 100 << 20
	maxExecutableBytes = 64 << 20
)

// AssetName returns the GoReleaser archive name for a supported platform.
func AssetName(version, goos, goarch string) (string, error) {
	if goos != "darwin" && goos != "linux" && goos != "windows" {
		return "", fmt.Errorf("unsupported platform %q", goos)
	}
	if goarch != "amd64" && goarch != "arm64" {
		return "", fmt.Errorf("unsupported architecture %q", goarch)
	}

	version = strings.TrimPrefix(version, "v")
	if version == "" {
		return "", fmt.Errorf("version is required")
	}

	extension := ".tar.gz"
	if goos == "windows" {
		extension = ".zip"
	}
	return fmt.Sprintf("mailcheck_%s_%s_%s%s", version, goos, goarch, extension), nil
}

// VerifyChecksum verifies archive against its exact entry in checksums.
func VerifyChecksum(name string, archive, checksums []byte) error {
	var expected []byte
	for _, line := range strings.Split(string(checksums), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) != 2 {
			return fmt.Errorf("malformed checksum entry")
		}
		digest, err := hex.DecodeString(fields[0])
		if err != nil || len(digest) != sha256.Size {
			return fmt.Errorf("malformed SHA-256 checksum for %q", fields[1])
		}

		entryName := strings.TrimPrefix(fields[1], "*")
		if entryName != name {
			continue
		}
		if expected != nil {
			return fmt.Errorf("duplicate checksum entry for %q", name)
		}
		expected = digest
	}

	if expected == nil {
		return fmt.Errorf("checksum for %q not found", name)
	}
	actual := sha256.Sum256(archive)
	if subtle.ConstantTimeCompare(actual[:], expected) != 1 {
		return fmt.Errorf("checksum mismatch for %q", name)
	}
	return nil
}

// ExtractExecutable returns the exact executable entry from a verified release archive.
func ExtractExecutable(name string, archive []byte) ([]byte, error) {
	if len(archive) > maxArchiveBytes {
		return nil, fmt.Errorf("archive exceeds maximum size of %d bytes", maxArchiveBytes)
	}

	switch {
	case strings.HasSuffix(name, ".tar.gz"):
		return extractTarGzExecutable(archive, "mailcheck")
	case strings.HasSuffix(name, ".zip"):
		return extractZipExecutable(archive, "mailcheck.exe")
	default:
		return nil, fmt.Errorf("unsupported archive extension for %q", name)
	}
}

func extractTarGzExecutable(archive []byte, executableName string) ([]byte, error) {
	gzipReader, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("open tar.gz archive: %w", err)
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)
	var executable []byte
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar archive: %w", err)
		}
		if header.Name != executableName {
			continue
		}
		if executable != nil {
			return nil, fmt.Errorf("archive contains duplicate executable entry %q", executableName)
		}

		executable, err = readExecutable(tarReader, header.Size, executableName)
		if err != nil {
			return nil, err
		}
	}

	if executable == nil {
		return nil, fmt.Errorf("executable entry %q not found", executableName)
	}
	return executable, nil
}

func extractZipExecutable(archive []byte, executableName string) ([]byte, error) {
	zipReader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, fmt.Errorf("open zip archive: %w", err)
	}

	var executable []byte
	for _, file := range zipReader.File {
		if file.Name != executableName {
			continue
		}
		if executable != nil {
			return nil, fmt.Errorf("archive contains duplicate executable entry %q", executableName)
		}
		if file.UncompressedSize64 > maxExecutableBytes {
			return nil, fmt.Errorf("executable entry %q exceeds maximum size of %d bytes", executableName, maxExecutableBytes)
		}

		entry, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("open executable entry %q: %w", executableName, err)
		}
		executable, err = readExecutable(entry, int64(file.UncompressedSize64), executableName)
		closeErr := entry.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close executable entry %q: %w", executableName, closeErr)
		}
	}

	if executable == nil {
		return nil, fmt.Errorf("executable entry %q not found", executableName)
	}
	return executable, nil
}

func readExecutable(reader io.Reader, size int64, name string) ([]byte, error) {
	if size <= 0 {
		return nil, fmt.Errorf("executable entry %q is empty", name)
	}
	if size > maxExecutableBytes {
		return nil, fmt.Errorf("executable entry %q exceeds maximum size of %d bytes", name, maxExecutableBytes)
	}

	data, err := io.ReadAll(io.LimitReader(reader, maxExecutableBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read executable entry %q: %w", name, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("executable entry %q is empty", name)
	}
	if len(data) > maxExecutableBytes {
		return nil, fmt.Errorf("executable entry %q exceeds maximum size of %d bytes", name, maxExecutableBytes)
	}
	return data, nil
}
