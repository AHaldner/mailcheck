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
	maxArchiveBytes         = 100 << 20
	maxExecutableBytes      = 64 << 20
	maxDecompressedTarBytes = 128 << 20
	maxArchiveEntries       = 1024
)

type extractionLimits struct {
	maxArchiveBytes         int64
	maxExecutableBytes      int64
	maxDecompressedTarBytes int64
	maxEntries              int
}

var productionExtractionLimits = extractionLimits{
	maxArchiveBytes:         maxArchiveBytes,
	maxExecutableBytes:      maxExecutableBytes,
	maxDecompressedTarBytes: maxDecompressedTarBytes,
	maxEntries:              maxArchiveEntries,
}

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
	return verifyChecksumReader(name, bytes.NewReader(archive), checksums)
}

func verifyChecksumReader(name string, archive io.Reader, checksums []byte) error {
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
	hash := sha256.New()
	if _, err := io.Copy(hash, archive); err != nil {
		return fmt.Errorf("read archive for checksum: %w", err)
	}
	if subtle.ConstantTimeCompare(hash.Sum(nil), expected) != 1 {
		return fmt.Errorf("checksum mismatch for %q", name)
	}
	return nil
}

// ExtractExecutable returns the exact executable entry from a verified release archive.
func ExtractExecutable(name string, archive []byte) ([]byte, error) {
	var executable bytes.Buffer
	err := extractExecutableTo(name, bytes.NewReader(archive), int64(len(archive)), &executable, productionExtractionLimits)
	if err != nil {
		return nil, err
	}
	return executable.Bytes(), nil
}

func extractExecutableTo(name string, archive io.ReaderAt, archiveSize int64, destination io.Writer, limits extractionLimits) error {
	if archiveSize > limits.maxArchiveBytes {
		return fmt.Errorf("archive exceeds maximum size of %d bytes", limits.maxArchiveBytes)
	}
	if archiveSize < 0 {
		return fmt.Errorf("archive size must not be negative")
	}

	switch {
	case strings.HasSuffix(name, ".tar.gz"):
		return extractTarGzExecutableTo(io.NewSectionReader(archive, 0, archiveSize), destination, "mailcheck", limits)
	case strings.HasSuffix(name, ".zip"):
		return extractZipExecutableTo(archive, archiveSize, destination, "mailcheck.exe", limits)
	default:
		return fmt.Errorf("unsupported archive extension for %q", name)
	}
}

func extractTarGzExecutableTo(archive io.Reader, destination io.Writer, executableName string, limits extractionLimits) error {
	gzipReader, err := gzip.NewReader(archive)
	if err != nil {
		return fmt.Errorf("open tar.gz archive: %w", err)
	}
	defer gzipReader.Close()

	decompressed := &io.LimitedReader{R: gzipReader, N: limits.maxDecompressedTarBytes + 1}
	tarReader := tar.NewReader(decompressed)
	found := false
	entries := 0
	for {
		header, err := tarReader.Next()
		if decompressed.N == 0 {
			return fmt.Errorf("tar archive exceeds maximum decompressed size of %d bytes", limits.maxDecompressedTarBytes)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar archive: %w", err)
		}
		entries++
		if entries > limits.maxEntries {
			return fmt.Errorf("tar archive exceeds maximum entry count of %d", limits.maxEntries)
		}
		if header.Name != executableName {
			continue
		}
		if found {
			return fmt.Errorf("archive contains duplicate executable entry %q", executableName)
		}

		err = copyExecutable(destination, tarReader, header.Size, executableName, limits.maxExecutableBytes)
		if decompressed.N == 0 {
			return fmt.Errorf("tar archive exceeds maximum decompressed size of %d bytes", limits.maxDecompressedTarBytes)
		}
		if err != nil {
			return err
		}
		found = true
	}

	if !found {
		return fmt.Errorf("executable entry %q not found", executableName)
	}
	return nil
}

func extractZipExecutableTo(archive io.ReaderAt, archiveSize int64, destination io.Writer, executableName string, limits extractionLimits) error {
	zipReader, err := zip.NewReader(archive, archiveSize)
	if err != nil {
		return fmt.Errorf("open zip archive: %w", err)
	}
	if len(zipReader.File) > limits.maxEntries {
		return fmt.Errorf("zip archive exceeds maximum entry count of %d", limits.maxEntries)
	}

	found := false
	for _, file := range zipReader.File {
		if file.Name != executableName {
			continue
		}
		if found {
			return fmt.Errorf("archive contains duplicate executable entry %q", executableName)
		}
		if file.UncompressedSize64 > uint64(limits.maxExecutableBytes) {
			return fmt.Errorf("executable entry %q exceeds maximum size of %d bytes", executableName, limits.maxExecutableBytes)
		}

		entry, err := file.Open()
		if err != nil {
			return fmt.Errorf("open executable entry %q: %w", executableName, err)
		}
		err = copyExecutable(destination, entry, int64(file.UncompressedSize64), executableName, limits.maxExecutableBytes)
		closeErr := entry.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return fmt.Errorf("close executable entry %q: %w", executableName, closeErr)
		}
		found = true
	}

	if !found {
		return fmt.Errorf("executable entry %q not found", executableName)
	}
	return nil
}

func copyExecutable(destination io.Writer, reader io.Reader, size int64, name string, maxBytes int64) error {
	if size <= 0 {
		return fmt.Errorf("executable entry %q is empty", name)
	}
	if size > maxBytes {
		return fmt.Errorf("executable entry %q exceeds maximum size of %d bytes", name, maxBytes)
	}

	written, err := io.Copy(destination, io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return fmt.Errorf("copy executable entry %q: %w", name, err)
	}
	if written == 0 {
		return fmt.Errorf("executable entry %q is empty", name)
	}
	if written > maxBytes {
		return fmt.Errorf("executable entry %q exceeds maximum size of %d bytes", name, maxBytes)
	}
	if written != size {
		return fmt.Errorf("executable entry %q size mismatch: copied %d bytes, expected %d", name, written, size)
	}
	return nil
}
