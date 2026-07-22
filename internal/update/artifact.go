package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

const (
	maxArchiveBytes         = 100 << 20
	maxExecutableBytes      = 64 << 20
	maxDecompressedTarBytes = 128 << 20
	// archive/tar exposes logical entries; hidden PAX/GNU extension headers
	// remain bounded by maxDecompressedTarBytes instead of this count.
	maxTarLogicalEntries  = 1024
	maxZipEntries         = 1024
	zipDirectoryEndSize   = 22
	zipMaxCommentSize     = 1<<16 - 1
	zipCentralHeaderSize  = 46
	zip64LocatorSize      = 20
	zip64DirectoryEndSize = 56
)

const (
	zipDirectoryEndSignature   = 0x06054b50
	zipCentralHeaderSignature  = 0x02014b50
	zip64LocatorSignature      = 0x07064b50
	zip64DirectoryEndSignature = 0x06064b50
)

type extractionLimits struct {
	maxArchiveBytes         int64
	maxExecutableBytes      int64
	maxDecompressedTarBytes int64
	maxTarLogicalEntries    int
	maxZipEntries           int
}

var productionExtractionLimits = extractionLimits{
	maxArchiveBytes:         maxArchiveBytes,
	maxExecutableBytes:      maxExecutableBytes,
	maxDecompressedTarBytes: maxDecompressedTarBytes,
	maxTarLogicalEntries:    maxTarLogicalEntries,
	maxZipEntries:           maxZipEntries,
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
		if entries > limits.maxTarLogicalEntries {
			return fmt.Errorf("tar archive exceeds maximum logical entry count of %d", limits.maxTarLogicalEntries)
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
	if err := preflightZipEntryCount(archive, archiveSize, limits.maxZipEntries); err != nil {
		return err
	}
	zipReader, err := zip.NewReader(archive, archiveSize)
	if err != nil {
		return fmt.Errorf("open zip archive: %w", err)
	}
	if len(zipReader.File) > limits.maxZipEntries {
		return fmt.Errorf("zip archive exceeds maximum entry count of %d", limits.maxZipEntries)
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

func preflightZipEntryCount(archive io.ReaderAt, archiveSize int64, maxEntries int) error {
	if maxEntries < 0 {
		return fmt.Errorf("zip maximum entry count must not be negative")
	}
	record, recordOffset, err := readZipDirectoryEnd(archive, archiveSize)
	if err != nil {
		return err
	}

	diskNumber := binary.LittleEndian.Uint16(record[4:6])
	directoryDisk := binary.LittleEndian.Uint16(record[6:8])
	entriesOnDisk := binary.LittleEndian.Uint16(record[8:10])
	totalEntries := uint64(binary.LittleEndian.Uint16(record[10:12]))
	directorySize := uint64(binary.LittleEndian.Uint32(record[12:16]))
	directoryOffset := uint64(binary.LittleEndian.Uint32(record[16:20]))
	directoryEndOffset := recordOffset

	usesZip64 := diskNumber == 0xffff ||
		directoryDisk == 0xffff ||
		entriesOnDisk == 0xffff ||
		totalEntries == 0xffff ||
		directorySize == 0xffffffff ||
		directoryOffset == 0xffffffff
	if usesZip64 {
		totalEntries, directorySize, directoryOffset, directoryEndOffset, err = readZip64DirectoryEnd(archive, recordOffset)
		if err != nil {
			return err
		}
	} else if diskNumber != 0 || directoryDisk != 0 || uint64(entriesOnDisk) != totalEntries {
		return fmt.Errorf("multi-disk zip archives are not supported")
	}

	if totalEntries > uint64(maxEntries) {
		return fmt.Errorf("zip archive exceeds maximum entry count of %d", maxEntries)
	}
	if directoryOffset > uint64(directoryEndOffset) || directorySize > uint64(directoryEndOffset)-directoryOffset {
		return fmt.Errorf("zip central directory is out of bounds")
	}
	return preflightZipCentralDirectory(
		archive,
		archiveSize,
		directoryEndOffset,
		directorySize,
		directoryOffset,
		totalEntries,
		maxEntries,
	)
}

func preflightZipCentralDirectory(
	archive io.ReaderAt,
	archiveSize int64,
	directoryEndOffset int64,
	directorySize uint64,
	directoryOffset uint64,
	claimedEntries uint64,
	maxEntries int,
) error {
	defaultStart := directoryEndOffset - int64(directorySize)
	defaultEntries, exceeded, err := scanZipCentralDirectory(archive, defaultStart, directoryEndOffset, maxEntries)
	if exceeded {
		return fmt.Errorf("zip archive exceeds maximum entry count of %d", maxEntries)
	}
	if err != nil {
		return err
	}

	// archive/zip may ignore its computed base offset when the raw metadata
	// offset begins with a valid directory header. Scan that possible path as
	// well, so even a signature-shaped malformed candidate cannot hide an
	// oversized default directory (or vice versa) from this preflight.
	baseOffset := uint64(directoryEndOffset) - directorySize - directoryOffset
	if baseOffset > 0 && directoryEndOffset >= 4 && directoryOffset <= uint64(directoryEndOffset-4) {
		var signature [4]byte
		if _, err := archive.ReadAt(signature[:], int64(directoryOffset)); err != nil {
			return fmt.Errorf("read zip central directory offset: %w", err)
		}
		if binary.LittleEndian.Uint32(signature[:]) == zipCentralHeaderSignature {
			// Go's raw-offset compatibility path reads to the end of the file,
			// not merely to the EOCD, so mirror that bound here.
			_, exceeded, _ := scanZipCentralDirectory(archive, int64(directoryOffset), archiveSize, maxEntries)
			if exceeded {
				return fmt.Errorf("zip archive exceeds maximum entry count of %d", maxEntries)
			}
		}
	}

	if defaultEntries != claimedEntries {
		return fmt.Errorf(
			"zip central directory entry count mismatch: metadata claims %d, found %d",
			claimedEntries,
			defaultEntries,
		)
	}
	return nil
}

func scanZipCentralDirectory(
	archive io.ReaderAt,
	start int64,
	directoryEndOffset int64,
	maxEntries int,
) (uint64, bool, error) {
	observedEntries := uint64(0)
	for cursor := start; cursor <= directoryEndOffset-4; {
		var signature [4]byte
		if _, err := archive.ReadAt(signature[:], cursor); err != nil {
			return observedEntries, false, fmt.Errorf("read zip central directory signature: %w", err)
		}
		if binary.LittleEndian.Uint32(signature[:]) != zipCentralHeaderSignature {
			break
		}
		if directoryEndOffset-cursor < zipCentralHeaderSize {
			return observedEntries, false, fmt.Errorf("zip central directory header is truncated")
		}

		var header [zipCentralHeaderSize]byte
		if _, err := archive.ReadAt(header[:], cursor); err != nil {
			return observedEntries, false, fmt.Errorf("read zip central directory header: %w", err)
		}
		variableSize := uint64(binary.LittleEndian.Uint16(header[28:30])) +
			uint64(binary.LittleEndian.Uint16(header[30:32])) +
			uint64(binary.LittleEndian.Uint16(header[32:34]))
		headerSize := uint64(zipCentralHeaderSize) + variableSize
		if headerSize > uint64(directoryEndOffset-cursor) {
			return observedEntries, false, fmt.Errorf("zip central directory header is out of bounds")
		}

		observedEntries++
		if observedEntries > uint64(maxEntries) {
			return observedEntries, true, nil
		}
		cursor += int64(headerSize)
	}
	return observedEntries, false, nil
}

func readZipDirectoryEnd(archive io.ReaderAt, archiveSize int64) ([]byte, int64, error) {
	if archiveSize < zipDirectoryEndSize {
		return nil, 0, fmt.Errorf("zip end of central directory is missing")
	}
	tailSize := int64(zipDirectoryEndSize + zipMaxCommentSize)
	if archiveSize < tailSize {
		tailSize = archiveSize
	}
	tail := make([]byte, int(tailSize))
	if _, err := archive.ReadAt(tail, archiveSize-tailSize); err != nil {
		return nil, 0, fmt.Errorf("read zip end of central directory: %w", err)
	}

	for index := len(tail) - zipDirectoryEndSize; index >= 0; index-- {
		if binary.LittleEndian.Uint32(tail[index:index+4]) != zipDirectoryEndSignature {
			continue
		}
		commentSize := int(binary.LittleEndian.Uint16(tail[index+20 : index+22]))
		if index+zipDirectoryEndSize+commentSize != len(tail) {
			continue
		}
		return tail[index : index+zipDirectoryEndSize], archiveSize - tailSize + int64(index), nil
	}
	return nil, 0, fmt.Errorf("zip end of central directory is missing or malformed")
}

func readZip64DirectoryEnd(archive io.ReaderAt, ordinaryEndOffset int64) (uint64, uint64, uint64, int64, error) {
	locatorOffset := ordinaryEndOffset - zip64LocatorSize
	if locatorOffset < 0 {
		return 0, 0, 0, 0, fmt.Errorf("zip64 locator is missing")
	}
	locator := make([]byte, zip64LocatorSize)
	if _, err := archive.ReadAt(locator, locatorOffset); err != nil {
		return 0, 0, 0, 0, fmt.Errorf("read zip64 locator: %w", err)
	}
	if binary.LittleEndian.Uint32(locator[0:4]) != zip64LocatorSignature {
		return 0, 0, 0, 0, fmt.Errorf("zip64 locator is missing")
	}
	if binary.LittleEndian.Uint32(locator[4:8]) != 0 || binary.LittleEndian.Uint32(locator[16:20]) != 1 {
		return 0, 0, 0, 0, fmt.Errorf("multi-disk zip64 archives are not supported")
	}

	recordOffset := binary.LittleEndian.Uint64(locator[8:16])
	if locatorOffset < zip64DirectoryEndSize || recordOffset > uint64(locatorOffset-zip64DirectoryEndSize) {
		return 0, 0, 0, 0, fmt.Errorf("zip64 end of central directory offset is out of bounds")
	}
	record := make([]byte, zip64DirectoryEndSize)
	if _, err := archive.ReadAt(record, int64(recordOffset)); err != nil {
		return 0, 0, 0, 0, fmt.Errorf("read zip64 end of central directory: %w", err)
	}
	if binary.LittleEndian.Uint32(record[0:4]) != zip64DirectoryEndSignature {
		return 0, 0, 0, 0, fmt.Errorf("zip64 end of central directory is missing")
	}
	recordBodySize := binary.LittleEndian.Uint64(record[4:12])
	if recordBodySize < zip64DirectoryEndSize-12 || recordBodySize > uint64(locatorOffset)-recordOffset-12 {
		return 0, 0, 0, 0, fmt.Errorf("zip64 end of central directory size is out of bounds")
	}
	if binary.LittleEndian.Uint32(record[16:20]) != 0 || binary.LittleEndian.Uint32(record[20:24]) != 0 {
		return 0, 0, 0, 0, fmt.Errorf("multi-disk zip64 archives are not supported")
	}
	entriesOnDisk := binary.LittleEndian.Uint64(record[24:32])
	totalEntries := binary.LittleEndian.Uint64(record[32:40])
	if entriesOnDisk != totalEntries {
		return 0, 0, 0, 0, fmt.Errorf("multi-disk zip64 archives are not supported")
	}
	return totalEntries,
		binary.LittleEndian.Uint64(record[40:48]),
		binary.LittleEndian.Uint64(record[48:56]),
		int64(recordOffset),
		nil
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
