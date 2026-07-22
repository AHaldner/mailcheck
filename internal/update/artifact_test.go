package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

func TestAssetName(t *testing.T) {
	tests := []struct {
		goos   string
		goarch string
		want   string
	}{
		{goos: "darwin", goarch: "amd64", want: "mailcheck_1.2.3_darwin_amd64.tar.gz"},
		{goos: "darwin", goarch: "arm64", want: "mailcheck_1.2.3_darwin_arm64.tar.gz"},
		{goos: "linux", goarch: "amd64", want: "mailcheck_1.2.3_linux_amd64.tar.gz"},
		{goos: "linux", goarch: "arm64", want: "mailcheck_1.2.3_linux_arm64.tar.gz"},
		{goos: "windows", goarch: "amd64", want: "mailcheck_1.2.3_windows_amd64.zip"},
		{goos: "windows", goarch: "arm64", want: "mailcheck_1.2.3_windows_arm64.zip"},
	}

	for _, test := range tests {
		t.Run(test.goos+"/"+test.goarch, func(t *testing.T) {
			got, err := AssetName("v1.2.3", test.goos, test.goarch)
			if err != nil || got != test.want {
				t.Fatalf("AssetName() = %q, %v; want %q, nil", got, err, test.want)
			}
		})
	}
}

func TestAssetNameRejectsUnsupportedPlatformOrArchitecture(t *testing.T) {
	tests := []struct {
		goos      string
		goarch    string
		wantError string
	}{
		{goos: "freebsd", goarch: "amd64", wantError: "unsupported platform"},
		{goos: "linux", goarch: "386", wantError: "unsupported architecture"},
	}

	for _, test := range tests {
		t.Run(test.goos+"/"+test.goarch, func(t *testing.T) {
			_, err := AssetName("v1.2.3", test.goos, test.goarch)
			requireErrorContains(t, err, test.wantError)
		})
	}
}

func TestVerifyChecksum(t *testing.T) {
	archive := []byte("release archive")
	sum := sha256.Sum256(archive)
	checksums := []byte(fmt.Sprintf("%x\t  mailcheck_1.2.3_linux_amd64.tar.gz\n", sum))

	if err := VerifyChecksum("mailcheck_1.2.3_linux_amd64.tar.gz", archive, checksums); err != nil {
		t.Fatalf("VerifyChecksum() error = %v", err)
	}
}

func TestVerifyChecksumReader(t *testing.T) {
	const archive = "release archive streamed from disk"
	const name = "mailcheck_1.2.3_linux_amd64.tar.gz"
	sum := sha256.Sum256([]byte(archive))
	checksums := []byte(fmt.Sprintf("%x  %s\n", sum, name))

	if err := verifyChecksumReader(name, strings.NewReader(archive), checksums); err != nil {
		t.Fatalf("verifyChecksumReader() error = %v", err)
	}
}

func TestVerifyChecksumRejectsDuplicateEntry(t *testing.T) {
	const name = "mailcheck_1.2.3_linux_amd64.tar.gz"
	archive := []byte("release archive")
	sum := sha256.Sum256(archive)
	checksums := []byte(fmt.Sprintf("%x  %s\n%x  *%s\n", sum, name, sum, name))

	err := VerifyChecksum(name, archive, checksums)
	requireErrorContains(t, err, "duplicate checksum entry")
}

func TestVerifyChecksumRejectsInvalidChecksums(t *testing.T) {
	archive := []byte("release archive")
	sum := sha256.Sum256(archive)

	tests := []struct {
		name      string
		checksums string
	}{
		{name: "absent filename", checksums: fmt.Sprintf("%x  other.tar.gz\n", sum)},
		{name: "malformed hash", checksums: "not-a-sha256  mailcheck_1.2.3_linux_amd64.tar.gz\n"},
		{name: "malformed line", checksums: fmt.Sprintf("%x  mailcheck_1.2.3_linux_amd64.tar.gz extra\n", sum)},
		{name: "mismatched hash", checksums: fmt.Sprintf("%064x  mailcheck_1.2.3_linux_amd64.tar.gz\n", 0)},
		{name: "prefix filename does not match", checksums: fmt.Sprintf("%x  prefix-mailcheck_1.2.3_linux_amd64.tar.gz\n", sum)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := VerifyChecksum("mailcheck_1.2.3_linux_amd64.tar.gz", archive, []byte(test.checksums))
			if err == nil {
				t.Fatal("VerifyChecksum() error = nil, want error")
			}
		})
	}
}

func TestExtractExecutable(t *testing.T) {
	t.Run("tar.gz", func(t *testing.T) {
		archive := tarGz(t, archiveFile{name: "mailcheck", data: []byte("unix executable")})
		got, err := ExtractExecutable("mailcheck_1.2.3_linux_amd64.tar.gz", archive)
		if err != nil {
			t.Fatalf("ExtractExecutable() error = %v", err)
		}
		if want := []byte("unix executable"); !bytes.Equal(got, want) {
			t.Fatalf("ExtractExecutable() = %q, want %q", got, want)
		}
	})

	t.Run("zip", func(t *testing.T) {
		archive := zipFile(t, archiveFile{name: "mailcheck.exe", data: []byte("windows executable")})
		got, err := ExtractExecutable("mailcheck_1.2.3_windows_amd64.zip", archive)
		if err != nil {
			t.Fatalf("ExtractExecutable() error = %v", err)
		}
		if want := []byte("windows executable"); !bytes.Equal(got, want) {
			t.Fatalf("ExtractExecutable() = %q, want %q", got, want)
		}
	})
}

func TestExtractExecutableUsesExactEntryName(t *testing.T) {
	tests := []struct {
		name    string
		archive func(*testing.T, ...archiveFile) []byte
		files   []archiveFile
	}{
		{
			name:    "tar.gz",
			archive: tarGz,
			files: []archiveFile{
				{name: "../mailcheck", data: []byte("malicious")},
				{name: "mailcheck", data: []byte("trusted")},
			},
		},
		{
			name:    "zip",
			archive: zipFile,
			files: []archiveFile{
				{name: "../mailcheck.exe", data: []byte("malicious")},
				{name: "mailcheck.exe", data: []byte("trusted")},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			name := "mailcheck_1.2.3_linux_amd64.tar.gz"
			if test.name == "zip" {
				name = "mailcheck_1.2.3_windows_amd64.zip"
			}
			got, err := ExtractExecutable(name, test.archive(t, test.files...))
			if err != nil {
				t.Fatalf("ExtractExecutable() error = %v", err)
			}
			if want := []byte("trusted"); !bytes.Equal(got, want) {
				t.Fatalf("ExtractExecutable() = %q, want %q", got, want)
			}
		})
	}
}

func TestExtractExecutableRejectsInvalidArchives(t *testing.T) {
	tests := []struct {
		name    string
		asset   string
		archive []byte
		wantErr string
	}{
		{
			name:    "duplicate tar entries",
			asset:   "mailcheck_1.2.3_linux_amd64.tar.gz",
			archive: tarGz(t, archiveFile{name: "mailcheck", data: []byte("one")}, archiveFile{name: "mailcheck", data: []byte("two")}),
		},
		{
			name:    "duplicate zip entries",
			asset:   "mailcheck_1.2.3_windows_amd64.zip",
			archive: zipFile(t, archiveFile{name: "mailcheck.exe", data: []byte("one")}, archiveFile{name: "mailcheck.exe", data: []byte("two")}),
		},
		{
			name:    "empty executable",
			asset:   "mailcheck_1.2.3_linux_amd64.tar.gz",
			archive: tarGz(t, archiveFile{name: "mailcheck", data: nil}),
		},
		{
			name:    "oversized executable",
			asset:   "mailcheck_1.2.3_linux_amd64.tar.gz",
			archive: tarGz(t, archiveFile{name: "mailcheck", data: make([]byte, maxExecutableBytes+1)}),
		},
		{
			name:    "only traversal entry",
			asset:   "mailcheck_1.2.3_linux_amd64.tar.gz",
			archive: tarGz(t, archiveFile{name: "../mailcheck", data: []byte("malicious")}),
		},
		{
			name:    "unrelated entry",
			asset:   "mailcheck_1.2.3_linux_amd64.tar.gz",
			archive: tarGz(t, archiveFile{name: "README.md", data: []byte("not executable")}),
		},
		{
			name:    "unsupported extension",
			asset:   "mailcheck_1.2.3_linux_amd64.unknown",
			archive: []byte("not an archive"),
			wantErr: "unsupported archive extension",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ExtractExecutable(test.asset, test.archive)
			if test.wantErr != "" {
				requireErrorContains(t, err, test.wantErr)
				return
			}
			if err == nil {
				t.Fatal("ExtractExecutable() error = nil, want error")
			}
		})
	}
}

func TestExtractExecutableRejectsInvalidZipArchives(t *testing.T) {
	tests := []struct {
		name    string
		archive []byte
	}{
		{
			name:    "empty executable",
			archive: zipFile(t, archiveFile{name: "mailcheck.exe", data: nil}),
		},
		{
			name:    "oversized executable",
			archive: zipFile(t, archiveFile{name: "mailcheck.exe", data: make([]byte, maxExecutableBytes+1)}),
		},
		{
			name:    "only traversal entry",
			archive: zipFile(t, archiveFile{name: "../mailcheck.exe", data: []byte("malicious")}),
		},
		{
			name:    "unrelated entry",
			archive: zipFile(t, archiveFile{name: "README.md", data: []byte("not executable")}),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ExtractExecutable("mailcheck_1.2.3_windows_amd64.zip", test.archive); err == nil {
				t.Fatal("ExtractExecutable() error = nil, want error")
			}
		})
	}
}

func TestExtractExecutableAcceptsExecutableAtMaximumSize(t *testing.T) {
	archive := tarGz(t, archiveFile{name: "mailcheck", data: make([]byte, maxExecutableBytes)})

	got, err := ExtractExecutable("mailcheck_1.2.3_linux_amd64.tar.gz", archive)
	if err != nil {
		t.Fatalf("ExtractExecutable() error = %v", err)
	}
	if len(got) != maxExecutableBytes {
		t.Fatalf("len(ExtractExecutable()) = %d, want %d", len(got), maxExecutableBytes)
	}
}

func TestExtractExecutableRejectsOversizedArchive(t *testing.T) {
	archive := make([]byte, maxArchiveBytes+1)
	if _, err := ExtractExecutable("mailcheck_1.2.3_linux_amd64.tar.gz", archive); err == nil {
		t.Fatal("ExtractExecutable() error = nil, want error")
	}
}

func TestExtractExecutableToRejectsExcessIrrelevantTarData(t *testing.T) {
	archive := tarGz(t,
		archiveFile{name: "README.md", data: make([]byte, 2<<10)},
		archiveFile{name: "mailcheck", data: []byte("executable")},
	)
	var destination bytes.Buffer
	err := extractExecutableTo(
		"mailcheck_1.2.3_linux_amd64.tar.gz",
		bytes.NewReader(archive),
		int64(len(archive)),
		&destination,
		extractionLimits{
			maxArchiveBytes:         1 << 20,
			maxExecutableBytes:      1 << 10,
			maxDecompressedTarBytes: 1 << 10,
			maxTarLogicalEntries:    10,
		},
	)
	requireErrorContains(t, err, "tar archive exceeds maximum decompressed size")
}

func TestExtractExecutableToRejectsTooManyTarEntries(t *testing.T) {
	archive := tarGz(t,
		archiveFile{name: "mailcheck", data: []byte("executable")},
		archiveFile{name: "README.md", data: []byte("one")},
		archiveFile{name: "LICENSE", data: []byte("two")},
	)
	var destination bytes.Buffer
	err := extractExecutableTo(
		"mailcheck_1.2.3_linux_amd64.tar.gz",
		bytes.NewReader(archive),
		int64(len(archive)),
		&destination,
		extractionLimits{
			maxArchiveBytes:         1 << 20,
			maxExecutableBytes:      1 << 10,
			maxDecompressedTarBytes: 1 << 20,
			maxTarLogicalEntries:    2,
		},
	)
	requireErrorContains(t, err, "tar archive exceeds maximum logical entry count")
}

func TestExtractExecutableToRejectsTooManyZipEntries(t *testing.T) {
	archive := zipFile(t,
		archiveFile{name: "mailcheck.exe", data: []byte("executable")},
		archiveFile{name: "README.md", data: []byte("one")},
		archiveFile{name: "LICENSE", data: []byte("two")},
	)
	var destination bytes.Buffer
	err := extractExecutableTo(
		"mailcheck_1.2.3_windows_amd64.zip",
		bytes.NewReader(archive),
		int64(len(archive)),
		&destination,
		extractionLimits{
			maxArchiveBytes:         1 << 20,
			maxExecutableBytes:      1 << 10,
			maxDecompressedTarBytes: 1 << 20,
			maxZipEntries:           2,
		},
	)
	requireErrorContains(t, err, "zip archive exceeds maximum entry count")
}

func TestExtractExecutableToPreflightsOrdinaryZipEntryCountWithComment(t *testing.T) {
	archive := ordinaryZipEOCD(0xfffe, 0, 0, []byte("comment PK\x05\x06 inside"))
	var destination bytes.Buffer
	err := extractExecutableTo(
		"mailcheck_1.2.3_windows_amd64.zip",
		bytes.NewReader(archive),
		int64(len(archive)),
		&destination,
		testExtractionLimits(2),
	)
	requireErrorContains(t, err, "zip archive exceeds maximum entry count of 2")
}

func TestExtractExecutableToPreflightsZip64EntryCount(t *testing.T) {
	archive := zip64EOCD(1<<63, 0)
	var destination bytes.Buffer
	err := extractExecutableTo(
		"mailcheck_1.2.3_windows_amd64.zip",
		bytes.NewReader(archive),
		int64(len(archive)),
		&destination,
		testExtractionLimits(2),
	)
	requireErrorContains(t, err, "zip archive exceeds maximum entry count of 2")
}

func TestExtractExecutableToPreflightsUnderstatedOrdinaryZipEntryCount(t *testing.T) {
	archive := understatedOrdinaryZipDirectory(3, 1)
	var destination bytes.Buffer
	err := extractExecutableTo(
		"mailcheck_1.2.3_windows_amd64.zip",
		bytes.NewReader(archive),
		int64(len(archive)),
		&destination,
		testExtractionLimits(2),
	)
	requireErrorContains(t, err, "zip archive exceeds maximum entry count of 2")
}

func TestExtractExecutableToPreflightsGoRawDirectoryOffsetFallback(t *testing.T) {
	directory := repeatedZipCentralDirectoryHeaders(3)
	archive := append(directory, ordinaryZipEOCD(1, 46, 0, nil)...)
	var destination bytes.Buffer
	err := extractExecutableTo(
		"mailcheck_1.2.3_windows_amd64.zip",
		bytes.NewReader(archive),
		int64(len(archive)),
		&destination,
		testExtractionLimits(2),
	)
	requireErrorContains(t, err, "zip archive exceeds maximum entry count of 2")
}

func TestExtractExecutableToPreflightsInvalidRawDirectoryFallbackCandidate(t *testing.T) {
	archive := invalidRawFallbackZipDirectory(3, 1)
	var destination bytes.Buffer
	err := extractExecutableTo(
		"mailcheck_1.2.3_windows_amd64.zip",
		bytes.NewReader(archive),
		int64(len(archive)),
		&destination,
		testExtractionLimits(2),
	)
	requireErrorContains(t, err, "zip archive exceeds maximum entry count of 2")
}

func TestExtractExecutableToPreflightsUnderstatedZip64EntryCount(t *testing.T) {
	archive := understatedZip64Directory(3, 1)
	var destination bytes.Buffer
	err := extractExecutableTo(
		"mailcheck_1.2.3_windows_amd64.zip",
		bytes.NewReader(archive),
		int64(len(archive)),
		&destination,
		testExtractionLimits(2),
	)
	requireErrorContains(t, err, "zip archive exceeds maximum entry count of 2")
}

func TestExtractExecutableToRejectsZipEntryCountMismatch(t *testing.T) {
	archive := understatedOrdinaryZipDirectory(2, 1)
	var destination bytes.Buffer
	err := extractExecutableTo(
		"mailcheck_1.2.3_windows_amd64.zip",
		bytes.NewReader(archive),
		int64(len(archive)),
		&destination,
		testExtractionLimits(3),
	)
	requireErrorContains(t, err, "zip central directory entry count mismatch")
}

func TestExtractExecutableAcceptsZip64DirectoryMetadata(t *testing.T) {
	archive := promoteZipToZip64(t, zipFile(t, archiveFile{name: "mailcheck.exe", data: []byte("executable")}))

	got, err := ExtractExecutable("mailcheck_1.2.3_windows_amd64.zip", archive)
	if err != nil {
		t.Fatalf("ExtractExecutable() error = %v", err)
	}
	if string(got) != "executable" {
		t.Fatalf("ExtractExecutable() = %q, want executable", got)
	}
}

func TestExtractExecutableToRejectsMalformedZipDirectoryMetadata(t *testing.T) {
	tests := []struct {
		name    string
		archive []byte
		want    string
	}{
		{
			name:    "ordinary central directory out of bounds",
			archive: ordinaryZipEOCD(1, 8, 999, nil),
			want:    "zip central directory is out of bounds",
		},
		{
			name:    "Zip64 locator missing",
			archive: ordinaryZipEOCD(0xffff, 0xffffffff, 0xffffffff, nil),
			want:    "zip64 locator is missing",
		},
		{
			name:    "Zip64 record offset out of bounds",
			archive: zip64EOCD(1, 1<<32),
			want:    "zip64 end of central directory offset is out of bounds",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var destination bytes.Buffer
			err := extractExecutableTo(
				"mailcheck_1.2.3_windows_amd64.zip",
				bytes.NewReader(tt.archive),
				int64(len(tt.archive)),
				&destination,
				testExtractionLimits(2),
			)
			requireErrorContains(t, err, tt.want)
		})
	}
}

func requireErrorContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want error containing %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want substring %q", err, want)
	}
}

type archiveFile struct {
	name string
	data []byte
}

func testExtractionLimits(maxEntries int) extractionLimits {
	return extractionLimits{
		maxArchiveBytes:         1 << 20,
		maxExecutableBytes:      1 << 10,
		maxDecompressedTarBytes: 1 << 20,
		maxTarLogicalEntries:    maxEntries,
		maxZipEntries:           maxEntries,
	}
}

func ordinaryZipEOCD(totalEntries uint16, directorySize, directoryOffset uint32, comment []byte) []byte {
	record := make([]byte, 22+len(comment))
	binary.LittleEndian.PutUint32(record[0:4], 0x06054b50)
	binary.LittleEndian.PutUint16(record[8:10], totalEntries)
	binary.LittleEndian.PutUint16(record[10:12], totalEntries)
	binary.LittleEndian.PutUint32(record[12:16], directorySize)
	binary.LittleEndian.PutUint32(record[16:20], directoryOffset)
	binary.LittleEndian.PutUint16(record[20:22], uint16(len(comment)))
	copy(record[22:], comment)
	return record
}

func zip64EOCD(totalEntries, locatorOffset uint64) []byte {
	record := make([]byte, 56+20)
	binary.LittleEndian.PutUint32(record[0:4], 0x06064b50)
	binary.LittleEndian.PutUint64(record[4:12], 44)
	binary.LittleEndian.PutUint16(record[12:14], 45)
	binary.LittleEndian.PutUint16(record[14:16], 45)
	binary.LittleEndian.PutUint64(record[24:32], totalEntries)
	binary.LittleEndian.PutUint64(record[32:40], totalEntries)

	locator := record[56:]
	binary.LittleEndian.PutUint32(locator[0:4], 0x07064b50)
	binary.LittleEndian.PutUint64(locator[8:16], locatorOffset)
	binary.LittleEndian.PutUint32(locator[16:20], 1)

	eocd := ordinaryZipEOCD(0xffff, 0xffffffff, 0xffffffff, nil)
	return append(record, eocd...)
}

func promoteZipToZip64(t *testing.T, archive []byte) []byte {
	t.Helper()
	if len(archive) < 22 {
		t.Fatal("ordinary zip is too small")
	}
	eocdOffset := len(archive) - 22
	eocd := archive[eocdOffset:]
	if binary.LittleEndian.Uint32(eocd[0:4]) != zipDirectoryEndSignature {
		t.Fatal("ordinary zip EOCD signature not found")
	}
	totalEntries := uint64(binary.LittleEndian.Uint16(eocd[10:12]))
	directorySize := uint64(binary.LittleEndian.Uint32(eocd[12:16]))
	directoryOffset := uint64(binary.LittleEndian.Uint32(eocd[16:20]))

	recordAndLocator := zip64EOCD(totalEntries, uint64(eocdOffset))
	record := recordAndLocator[:56]
	binary.LittleEndian.PutUint64(record[40:48], directorySize)
	binary.LittleEndian.PutUint64(record[48:56], directoryOffset)

	result := append([]byte(nil), archive[:eocdOffset]...)
	result = append(result, recordAndLocator...)
	return result
}

func understatedOrdinaryZipDirectory(actualEntries int, claimedEntries uint16) []byte {
	directory := repeatedZipCentralDirectoryHeaders(actualEntries)
	return append(directory, ordinaryZipEOCD(claimedEntries, uint32(len(directory)), 0, nil)...)
}

func understatedZip64Directory(actualEntries int, claimedEntries uint64) []byte {
	directory := repeatedZipCentralDirectoryHeaders(actualEntries)
	metadata := zip64EOCD(claimedEntries, uint64(len(directory)))
	binary.LittleEndian.PutUint64(metadata[40:48], uint64(len(directory)))
	return append(directory, metadata...)
}

func repeatedZipCentralDirectoryHeaders(count int) []byte {
	directory := make([]byte, count*46)
	for index := range count {
		binary.LittleEndian.PutUint32(directory[index*46:index*46+4], 0x02014b50)
	}
	return directory
}

func invalidRawFallbackZipDirectory(actualEntries int, claimedEntries uint16) []byte {
	fakeRawHeader := repeatedZipCentralDirectoryHeaders(1)
	binary.LittleEndian.PutUint32(fakeRawHeader[20:24], 0xffffffff)
	prefix := append(fakeRawHeader, []byte("JUNK")...)
	directory := repeatedZipCentralDirectoryHeaders(actualEntries)
	archive := append(prefix, directory...)
	return append(archive, ordinaryZipEOCD(claimedEntries, uint32(len(directory)), 0, nil)...)
}

func tarGz(t *testing.T, files ...archiveFile) []byte {
	t.Helper()

	var output bytes.Buffer
	gzipWriter := gzip.NewWriter(&output)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, file := range files {
		if err := tarWriter.WriteHeader(&tar.Header{Name: file.name, Mode: 0o755, Size: int64(len(file.data))}); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if _, err := tarWriter.Write(file.data); err != nil {
			t.Fatalf("write tar file: %v", err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	return output.Bytes()
}

func zipFile(t *testing.T, files ...archiveFile) []byte {
	t.Helper()

	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for _, file := range files {
		entry, err := writer.Create(file.name)
		if err != nil {
			t.Fatalf("create zip entry: %v", err)
		}
		if _, err := entry.Write(file.data); err != nil {
			t.Fatalf("write zip entry: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
	return output.Bytes()
}
