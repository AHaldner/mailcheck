package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
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
