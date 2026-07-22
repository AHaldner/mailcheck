package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestUpgraderConstructorUsesProductionDefaults(t *testing.T) {
	upgrader := NewUpgrader("v1.2.3")

	if upgrader.Client.HTTP == nil || upgrader.Client.HTTP.Timeout != 2*time.Second {
		t.Fatalf("HTTP client = %#v, want 2s timeout", upgrader.Client.HTTP)
	}
	if upgrader.Client.LatestURL != "https://api.github.com/repos/AHaldner/mailcheck/releases/latest" {
		t.Fatalf("LatestURL = %q, want fixed GitHub latest-release URL", upgrader.Client.LatestURL)
	}
	if upgrader.Client.UserAgent != "mailcheck/v1.2.3" {
		t.Fatalf("UserAgent = %q, want mailcheck/v1.2.3", upgrader.Client.UserAgent)
	}
	if upgrader.GOOS != runtime.GOOS || upgrader.GOARCH != runtime.GOARCH {
		t.Fatalf("platform = %s/%s, want %s/%s", upgrader.GOOS, upgrader.GOARCH, runtime.GOOS, runtime.GOARCH)
	}
	if upgrader.DownloadArchive == nil || upgrader.ExecutablePath == nil || upgrader.Replace == nil {
		t.Fatal("production executable path and replacement functions must be configured")
	}
}

func TestUpgraderRejectsInvalidCurrentVersionBeforeRequest(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()

	replaced := false
	upgrader := testUpgrader(server, func(string, io.Reader) error {
		replaced = true
		return nil
	})

	_, err := upgrader.Upgrade(context.Background(), "dev")
	requireErrorContains(t, err, "tagged release build")
	if got := requests.Load(); got != 0 {
		t.Fatalf("HTTP requests = %d, want 0", got)
	}
	if replaced {
		t.Fatal("Replace() called for invalid current version")
	}
}

func TestUpgraderRejectsNonStableCurrentVersionBeforeAnyWork(t *testing.T) {
	archive := upgraderTarGz(t, []byte("new executable"))
	sum := sha256.Sum256(archive)
	checksums := []byte(fmt.Sprintf("%x  mailcheck_1.3.0_linux_amd64.tar.gz\n", sum))

	for _, currentVersion := range []string{"v1.3.0-rc.1", "v1.3.0-12-gabcdef-dirty"} {
		t.Run(currentVersion, func(t *testing.T) {
			var requests atomic.Int32
			client := ReleaseClient{
				HTTP:      &http.Client{},
				LatestURL: "https://example.com/latest",
				UserAgent: "mailcheck/test",
			}
			client.HTTP.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
				requests.Add(1)
				var body []byte
				switch request.URL.Path {
				case "/latest":
					body = []byte(`{"tag_name":"v1.3.0","assets":[{"name":"mailcheck_1.3.0_linux_amd64.tar.gz","browser_download_url":"https://example.com/archive"},{"name":"checksums.txt","browser_download_url":"https://example.com/checksums.txt"}]}`)
				case "/archive":
					body = archive
				case "/checksums.txt":
					body = checksums
				default:
					t.Fatalf("unexpected request path %q", request.URL.Path)
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Status:     "200 OK",
					Header:     make(http.Header),
					Body:       io.NopCloser(bytes.NewReader(body)),
					Request:    request,
				}, nil
			})
			upgrader := Upgrader{
				Client: client,
				GOOS:   "linux",
				GOARCH: "amd64",
				ExecutablePath: func() (string, error) {
					t.Error("ExecutablePath() called for non-stable current version")
					return "/tmp/mailcheck", nil
				},
				Replace: func(string, io.Reader) error {
					t.Error("Replace() called for non-stable current version")
					return nil
				},
			}

			_, err := upgrader.Upgrade(context.Background(), currentVersion)
			if got := requests.Load(); got != 0 {
				t.Errorf("HTTP requests = %d, want 0", got)
			}
			requireErrorContains(t, err, "tagged release build")
		})
	}
}

func TestUpgraderDoesNotDownloadOrReplaceWhenCurrentIsEqualOrNewer(t *testing.T) {
	tests := []struct {
		name    string
		current string
		latest  string
	}{
		{name: "equal", current: "v1.3.0", latest: "v1.3.0"},
		{name: "newer", current: "v2.0.0", latest: "v1.3.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var downloads atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/latest":
					fmt.Fprintf(w, `{"tag_name":%q,"assets":[{"name":"checksums.txt","browser_download_url":%q}]}`, tt.latest, requestURL(r, "/checksums.txt"))
				default:
					downloads.Add(1)
					http.Error(w, "unexpected download", http.StatusInternalServerError)
				}
			}))
			defer server.Close()

			replaced := false
			upgrader := testUpgrader(server, func(string, io.Reader) error {
				replaced = true
				return nil
			})
			upgrader.ExecutablePath = func() (string, error) {
				t.Fatal("ExecutablePath() called for unchanged version")
				return "", nil
			}

			result, err := upgrader.Upgrade(context.Background(), tt.current)
			if err != nil {
				t.Fatalf("Upgrade() error = %v", err)
			}
			want := Result{From: tt.current, To: tt.current, Changed: false}
			if result != want {
				t.Fatalf("Upgrade() = %#v, want %#v", result, want)
			}
			if got := downloads.Load(); got != 0 {
				t.Fatalf("asset downloads = %d, want 0", got)
			}
			if replaced {
				t.Fatal("Replace() called for unchanged version")
			}
		})
	}
}

func TestUpgraderRequiresArchiveAndChecksumsAssets(t *testing.T) {
	const archiveName = "mailcheck_1.3.0_linux_amd64.tar.gz"
	tests := []struct {
		name      string
		assetName string
		missing   string
	}{
		{name: "archive", assetName: "checksums.txt", missing: archiveName},
		{name: "checksums", assetName: archiveName, missing: "checksums.txt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var downloads atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/latest" {
					downloads.Add(1)
					http.Error(w, "unexpected download", http.StatusInternalServerError)
					return
				}
				fmt.Fprintf(w, `{"tag_name":"v1.3.0","assets":[{"name":%q,"browser_download_url":%q}]}`, tt.assetName, requestURL(r, "/asset"))
			}))
			defer server.Close()

			replaced := false
			upgrader := testUpgrader(server, func(string, io.Reader) error {
				replaced = true
				return nil
			})

			_, err := upgrader.Upgrade(context.Background(), "v1.2.3")
			requireErrorContains(t, err, tt.missing)
			if got := downloads.Load(); got != 0 {
				t.Fatalf("asset downloads = %d, want 0", got)
			}
			if replaced {
				t.Fatal("Replace() called with a required asset missing")
			}
		})
	}
}

func TestUpgraderDoesNotReplaceOnChecksumFailure(t *testing.T) {
	archive := upgraderTarGz(t, []byte("new executable"))
	server := upgraderServer(t, archive, []byte(strings.Repeat("0", 64)+"  mailcheck_1.3.0_linux_amd64.tar.gz\n"))

	replaced := false
	upgrader := testUpgrader(server, func(string, io.Reader) error {
		replaced = true
		return nil
	})
	upgrader.ExecutablePath = func() (string, error) {
		t.Fatal("ExecutablePath() called before checksum verification succeeded")
		return "", nil
	}

	_, err := upgrader.Upgrade(context.Background(), "v1.2.3")
	requireErrorContains(t, err, "checksum mismatch")
	if replaced {
		t.Fatal("Replace() called after checksum failure")
	}
}

func TestUpgraderInstallsVerifiedNewerRelease(t *testing.T) {
	executable := []byte("new executable")
	archive := upgraderTarGz(t, executable)
	sum := sha256.Sum256(archive)
	checksums := []byte(fmt.Sprintf("%x  mailcheck_1.3.0_linux_amd64.tar.gz\n", sum))
	server := upgraderServer(t, archive, checksums)

	var gotPath string
	var gotExecutable []byte
	upgrader := testUpgrader(server, func(path string, source io.Reader) error {
		gotPath = path
		var err error
		gotExecutable, err = io.ReadAll(source)
		return err
	})

	result, err := upgrader.Upgrade(context.Background(), "v1.2.3")
	if err != nil {
		t.Fatalf("Upgrade() error = %v", err)
	}
	if want := (Result{From: "v1.2.3", To: "v1.3.0", Changed: true}); result != want {
		t.Fatalf("Upgrade() = %#v, want %#v", result, want)
	}
	if gotPath != "/tmp/mailcheck" {
		t.Fatalf("Replace() path = %q, want /tmp/mailcheck", gotPath)
	}
	if !bytes.Equal(gotExecutable, executable) {
		t.Fatalf("Replace() binary = %q, want %q", gotExecutable, executable)
	}
}

func TestUpgraderStreamsThroughTemporaryFilesAndCleansThem(t *testing.T) {
	validArchive := upgraderTarGz(t, []byte("new executable"))
	invalidArchive := []byte("not a tar.gz archive")
	replacementErr := errors.New("injected replacement failure")

	tests := []struct {
		name       string
		archive    []byte
		checksumOK bool
		replaceErr error
		wantErr    string
	}{
		{name: "success", archive: validArchive, checksumOK: true},
		{name: "checksum failure", archive: validArchive, wantErr: "checksum mismatch"},
		{name: "extraction failure", archive: invalidArchive, checksumOK: true, wantErr: "open tar.gz archive"},
		{name: "replacement failure", archive: validArchive, checksumOK: true, replaceErr: replacementErr, wantErr: "replacement failure"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDirectory := t.TempDir()
			sum := sha256.Sum256(tt.archive)
			if !tt.checksumOK {
				sum = sha256.Sum256([]byte("different archive"))
			}
			checksums := []byte(fmt.Sprintf("%x  mailcheck_1.3.0_linux_amd64.tar.gz\n", sum))
			server := upgraderServer(t, tt.archive, checksums)

			downloadCalls := 0
			replaceCalls := 0
			upgrader := Upgrader{
				Client: ReleaseClient{
					HTTP:      server.Client(),
					LatestURL: server.URL + "/latest",
					UserAgent: "mailcheck/test",
				},
				GOOS:    "linux",
				GOARCH:  "amd64",
				TempDir: tempDirectory,
				DownloadArchive: func(_ context.Context, _ string, limit int64, destination io.Writer) (int64, error) {
					downloadCalls++
					if limit != maxArchiveBytes {
						t.Errorf("archive limit = %d, want %d", limit, maxArchiveBytes)
					}
					file, ok := destination.(*os.File)
					if !ok {
						t.Errorf("archive destination = %T, want *os.File", destination)
					} else if filepath.Dir(file.Name()) != tempDirectory {
						t.Errorf("archive temporary directory = %q, want %q", filepath.Dir(file.Name()), tempDirectory)
					}
					return io.Copy(destination, bytes.NewReader(tt.archive))
				},
				ExecutablePath: func() (string, error) { return "/tmp/mailcheck", nil },
				Replace: func(path string, source io.Reader) error {
					replaceCalls++
					if path != "/tmp/mailcheck" {
						t.Errorf("replacement path = %q, want /tmp/mailcheck", path)
					}
					file, ok := source.(*os.File)
					if !ok {
						t.Errorf("replacement source = %T, want *os.File", source)
					} else if filepath.Dir(file.Name()) != tempDirectory {
						t.Errorf("executable temporary directory = %q, want %q", filepath.Dir(file.Name()), tempDirectory)
					}
					got, err := io.ReadAll(source)
					if err != nil {
						return err
					}
					if !bytes.Equal(got, []byte("new executable")) {
						t.Errorf("replacement source = %q, want new executable", got)
					}
					return tt.replaceErr
				},
			}

			_, err := upgrader.Upgrade(context.Background(), "v1.2.3")
			if tt.wantErr == "" && err != nil {
				t.Fatalf("Upgrade() error = %v", err)
			}
			if tt.wantErr != "" {
				requireErrorContains(t, err, tt.wantErr)
			}
			if downloadCalls != 1 {
				t.Fatalf("streaming archive downloads = %d, want 1", downloadCalls)
			}
			wantReplaceCalls := 0
			if tt.name == "success" || tt.name == "replacement failure" {
				wantReplaceCalls = 1
			}
			if replaceCalls != wantReplaceCalls {
				t.Fatalf("replacement calls = %d, want %d", replaceCalls, wantReplaceCalls)
			}
			entries, readErr := os.ReadDir(tempDirectory)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if len(entries) != 0 {
				t.Fatalf("temporary artifacts remain: %v", entries)
			}
		})
	}
}

func testUpgrader(server *httptest.Server, replace func(string, io.Reader) error) Upgrader {
	return Upgrader{
		Client: ReleaseClient{
			HTTP:      server.Client(),
			LatestURL: server.URL + "/latest",
			UserAgent: "mailcheck/test",
		},
		GOOS:           "linux",
		GOARCH:         "amd64",
		ExecutablePath: func() (string, error) { return "/tmp/mailcheck", nil },
		Replace:        replace,
	}
}

func upgraderServer(t *testing.T, archive, checksums []byte) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest":
			fmt.Fprintf(w, `{"tag_name":"v1.3.0","assets":[{"name":"mailcheck_1.3.0_linux_amd64.tar.gz","browser_download_url":%q},{"name":"checksums.txt","browser_download_url":%q}]}`, requestURL(r, "/archive"), requestURL(r, "/checksums.txt"))
		case "/archive":
			_, _ = w.Write(archive)
		case "/checksums.txt":
			_, _ = w.Write(checksums)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func requestURL(r *http.Request, path string) string {
	return "http://" + r.Host + path
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func upgraderTarGz(t *testing.T, executable []byte) []byte {
	t.Helper()

	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := tarWriter.WriteHeader(&tar.Header{Name: "mailcheck", Mode: 0o755, Size: int64(len(executable))}); err != nil {
		t.Fatalf("WriteHeader() error = %v", err)
	}
	if _, err := tarWriter.Write(executable); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("tar Close() error = %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("gzip Close() error = %v", err)
	}
	return buffer.Bytes()
}
