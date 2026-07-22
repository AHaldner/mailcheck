package update

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestReleaseClientLatest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/latest" {
			t.Fatalf("request path = %q, want /latest", r.URL.Path)
		}
		if got := r.Header.Get("User-Agent"); got != "mailcheck/v1.2.3" {
			t.Fatalf("User-Agent = %q, want mailcheck/v1.2.3", got)
		}
		if got := r.Header.Get("Accept"); got != "application/vnd.github+json" {
			t.Fatalf("Accept = %q, want GitHub JSON media type", got)
		}
		if got := r.Header.Get("X-GitHub-Api-Version"); got != "2022-11-28" {
			t.Fatalf("X-GitHub-Api-Version = %q, want 2022-11-28", got)
		}

		fmt.Fprintf(w, `{"tag_name":"v1.2.3","assets":[{"name":"checksums.txt","browser_download_url":%q}]}`, serverURL(r))
	}))
	defer server.Close()

	client := ReleaseClient{
		HTTP:      server.Client(),
		LatestURL: server.URL + "/latest",
		UserAgent: "mailcheck/v1.2.3",
	}
	release, err := client.Latest(context.Background())
	if err != nil {
		t.Fatalf("Latest() error = %v", err)
	}
	if release.TagName != "v1.2.3" {
		t.Errorf("Latest().TagName = %q, want v1.2.3", release.TagName)
	}
	if got := release.Assets["checksums.txt"]; got != server.URL+"/checksums.txt" {
		t.Errorf("Latest().Assets[checksums.txt] = %q, want %q", got, server.URL+"/checksums.txt")
	}
}

func TestReleaseClientLatestAllowsBuildMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"tag_name":"v1.2.3+build-1","assets":[{"name":"checksums.txt","browser_download_url":%q}]}`, serverURL(r))
	}))
	defer server.Close()

	client := ReleaseClient{HTTP: server.Client(), LatestURL: server.URL, UserAgent: "mailcheck/test"}
	if _, err := client.Latest(context.Background()); err != nil {
		t.Fatalf("Latest() error = %v", err)
	}
}

func TestReleaseClientLatestRejectsInvalidResponse(t *testing.T) {
	tests := []struct {
		name string
		body string
		code int
	}{
		{name: "invalid tag", body: `{"tag_name":"latest","assets":[{"name":"checksums.txt","browser_download_url":"https://example.com/checksums.txt"}]}`, code: http.StatusOK},
		{name: "pre-release tag", body: `{"tag_name":"v1.2.3-rc.1","assets":[{"name":"checksums.txt","browser_download_url":"https://example.com/checksums.txt"}]}`, code: http.StatusOK},
		{name: "missing assets", body: `{"tag_name":"v1.2.3","assets":[]}`, code: http.StatusOK},
		{name: "empty asset name", body: `{"tag_name":"v1.2.3","assets":[{"name":"","browser_download_url":"https://example.com/checksums.txt"}]}`, code: http.StatusOK},
		{name: "empty asset URL", body: `{"tag_name":"v1.2.3","assets":[{"name":"checksums.txt","browser_download_url":""}]}`, code: http.StatusOK},
		{name: "duplicate asset name", body: `{"tag_name":"v1.2.3","assets":[{"name":"checksums.txt","browser_download_url":"https://example.com/a"},{"name":"checksums.txt","browser_download_url":"https://example.com/b"}]}`, code: http.StatusOK},
		{name: "non success status", body: `unavailable`, code: http.StatusServiceUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.code)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			client := ReleaseClient{HTTP: server.Client(), LatestURL: server.URL, UserAgent: "mailcheck/test"}
			if _, err := client.Latest(context.Background()); err == nil {
				t.Fatal("Latest() error = nil, want error")
			}
		})
	}
}

func TestReleaseClientDownload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); got != "mailcheck/v1.2.3" {
			t.Fatalf("User-Agent = %q, want mailcheck/v1.2.3", got)
		}

		switch r.URL.Path {
		case "/small":
			_, _ = w.Write([]byte("small"))
		case "/large":
			_, _ = w.Write([]byte("too large"))
		default:
			t.Fatalf("unexpected request path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	client := ReleaseClient{HTTP: server.Client(), UserAgent: "mailcheck/v1.2.3"}
	got, err := client.Download(context.Background(), server.URL+"/small", int64(len("small")))
	if err != nil {
		t.Fatalf("Download() error = %v", err)
	}
	if string(got) != "small" {
		t.Errorf("Download() = %q, want small", got)
	}

	got, err = client.Download(context.Background(), server.URL+"/small", math.MaxInt64)
	if err != nil {
		t.Fatalf("Download() with maximum limit error = %v", err)
	}
	if string(got) != "small" {
		t.Errorf("Download() with maximum limit = %q, want small", got)
	}

	if _, err := client.Download(context.Background(), server.URL+"/large", int64(len("small"))); err == nil {
		t.Fatal("Download() error = nil, want size error")
	}
}

func serverURL(r *http.Request) string {
	return "http://" + r.Host + "/checksums.txt"
}

func TestReleaseClientDownloadRejectsNonSuccessStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer server.Close()

	client := ReleaseClient{HTTP: server.Client(), UserAgent: "mailcheck/test"}
	if _, err := client.Download(context.Background(), server.URL, 1024); err == nil {
		t.Fatal("Download() error = nil, want error")
	}
}

func TestReleaseClientRejectsBlankUserAgentWithoutRequest(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch r.URL.Path {
		case "/latest":
			fmt.Fprintf(w, `{"tag_name":"v1.2.3","assets":[{"name":"checksums.txt","browser_download_url":%q}]}`, serverURL(r))
		case "/download":
			_, _ = w.Write([]byte("download"))
		default:
			t.Fatalf("unexpected request path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	tests := []struct {
		name string
		call func(ReleaseClient) error
	}{
		{
			name: "latest",
			call: func(client ReleaseClient) error {
				_, err := client.Latest(context.Background())
				return err
			},
		},
		{
			name: "download",
			call: func(client ReleaseClient) error {
				_, err := client.Download(context.Background(), server.URL+"/download", 1024)
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requests.Store(0)
			client := ReleaseClient{HTTP: server.Client(), LatestURL: server.URL + "/latest"}
			if err := tt.call(client); err == nil {
				t.Fatal("request with blank UserAgent error = nil, want error")
			}
			if got := requests.Load(); got != 0 {
				t.Fatalf("requests = %d, want 0", got)
			}
		})
	}
}
