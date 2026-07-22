package update

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
)

const (
	githubAcceptHeader            = "application/vnd.github+json"
	githubAPIVersionHeader        = "2022-11-28"
	maxLatestReleaseMetadataBytes = 1 << 20
)

// Release is the metadata needed to install a published release.
type Release struct {
	TagName string
	Assets  map[string]string
}

// ReleaseClient retrieves release metadata and assets.
type ReleaseClient struct {
	HTTP      *http.Client
	LatestURL string
	UserAgent string
}

// Latest retrieves and validates the latest GitHub release metadata.
func (c ReleaseClient) Latest(ctx context.Context) (Release, error) {
	if strings.TrimSpace(c.UserAgent) == "" {
		return Release{}, fmt.Errorf("release client UserAgent is required")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.LatestURL, nil)
	if err != nil {
		return Release{}, fmt.Errorf("create latest release request: %w", err)
	}
	request.Header.Set("Accept", githubAcceptHeader)
	request.Header.Set("X-GitHub-Api-Version", githubAPIVersionHeader)
	request.Header.Set("User-Agent", c.UserAgent)

	response, err := c.httpClient().Do(request)
	if err != nil {
		return Release{}, fmt.Errorf("request latest release: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return Release{}, fmt.Errorf("request latest release: unexpected HTTP status %s", response.Status)
	}

	var payload struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	metadata, err := io.ReadAll(io.LimitReader(response.Body, maxLatestReleaseMetadataBytes+1))
	if err != nil {
		return Release{}, fmt.Errorf("read latest release metadata: %w", err)
	}
	if len(metadata) > maxLatestReleaseMetadataBytes {
		return Release{}, fmt.Errorf("latest release metadata exceeds maximum size of %d bytes", maxLatestReleaseMetadataBytes)
	}
	if err := json.Unmarshal(metadata, &payload); err != nil {
		return Release{}, fmt.Errorf("decode latest release: %w", err)
	}
	if !StableVersion(payload.TagName) {
		return Release{}, fmt.Errorf("latest release has invalid tag %q", payload.TagName)
	}
	if len(payload.Assets) == 0 {
		return Release{}, fmt.Errorf("latest release has no assets")
	}

	release := Release{TagName: payload.TagName, Assets: make(map[string]string, len(payload.Assets))}
	for _, asset := range payload.Assets {
		if asset.Name == "" || asset.BrowserDownloadURL == "" {
			return Release{}, fmt.Errorf("latest release has asset with missing name or download URL")
		}
		if _, exists := release.Assets[asset.Name]; exists {
			return Release{}, fmt.Errorf("latest release has duplicate asset name %q", asset.Name)
		}
		release.Assets[asset.Name] = asset.BrowserDownloadURL
	}

	return release, nil
}

// Download retrieves url and rejects a response body larger than maxBytes.
func (c ReleaseClient) Download(ctx context.Context, url string, maxBytes int64) ([]byte, error) {
	var body bytes.Buffer
	if _, err := c.DownloadTo(ctx, url, maxBytes, &body); err != nil {
		return nil, err
	}
	return body.Bytes(), nil
}

// DownloadTo streams url into destination and rejects a response body larger
// than maxBytes.
func (c ReleaseClient) DownloadTo(ctx context.Context, url string, maxBytes int64, destination io.Writer) (int64, error) {
	if strings.TrimSpace(c.UserAgent) == "" {
		return 0, fmt.Errorf("release client UserAgent is required")
	}
	if maxBytes < 0 {
		return 0, fmt.Errorf("maxBytes must not be negative")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("create download request: %w", err)
	}
	request.Header.Set("User-Agent", c.UserAgent)

	response, err := c.httpClient().Do(request)
	if err != nil {
		return 0, fmt.Errorf("download: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return 0, fmt.Errorf("download: unexpected HTTP status %s", response.Status)
	}

	limit := maxBytes
	if maxBytes < math.MaxInt64 {
		limit++
	}
	written, err := io.Copy(destination, io.LimitReader(response.Body, limit))
	if err != nil {
		return written, fmt.Errorf("write download: %w", err)
	}
	if written > maxBytes {
		return written, fmt.Errorf("download exceeds maximum size of %d bytes", maxBytes)
	}

	return written, nil
}

func (c ReleaseClient) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}
