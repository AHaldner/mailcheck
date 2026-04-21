package ui

import (
	"bytes"
	"strings"
	"testing"
)

func TestProgressWriterReusesSingleLine(t *testing.T) {
	var buffer bytes.Buffer
	progress := &ProgressWriter{writer: &buffer, enabled: true}

	progress.Start("MX")
	progress.Start("SPF")
	progress.Finish()

	out := buffer.String()
	if strings.Count(out, "\n") != 1 {
		t.Fatalf("progress output should end with one newline, got:\n%q", out)
	}

	for _, part := range []string{"\r\x1b[2KChecking MX...", "\r\x1b[2KChecking SPF...", "\r\x1b[2K\n"} {
		if !strings.Contains(out, part) {
			t.Fatalf("progress output missing %q:\n%q", part, out)
		}
	}
}
