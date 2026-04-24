package ui

import (
	"bytes"
	"strings"
	"testing"
)

func TestProgressWriterRendersProgressBar(t *testing.T) {
	var buffer bytes.Buffer
	progress := &ProgressWriter{writer: &buffer, enabled: true, total: 4}

	progress.Start("MX")
	progress.Start("SPF")
	progress.Finish()

	out := buffer.String()
	if strings.Count(out, "\n") != 1 {
		t.Fatalf("progress output should end with one newline, got:\n%q", out)
	}

	for _, part := range []string{"\r\x1b[2K[#####---------------] 1/4 MX", "\r\x1b[2K[##########----------] 2/4 SPF", "\r\x1b[2K\n"} {
		if !strings.Contains(out, part) {
			t.Fatalf("progress output missing %q:\n%q", part, out)
		}
	}
}

func TestProgressWriterUsesOneStepWhenTotalMissing(t *testing.T) {
	var buffer bytes.Buffer
	progress := &ProgressWriter{writer: &buffer, enabled: true}

	progress.Start("MX")

	if !strings.Contains(buffer.String(), "[####################] 1/1 MX") {
		t.Fatalf("progress output = %q, want full single-step bar", buffer.String())
	}
}
