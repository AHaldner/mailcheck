package main

import (
	"os"
	"strings"
	"testing"

	appversion "github.com/AHaldner/mailcheck/internal/version"
)

func TestRunVersionPrintsVersion(t *testing.T) {
	oldValue := appversion.Value
	appversion.Value = "v1.2.3"
	defer func() { appversion.Value = oldValue }()

	stdoutFile, err := os.CreateTemp(t.TempDir(), "stdout-version")
	if err != nil {
		t.Fatalf("CreateTemp(stdout) error = %v", err)
	}
	defer stdoutFile.Close()

	stderrFile, err := os.CreateTemp(t.TempDir(), "stderr-version")
	if err != nil {
		t.Fatalf("CreateTemp(stderr) error = %v", err)
	}
	defer stderrFile.Close()

	code := run([]string{"--version"}, stdoutFile, stderrFile)
	if code != 0 {
		t.Fatalf("run() code = %d, want 0", code)
	}

	stdoutData, err := os.ReadFile(stdoutFile.Name())
	if err != nil {
		t.Fatalf("ReadFile(stdout) error = %v", err)
	}

	if strings.TrimSpace(string(stdoutData)) != "v1.2.3" {
		t.Fatalf("stdout = %q, want %q", strings.TrimSpace(string(stdoutData)), "v1.2.3")
	}
}

func TestRunDoesNotEmitProgressToNonTTYStderr(t *testing.T) {
	stdoutFile, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatalf("CreateTemp(stdout) error = %v", err)
	}
	defer stdoutFile.Close()

	stderrFile, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatalf("CreateTemp(stderr) error = %v", err)
	}
	defer stderrFile.Close()

	code := run([]string{"example.com"}, stdoutFile, stderrFile)
	if code != 1 {
		t.Fatalf("run() code = %d, want 1", code)
	}

	stderrData, err := os.ReadFile(stderrFile.Name())
	if err != nil {
		t.Fatalf("ReadFile(stderr) error = %v", err)
	}

	if strings.Contains(string(stderrData), "Checking MX") {
		t.Fatalf("stderr contained progress output:\n%s", string(stderrData))
	}
}

func TestRunJSONDoesNotEmitProgress(t *testing.T) {
	stdoutFile, err := os.CreateTemp(t.TempDir(), "stdout-json")
	if err != nil {
		t.Fatalf("CreateTemp(stdout) error = %v", err)
	}
	defer stdoutFile.Close()

	stderrFile, err := os.CreateTemp(t.TempDir(), "stderr-json")
	if err != nil {
		t.Fatalf("CreateTemp(stderr) error = %v", err)
	}
	defer stderrFile.Close()

	_ = run([]string{"example.com", "--json"}, stdoutFile, stderrFile)

	stderrData, err := os.ReadFile(stderrFile.Name())
	if err != nil {
		t.Fatalf("ReadFile(stderr) error = %v", err)
	}

	if strings.Contains(string(stderrData), "Checking ") {
		t.Fatalf("stderr contained progress output in json mode:\n%s", string(stderrData))
	}
}
