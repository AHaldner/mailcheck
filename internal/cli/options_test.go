package cli

import (
	"io"
	"strings"
	"testing"

	"github.com/AHaldner/mailcheck/internal/help"
)

func TestBuildSelectorsDeduplicatesExplicitSelectors(t *testing.T) {
	got := BuildSelectors([]string{"Google", "custom", "google", "custom"})
	want := []string{"google", "custom"}

	if len(got) != len(want) {
		t.Fatalf("len(got) = %d, want %d", len(got), len(want))
	}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestValidateDomainRejectsEmpty(t *testing.T) {
	if err := ValidateDomain(""); err == nil {
		t.Fatal("ValidateDomain() error = nil, want error")
	}
}

func TestParseArgsAllowsDomainBeforeFlags(t *testing.T) {
	got, err := ParseArgs([]string{"example.com", "--json", "--timeout", "5s"}, io.Discard)
	if err != nil {
		t.Fatalf("ParseArgs() error = %v", err)
	}

	if got.Domain != "example.com" {
		t.Fatalf("Domain = %q, want %q", got.Domain, "example.com")
	}

	if !got.JSON {
		t.Fatal("JSON = false, want true")
	}

	if got.Timeout.Seconds() != 5 {
		t.Fatalf("Timeout = %v, want 5s", got.Timeout)
	}
}

func TestParseArgsSupportsNoProgress(t *testing.T) {
	got, err := ParseArgs([]string{"example.com", "--no-progress"}, io.Discard)
	if err != nil {
		t.Fatalf("ParseArgs() error = %v", err)
	}

	if !got.NoProgress {
		t.Fatal("NoProgress = false, want true")
	}
}

func TestParseArgsSupportsVersionWithoutDomain(t *testing.T) {
	got, err := ParseArgs([]string{"--version"}, io.Discard)
	if err != nil {
		t.Fatalf("ParseArgs() error = %v", err)
	}

	if !got.Version {
		t.Fatal("Version = false, want true")
	}
}

func TestParseArgsSupportsShortVersionWithoutDomain(t *testing.T) {
	got, err := ParseArgs([]string{"-v"}, io.Discard)
	if err != nil {
		t.Fatalf("ParseArgs() error = %v", err)
	}

	if !got.Version {
		t.Fatal("Version = false, want true")
	}
}

func TestParseArgsSupportsHelpWithoutDomain(t *testing.T) {
	got, err := ParseArgs([]string{"--help"}, io.Discard)
	if err != nil {
		t.Fatalf("ParseArgs() error = %v", err)
	}

	if !got.Help {
		t.Fatal("Help = false, want true")
	}
}

func TestParseArgsRejectsHelpWithDomain(t *testing.T) {
	_, err := ParseArgs([]string{"--help", "example.com"}, io.Discard)
	if err == nil {
		t.Fatal("ParseArgs() error = nil, want error")
	}

	if err.Error() != "--help does not accept a domain argument" {
		t.Fatalf("ParseArgs() error = %q, want %q", err.Error(), "--help does not accept a domain argument")
	}
}

func TestParseArgsSupportsShortHelpWithoutDomain(t *testing.T) {
	got, err := ParseArgs([]string{"-h"}, io.Discard)
	if err != nil {
		t.Fatalf("ParseArgs() error = %v", err)
	}

	if !got.Help {
		t.Fatal("Help = false, want true")
	}
}

func TestParseArgsRejectsHelpWithDomainPrintsConsistentUsage(t *testing.T) {
	var stderr strings.Builder

	_, err := ParseArgs([]string{"--help", "example.com"}, &stderr)
	if err == nil {
		t.Fatal("ParseArgs() error = nil, want error")
	}

	if err.Error() != "--help does not accept a domain argument" {
		t.Fatalf("ParseArgs() error = %q, want %q", err.Error(), "--help does not accept a domain argument")
	}

	if strings.TrimSpace(stderr.String()) != help.GetHelp() {
		t.Fatalf("stderr = %q, want %q", strings.TrimSpace(stderr.String()), help.GetHelp())
	}
}
