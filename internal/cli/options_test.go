package cli

import (
	"flag"
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

func TestParseArgsUsesLongerDefaultTimeout(t *testing.T) {
	got, err := ParseArgs([]string{"example.com"}, io.Discard)
	if err != nil {
		t.Fatalf("ParseArgs() error = %v", err)
	}

	if got.Timeout.Seconds() != 30 {
		t.Fatalf("Timeout = %v, want 30s", got.Timeout)
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

func TestParseArgsSupportsNoCache(t *testing.T) {
	got, err := ParseArgs([]string{"example.com", "--no-cache"}, io.Discard)
	if err != nil {
		t.Fatalf("ParseArgs() error = %v", err)
	}

	if !got.NoCache {
		t.Fatal("NoCache = false, want true")
	}
}

func TestRegisterFlagDefinitionsUsesDeclarativeBoolTarget(t *testing.T) {
	definitions := []flagDefinition{
		{
			help:        help.Flag{Names: []string{"json"}, Usage: "render machine-readable JSON", UsageMode: help.UsageOption},
			valueKind:   boolFlag,
			optionField: "JSON",
		},
	}
	var opts Options
	var selectors selectorFlags
	fs := flag.NewFlagSet("mailcheck", flag.ContinueOnError)

	registerFlagDefinitions(fs, &opts, &selectors, definitions)

	if err := fs.Parse([]string{"--json"}); err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !opts.JSON {
		t.Fatal("JSON = false, want true")
	}
}

func TestRegisterFlagDefinitionsUsesProvidedDefinitionsOnly(t *testing.T) {
	var opts Options
	var selectors selectorFlags
	fs := flag.NewFlagSet("mailcheck", flag.ContinueOnError)

	registerFlagDefinitions(fs, &opts, &selectors, nil)

	if err := fs.Parse([]string{"--json"}); err == nil {
		t.Fatal("Parse() error = nil, want unknown flag error")
	}
}

func TestHelpMatchesCurrentOutput(t *testing.T) {
	want := `Usage: mailcheck [--version] | [--help] | [--selector name] [--advanced] [--details] [--dkim-deep] [--json] [--no-cache] [--no-color] [--no-progress] [--timeout 30s] domain.example

Flags:
  --selector <name>   additional DKIM selector to try
  --json              render machine-readable JSON
  --no-cache          disable DNS lookup caching for the run
  --no-color          disable ANSI color in text output
  --no-progress       disable interactive progress output
  --advanced          include mail DNS diagnostic checks
  --details           show raw DNS records and lookup details
  --verbose           alias for --details
  --dkim-deep         try the extended DKIM selector list
  --timeout <value>   total DNS lookup timeout (default 30s)
  --version, -v       print version and exit
  --help, -h          print help message and exit`

	if Help() != want {
		t.Fatalf("Help() = %q, want %q", Help(), want)
	}
}

func TestParseArgsSupportsDeepDKIM(t *testing.T) {
	got, err := ParseArgs([]string{"example.com", "--dkim-deep"}, io.Discard)
	if err != nil {
		t.Fatalf("ParseArgs() error = %v", err)
	}

	if !got.DeepDKIM {
		t.Fatal("DeepDKIM = false, want true")
	}
}

func TestParseArgsSupportsAdvanced(t *testing.T) {
	got, err := ParseArgs([]string{"example.com", "--advanced"}, io.Discard)
	if err != nil {
		t.Fatalf("ParseArgs() error = %v", err)
	}

	if !got.Advanced {
		t.Fatal("Advanced = false, want true")
	}
}

func TestParseArgsSupportsDetailsAndVerbose(t *testing.T) {
	got, err := ParseArgs([]string{"example.com", "--details"}, io.Discard)
	if err != nil {
		t.Fatalf("ParseArgs() error = %v", err)
	}
	if !got.Details {
		t.Fatal("Details = false, want true")
	}

	got, err = ParseArgs([]string{"example.com", "--verbose"}, io.Discard)
	if err != nil {
		t.Fatalf("ParseArgs() error = %v", err)
	}
	if !got.Details {
		t.Fatal("Details = false for --verbose, want true")
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

	if strings.TrimSpace(stderr.String()) != Help() {
		t.Fatalf("stderr = %q, want %q", strings.TrimSpace(stderr.String()), Help())
	}
}
