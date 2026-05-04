package help

import "testing"

func TestFormatGeneratesCurrentHelpShapeFromFlags(t *testing.T) {
	flags := []Flag{
		{Names: []string{"selector"}, ValueName: "name", UsageValue: "name", Usage: "additional DKIM selector to try", UsageMode: UsageOption},
		{Names: []string{"json"}, Usage: "render machine-readable JSON", UsageMode: UsageOption},
		{Names: []string{"no-cache"}, Usage: "disable DNS lookup caching for the run", UsageMode: UsageOption},
		{Names: []string{"no-color"}, Usage: "disable ANSI color in text output", UsageMode: UsageOption},
		{Names: []string{"no-progress"}, Usage: "disable interactive progress output", UsageMode: UsageOption},
		{Names: []string{"advanced"}, Usage: "include mail DNS diagnostic checks", UsageMode: UsageOption},
		{Names: []string{"details"}, Usage: "show raw DNS records and lookup details", UsageMode: UsageOption},
		{Names: []string{"verbose"}, Usage: "alias for --details", UsageMode: UsageFlagListOnly},
		{Names: []string{"dkim-deep"}, Usage: "try the extended DKIM selector list", UsageMode: UsageOption},
		{Names: []string{"timeout"}, ValueName: "value", UsageValue: "30s", Default: "30s", Usage: "total DNS lookup timeout", UsageMode: UsageOption},
		{Names: []string{"version", "v"}, Usage: "print version and exit", UsageMode: UsageCommand},
		{Names: []string{"help", "h"}, Usage: "print help message and exit", UsageMode: UsageCommand},
	}

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

	if got := Format("mailcheck", "domain.example", flags); got != want {
		t.Fatalf("Format() = %q, want %q", got, want)
	}
}

func TestFormatIncludesNewFlagsWithoutChangingFormatter(t *testing.T) {
	flags := []Flag{
		{Names: []string{"json"}, Usage: "render machine-readable JSON", UsageMode: UsageOption},
		{Names: []string{"dry-run"}, Usage: "show planned checks without running them", UsageMode: UsageOption},
	}

	want := `Usage: mailcheck [--dry-run] [--json] domain.example

Flags:
  --json              render machine-readable JSON
  --dry-run           show planned checks without running them`

	if got := Format("mailcheck", "domain.example", flags); got != want {
		t.Fatalf("Format() = %q, want %q", got, want)
	}
}
