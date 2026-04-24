package help

import "testing"

func TestUsageLine(t *testing.T) {
	if UsageLine() != usageLine {
		t.Fatalf("UsageLine() = %q, want %q", UsageLine(), usageLine)
	}
}

func TestGetHelp(t *testing.T) {
	want := `Usage: mailcheck [--version] | [--help] | [--selector name] [--advanced] [--details] [--dkim-deep] [--json] [--no-color] [--no-progress] [--timeout 30s] domain.example

Flags:
  --selector <name>   additional DKIM selector to try
  --json              render machine-readable JSON
  --no-color          disable ANSI color in text output
  --no-progress       disable interactive progress output
  --advanced          include mail DNS diagnostic checks
  --details           show raw DNS records and lookup details
  --verbose           alias for --details
  --dkim-deep         try the extended DKIM selector list
  --timeout <value>   total DNS lookup timeout (default 30s)
  --version, -v       print version and exit
  --help, -h          print help message and exit`

	if GetHelp() != want {
		t.Fatalf("GetHelp() = %q, want %q", GetHelp(), want)
	}
}
