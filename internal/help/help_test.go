package help

import "testing"

func TestUsageLine(t *testing.T) {
	if UsageLine() != usageLine {
		t.Fatalf("UsageLine() = %q, want %q", UsageLine(), usageLine)
	}
}

func TestGetHelp(t *testing.T) {
	want := `Usage: mailcheck [--version] | [--help] | [--selector name] [--json] [--no-color] [--no-progress] [--timeout 3s] domain.example

Flags:
  --selector <name>   additional DKIM selector to try
  --json              render machine-readable JSON
  --no-color          disable ANSI color in text output
  --no-progress       disable interactive progress output
  --timeout <value>   total DNS lookup timeout (default 3s)
  --version, -v       print version and exit
  --help, -h          print help message and exit`

	if GetHelp() != want {
		t.Fatalf("GetHelp() = %q, want %q", GetHelp(), want)
	}
}
