package help

import "strings"

const usageLine = "Usage: mailcheck [--version] | [--help] | [--selector name] [--json] [--no-color] [--no-progress] [--timeout 3s] domain.example"

func UsageLine() string {
	return usageLine
}

func GetHelp() string {
	lines := []string{
		usageLine,
		"",
		"Flags:",
		"  --selector <name>   additional DKIM selector to try",
		"  --json              render machine-readable JSON",
		"  --no-color          disable ANSI color in text output",
		"  --no-progress       disable interactive progress output",
		"  --timeout <value>   total DNS lookup timeout (default 3s)",
		"  --version, -v       print version and exit",
		"  --help, -h          print help message and exit",
	}

	return strings.Join(lines, "\n")
}
