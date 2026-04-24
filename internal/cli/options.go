package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/AHaldner/mailcheck/internal/help"
)

const DefaultTimeout = 30 * time.Second

type Options struct {
	Domain     string
	Selectors  []string
	JSON       bool
	NoColor    bool
	NoProgress bool
	Advanced   bool
	Details    bool
	DeepDKIM   bool
	Version    bool
	Help       bool
	Timeout    time.Duration
}

type selectorFlags []string

func (s *selectorFlags) String() string {
	return strings.Join(*s, ",")
}

func (s *selectorFlags) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func ParseArgs(args []string, stderr io.Writer) (Options, error) {
	var opts Options
	var selectors selectorFlags
	normalized, err := normalizeArgs(args)
	if err != nil {
		return Options{}, err
	}

	fs := flag.NewFlagSet("mailcheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Var(&selectors, "selector", "additional DKIM selector to try")
	fs.BoolVar(&opts.JSON, "json", false, "render machine-readable JSON")
	fs.BoolVar(&opts.NoColor, "no-color", false, "disable ANSI color in text output")
	fs.BoolVar(&opts.NoProgress, "no-progress", false, "disable interactive progress output")
	fs.BoolVar(&opts.Advanced, "advanced", false, "include mail DNS diagnostic checks")
	fs.BoolVar(&opts.Details, "details", false, "show raw DNS records and lookup details")
	fs.BoolVar(&opts.Details, "verbose", false, "alias for --details")
	fs.BoolVar(&opts.DeepDKIM, "dkim-deep", false, "try the extended DKIM selector list")
	fs.BoolVar(&opts.Version, "version", false, "print version and exit")
	fs.BoolVar(&opts.Version, "v", false, "print version and exit")
	fs.BoolVar(&opts.Help, "help", false, "print help message and exit")
	fs.BoolVar(&opts.Help, "h", false, "print help message and exit")
	fs.DurationVar(&opts.Timeout, "timeout", DefaultTimeout, "total DNS lookup timeout")
	fs.Usage = func() {
		fmt.Fprintln(stderr, help.GetHelp())
		fmt.Fprintln(stderr)
	}

	if err := fs.Parse(normalized); err != nil {
		return Options{}, err
	}

	if earlyOpts, done, err := finalizeFlagOnlyCommand("version", opts.Version, fs, selectors, opts); done {
		return earlyOpts, err
	}

	if earlyOpts, done, err := finalizeFlagOnlyCommand("help", opts.Help, fs, selectors, opts); done {
		return earlyOpts, err
	}

	if fs.NArg() != 1 {
		fs.Usage()
		return Options{}, errors.New("expected exactly one domain argument")
	}

	opts.Domain = fs.Arg(0)
	opts.Selectors = BuildSelectors(selectors)
	return opts, nil
}

func finalizeFlagOnlyCommand(flagName string, enabled bool, fs *flag.FlagSet, selectors selectorFlags, opts Options) (Options, bool, error) {
	if !enabled {
		return opts, false, nil
	}

	if fs.NArg() != 0 {
		fs.Usage()
		return Options{}, true, fmt.Errorf("--%s does not accept a domain argument", flagName)
	}

	opts.Selectors = BuildSelectors(selectors)
	return opts, true, nil
}

func normalizeArgs(args []string) ([]string, error) {
	normalized := make([]string, 0, len(args))
	var domain string
	var expectsValue bool

	for _, arg := range args {
		if expectsValue {
			normalized = append(normalized, arg)
			expectsValue = false
			continue
		}

		switch {
		case arg == "--selector" || arg == "--timeout":
			normalized = append(normalized, arg)
			expectsValue = true
		case strings.HasPrefix(arg, "--selector="),
			strings.HasPrefix(arg, "--timeout="),
			arg == "--json",
			arg == "--no-color",
			arg == "--no-progress",
			arg == "--advanced",
			arg == "--details",
			arg == "--verbose",
			arg == "--dkim-deep",
			arg == "--help",
			arg == "--version":
			normalized = append(normalized, arg)
		case strings.HasPrefix(arg, "-"):
			normalized = append(normalized, arg)
		default:
			if domain != "" {
				return nil, errors.New("expected exactly one domain argument")
			}
			domain = arg
		}
	}

	if expectsValue {
		return nil, errors.New("missing value for trailing flag")
	}
	if domain != "" {
		normalized = append(normalized, domain)
	}

	return normalized, nil
}

func BuildSelectors(explicit []string) []string {
	seen := make(map[string]struct{}, len(explicit))
	selectors := make([]string, 0, len(explicit))

	add := func(selector string) {
		selector = strings.ToLower(strings.TrimSpace(selector))
		if selector == "" {
			return
		}

		if _, ok := seen[selector]; ok {
			return
		}

		seen[selector] = struct{}{}
		selectors = append(selectors, selector)
	}

	for _, selector := range explicit {
		add(selector)
	}

	return selectors
}
