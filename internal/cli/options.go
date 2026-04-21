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

type Options struct {
	Domain     string
	Selectors  []string
	JSON       bool
	NoColor    bool
	NoProgress bool
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
	fs.BoolVar(&opts.Version, "version", false, "print version and exit")
	fs.BoolVar(&opts.Version, "v", false, "print version and exit")
	fs.BoolVar(&opts.Help, "help", false, "print help message and exit")
	fs.BoolVar(&opts.Help, "h", false, "print help message and exit")
	fs.DurationVar(&opts.Timeout, "timeout", 3*time.Second, "total DNS lookup timeout")
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

func ValidateDomain(domain string) error {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return errors.New("domain must not be empty")
	}

	if len(domain) > 253 {
		return errors.New("domain exceeds maximum length")
	}

	if strings.Contains(domain, "://") || strings.Contains(domain, "/") || strings.Contains(domain, " ") {
		return errors.New("domain must be a bare hostname")
	}

	if before, ok := strings.CutSuffix(domain, "."); ok {
		domain = before
	}

	if !strings.Contains(domain, ".") {
		return errors.New("domain must contain at least one dot")
	}

	labels := strings.SplitSeq(domain, ".")
	for label := range labels {
		if label == "" {
			return errors.New("domain contains an empty label")
		}

		if len(label) > 63 {
			return fmt.Errorf("domain label %q exceeds maximum length", label)
		}

		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("domain label %q must not start or end with '-'", label)
		}

		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}

			return fmt.Errorf("domain label %q contains invalid character %q", label, r)
		}
	}

	return nil
}
