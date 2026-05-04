package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"reflect"
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
	NoCache    bool
	Advanced   bool
	Details    bool
	DeepDKIM   bool
	Version    bool
	Help       bool
	Timeout    time.Duration
}

type selectorFlags []string

type flagValueKind int

const (
	boolFlag flagValueKind = iota
	durationFlag
	selectorFlag
)

type flagDefinition struct {
	help        help.Flag
	valueKind   flagValueKind
	optionField string
}

var flagDefinitions = []flagDefinition{
	{
		help:      help.Flag{Names: []string{"selector"}, ValueName: "name", UsageValue: "name", Usage: "additional DKIM selector to try", UsageMode: help.UsageOption},
		valueKind: selectorFlag,
	},
	{
		help:        help.Flag{Names: []string{"json"}, Usage: "render machine-readable JSON", UsageMode: help.UsageOption},
		valueKind:   boolFlag,
		optionField: "JSON",
	},
	{
		help:        help.Flag{Names: []string{"no-cache"}, Usage: "disable DNS lookup caching for the run", UsageMode: help.UsageOption},
		valueKind:   boolFlag,
		optionField: "NoCache",
	},
	{
		help:        help.Flag{Names: []string{"no-color"}, Usage: "disable ANSI color in text output", UsageMode: help.UsageOption},
		valueKind:   boolFlag,
		optionField: "NoColor",
	},
	{
		help:        help.Flag{Names: []string{"no-progress"}, Usage: "disable interactive progress output", UsageMode: help.UsageOption},
		valueKind:   boolFlag,
		optionField: "NoProgress",
	},
	{
		help:        help.Flag{Names: []string{"advanced"}, Usage: "include mail DNS diagnostic checks", UsageMode: help.UsageOption},
		valueKind:   boolFlag,
		optionField: "Advanced",
	},
	{
		help:        help.Flag{Names: []string{"details"}, Usage: "show raw DNS records and lookup details", UsageMode: help.UsageOption},
		valueKind:   boolFlag,
		optionField: "Details",
	},
	{
		help:        help.Flag{Names: []string{"verbose"}, Usage: "alias for --details", UsageMode: help.UsageFlagListOnly},
		valueKind:   boolFlag,
		optionField: "Details",
	},
	{
		help:        help.Flag{Names: []string{"dkim-deep"}, Usage: "try the extended DKIM selector list", UsageMode: help.UsageOption},
		valueKind:   boolFlag,
		optionField: "DeepDKIM",
	},
	{
		help:        help.Flag{Names: []string{"timeout"}, ValueName: "value", UsageValue: "30s", Default: DefaultTimeout.String(), Usage: "total DNS lookup timeout", UsageMode: help.UsageOption},
		valueKind:   durationFlag,
		optionField: "Timeout",
	},
	{
		help:        help.Flag{Names: []string{"version", "v"}, Usage: "print version and exit", UsageMode: help.UsageCommand},
		valueKind:   boolFlag,
		optionField: "Version",
	},
	{
		help:        help.Flag{Names: []string{"help", "h"}, Usage: "print help message and exit", UsageMode: help.UsageCommand},
		valueKind:   boolFlag,
		optionField: "Help",
	},
}

func (s *selectorFlags) String() string {
	return strings.Join(*s, ",")
}

func (s *selectorFlags) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func Help() string {
	flags := make([]help.Flag, 0, len(flagDefinitions))
	for _, definition := range flagDefinitions {
		flags = append(flags, definition.help)
	}
	return help.Format("mailcheck", "domain.example", flags)
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
	registerFlags(fs, &opts, &selectors)
	fs.Usage = func() {
		fmt.Fprintln(stderr, Help())
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
	valueFlags, boolFlags := knownFlags()
	var domain string
	var expectsValue bool

	for _, arg := range args {
		if expectsValue {
			normalized = append(normalized, arg)
			expectsValue = false
			continue
		}

		switch {
		case strings.HasPrefix(arg, "--") && valueFlags[strings.TrimPrefix(arg, "--")]:
			normalized = append(normalized, arg)
			expectsValue = true
		case strings.HasPrefix(arg, "--") && isKnownLongFlag(arg, valueFlags, boolFlags):
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

func registerFlags(fs *flag.FlagSet, opts *Options, selectors *selectorFlags) {
	registerFlagDefinitions(fs, opts, selectors, flagDefinitions)
}

func registerFlagDefinitions(fs *flag.FlagSet, opts *Options, selectors *selectorFlags, definitions []flagDefinition) {
	for _, definition := range definitions {
		registerFlagDefinition(fs, opts, selectors, definition)
	}
}

func registerFlagDefinition(fs *flag.FlagSet, opts *Options, selectors *selectorFlags, definition flagDefinition) {
	switch definition.valueKind {
	case boolFlag:
		target := boolOptionField(opts, definition.optionField)
		for _, name := range definition.help.Names {
			fs.BoolVar(target, name, false, definition.help.Usage)
		}
	case durationFlag:
		target := durationOptionField(opts, definition.optionField)
		for _, name := range definition.help.Names {
			fs.DurationVar(target, name, DefaultTimeout, definition.help.Usage)
		}
	case selectorFlag:
		fs.Var(selectors, definition.help.Names[0], definition.help.Usage)
	default:
		panic(fmt.Sprintf("unsupported flag value kind %d", definition.valueKind))
	}
}

func knownFlags() (map[string]bool, map[string]bool) {
	valueFlags := make(map[string]bool)
	boolFlags := make(map[string]bool)

	for _, definition := range flagDefinitions {
		for _, name := range definition.help.Names {
			if definition.takesValue() {
				valueFlags[name] = true
				continue
			}
			boolFlags[name] = true
		}
	}

	return valueFlags, boolFlags
}

func (d flagDefinition) takesValue() bool {
	return d.valueKind == durationFlag || d.valueKind == selectorFlag
}

func boolOptionField(opts *Options, name string) *bool {
	field := optionField(opts, name, reflect.Bool)
	return field.Addr().Interface().(*bool)
}

func durationOptionField(opts *Options, name string) *time.Duration {
	field := optionField(opts, name, reflect.Int64)
	if field.Type() != reflect.TypeOf(time.Duration(0)) {
		panic(fmt.Sprintf("Options.%s is %s, want time.Duration", name, field.Type()))
	}
	return field.Addr().Interface().(*time.Duration)
}

func optionField(opts *Options, name string, kind reflect.Kind) reflect.Value {
	field := reflect.ValueOf(opts).Elem().FieldByName(name)
	if !field.IsValid() {
		panic(fmt.Sprintf("Options.%s does not exist", name))
	}
	if field.Kind() != kind {
		panic(fmt.Sprintf("Options.%s is %s, want %s", name, field.Kind(), kind))
	}
	return field
}

func isKnownLongFlag(arg string, valueFlags map[string]bool, boolFlags map[string]bool) bool {
	name := strings.TrimPrefix(arg, "--")
	if before, _, ok := strings.Cut(name, "="); ok {
		name = before
	}

	return valueFlags[name] || boolFlags[name]
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
