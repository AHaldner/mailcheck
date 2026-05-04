package help

import (
	"fmt"
	"sort"
	"strings"
)

type UsageMode int

const (
	UsageFlagListOnly UsageMode = iota
	UsageOption
	UsageCommand
)

type Flag struct {
	Names      []string
	ValueName  string
	UsageValue string
	Default    string
	Usage      string
	UsageMode  UsageMode
}

func Format(command string, argument string, flags []Flag) string {
	lines := []string{
		usageLine(command, argument, flags),
		"",
		"Flags:",
	}

	for _, flag := range flags {
		lines = append(lines, fmt.Sprintf("  %-20s%s", helpLabel(flag), helpUsage(flag)))
	}

	return strings.Join(lines, "\n")
}

func usageLine(command string, argument string, flags []Flag) string {
	commands := make([]string, 0)
	optionsWithValues := make([]string, 0)
	boolOptions := make([]string, 0)
	optionsWithDefaults := make([]string, 0)

	for _, flag := range flags {
		switch flag.UsageMode {
		case UsageCommand:
			commands = append(commands, usageToken(flag))
		case UsageOption:
			token := usageToken(flag)
			switch {
			case flag.UsageValue != "" && flag.Default != "":
				optionsWithDefaults = append(optionsWithDefaults, token)
			case flag.UsageValue != "":
				optionsWithValues = append(optionsWithValues, token)
			default:
				boolOptions = append(boolOptions, token)
			}
		}
	}

	sort.Strings(boolOptions)

	parts := make([]string, 0, 3)
	for _, command := range commands {
		parts = append(parts, bracket(command))
	}

	options := append(optionsWithValues, boolOptions...)
	options = append(options, optionsWithDefaults...)
	if len(options) > 0 || argument != "" {
		tail := make([]string, 0, len(options)+1)
		for _, option := range options {
			tail = append(tail, bracket(option))
		}
		if argument != "" {
			tail = append(tail, argument)
		}
		parts = append(parts, strings.Join(tail, " "))
	}

	return fmt.Sprintf("Usage: %s %s", command, strings.Join(parts, " | "))
}

func usageToken(flag Flag) string {
	token := prefixedName(flag.Names[0])
	if flag.UsageValue != "" {
		token += " " + flag.UsageValue
	}
	return token
}

func helpLabel(flag Flag) string {
	labels := make([]string, 0, len(flag.Names))
	for i, name := range flag.Names {
		label := prefixedName(name)
		if i == 0 && flag.ValueName != "" {
			label += " <" + flag.ValueName + ">"
		}
		labels = append(labels, label)
	}
	return strings.Join(labels, ", ")
}

func helpUsage(flag Flag) string {
	if flag.Default == "" {
		return flag.Usage
	}
	return fmt.Sprintf("%s (default %s)", flag.Usage, flag.Default)
}

func prefixedName(name string) string {
	if len(name) == 1 {
		return "-" + name
	}
	return "--" + name
}

func bracket(value string) string {
	return "[" + value + "]"
}
