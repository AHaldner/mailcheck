package report

import (
	"fmt"
	"strings"

	"github.com/AHaldner/mailcheck/internal/model"
)

type TextOptions struct {
	NoColor bool
	Details bool
}

func RenderText(result model.RunResult, opts TextOptions) (string, error) {
	var builder strings.Builder

	renderReportTitle(&builder, opts.NoColor)
	fmt.Fprintf(&builder, "Domain: %s\n", result.Domain)
	rating := result.Rating
	if !opts.NoColor {
		rating = colorizeRating(result.Rating)
	}
	fmt.Fprintf(&builder, "Rating: %s\n", rating)
	if result.RatingReason != "" {
		fmt.Fprintf(&builder, "Reason: %s\n", result.RatingReason)
	}
	fmt.Fprintln(&builder)

	core, advanced := splitChecks(result.Checks)
	renderCheckSection(&builder, "Core mail checks", core, opts.NoColor)
	if len(advanced) > 0 {
		fmt.Fprintln(&builder)
		renderCheckSection(&builder, "Advanced DNS", advanced, opts.NoColor)
	}

	renderActions(&builder, result.Checks, opts.NoColor)
	if opts.Details {
		renderDetails(&builder, result.Checks)
	}

	return builder.String(), nil
}

func splitChecks(checks []model.CheckResult) ([]model.CheckResult, []model.CheckResult) {
	core := make([]model.CheckResult, 0, len(checks))
	advanced := make([]model.CheckResult, 0)

	for _, check := range checks {
		switch check.Name {
		case "MX", "SPF", "DMARC", "DKIM":
			core = append(core, check)
		default:
			advanced = append(advanced, check)
		}
	}

	return core, advanced
}

func renderReportTitle(builder *strings.Builder, noColor bool) {
	const title = "Mailcheck Results"
	const horizontalPadding = 4
	padding := strings.Repeat(" ", horizontalPadding)
	width := len(title) + horizontalPadding*2
	lines := []string{
		"┌" + strings.Repeat("─", width) + "┐",
		"│" + padding + title + padding + "│",
		"└" + strings.Repeat("─", width) + "┘",
	}

	for _, line := range lines {
		if noColor {
			fmt.Fprintln(builder, line)
			continue
		}

		fmt.Fprintf(builder, "\x1b[1;36m%s\x1b[0m\n", line)
	}
	fmt.Fprintln(builder)
}

func renderCheckSection(builder *strings.Builder, title string, checks []model.CheckResult, noColor bool) {
	if len(checks) == 0 {
		return
	}

	renderSectionTitle(builder, title, noColor)
	nameWidth := checkNameWidth(checks)
	for _, check := range checks {
		status := string(check.Status)
		summary := check.Summary
		if !noColor {
			status = colorize(check.Status, status)
			summary = colorizeBracketMeta(summary)
		}

		fmt.Fprintf(builder, "%-*s %-5s %s\n", nameWidth, check.Name, status, summary)
	}
}

func renderActions(builder *strings.Builder, checks []model.CheckResult, noColor bool) {
	actions := make([]model.CheckResult, 0)
	for _, check := range checks {
		if check.Suggestion == "" {
			continue
		}
		actions = append(actions, check)
	}
	if len(actions) == 0 {
		return
	}

	fmt.Fprintln(builder)
	renderSectionTitle(builder, "Actions", noColor)
	nameWidth := checkNameWidth(actions)
	for _, check := range actions {
		fmt.Fprintf(builder, "%-*s  %s\n", nameWidth, check.Name, check.Suggestion)
	}
}

func renderDetails(builder *strings.Builder, checks []model.CheckResult) {
	hasDetails := false
	for _, check := range checks {
		if len(check.Details) > 0 {
			hasDetails = true
			break
		}
	}
	if !hasDetails {
		return
	}

	fmt.Fprintln(builder)
	renderDetailsTitle(builder)
	for _, check := range checks {
		if len(check.Details) == 0 {
			continue
		}

		fmt.Fprintf(builder, "%s\n", check.Name)
		for _, detail := range check.Details {
			fmt.Fprintf(builder, "  %s\n", detail)
		}
	}
}

func renderSectionTitle(builder *strings.Builder, title string, noColor bool) {
	line := fmt.Sprintf("== %s ==", title)
	if !noColor {
		line = "\x1b[1m" + line + "\x1b[0m"
	}

	fmt.Fprintln(builder, line)
}

func renderDetailsTitle(builder *strings.Builder) {
	fmt.Fprintln(builder, "---- Technical details --------------------------------------------------")
	fmt.Fprintln(builder, "Raw DNS records and lookup details")
	fmt.Fprintln(builder)
}

func checkNameWidth(checks []model.CheckResult) int {
	width := 2
	for _, check := range checks {
		if len(check.Name) > width {
			width = len(check.Name)
		}
	}

	return width
}

func colorizeBracketMeta(value string) string {
	start := strings.IndexByte(value, '[')
	if start == -1 {
		return value
	}

	end := strings.IndexByte(value[start:], ']')
	if end == -1 {
		return value
	}

	end += start
	return value[:start] + "\x1b[38;5;117m" + value[start:end+1] + "\x1b[0m" + value[end+1:]
}

func colorizeRating(rating string) string {
	switch rating {
	case "A", "B":
		return "\x1b[32m" + rating + "\x1b[0m"
	case "C":
		return "\x1b[33m" + rating + "\x1b[0m"
	case "D", "F":
		return "\x1b[31m" + rating + "\x1b[0m"
	default:
		return rating
	}
}

func colorize(status model.Status, value string) string {
	switch status {
	case model.StatusPass:
		return "\x1b[32m" + value + "\x1b[0m"
	case model.StatusWarn:
		return "\x1b[33m" + value + "\x1b[0m"
	case model.StatusFail:
		return "\x1b[31m" + value + "\x1b[0m"
	case model.StatusInfo:
		return "\x1b[36m" + value + "\x1b[0m"
	default:
		return value
	}
}
