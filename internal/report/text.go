package report

import (
	"fmt"
	"strings"

	"github.com/AHaldner/mailcheck/internal/model"
)

func RenderText(result model.RunResult, noColor bool) (string, error) {
	var builder strings.Builder

	fmt.Fprintf(&builder, "Mailcheck: %s\n", result.Domain)
	rating := result.Rating
	if !noColor {
		rating = colorizeRating(result.Rating)
	}
	fmt.Fprintf(&builder, "Rating: %s\n\n", rating)

	for _, check := range result.Checks {
		status := string(check.Status)
		if !noColor {
			status = colorize(check.Status, status)
		}

		fmt.Fprintf(&builder, "%-7s %-5s %s\n", check.Name, status, check.Summary)
	}

	for _, check := range result.Checks {
		if check.Suggestion == "" {
			continue
		}

		fmt.Fprintf(&builder, "\nSuggestion: %s\n", check.Suggestion)
	}

	return builder.String(), nil
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
	default:
		return value
	}
}
