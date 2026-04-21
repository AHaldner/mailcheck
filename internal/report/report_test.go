package report

import (
	"strings"
	"testing"

	"mailcheck/internal/model"
)

func TestRenderTextIncludesChecksAndSuggestion(t *testing.T) {
	result := model.RunResult{
		Domain: "example.com",
		Rating: "B",
		Checks: []model.CheckResult{
			{Name: "MX", Status: model.StatusPass, Summary: "2 records found"},
			{Name: "DKIM", Status: model.StatusWarn, Summary: "no common selector found", Suggestion: "try --selector default"},
		},
	}

	out, err := RenderText(result, true)
	if err != nil {
		t.Fatalf("RenderText error = %v", err)
	}

	for _, part := range []string{
		"Mailcheck: example.com",
		"Rating: B",
		"MX",
		"DKIM",
		"Suggestion: try --selector default",
	} {
		if !strings.Contains(out, part) {
			t.Fatalf("output missing %q:\n%s", part, out)
		}
	}
}

func TestRenderJSONIncludesSelectors(t *testing.T) {
	result := model.RunResult{
		Domain:             "example.com",
		Rating:             "A",
		DKIMSelectorsTried: []string{"default", "google"},
		DKIMSelectorsFound: []string{"google"},
	}

	out, err := RenderJSON(result)
	if err != nil {
		t.Fatalf("RenderJSON error = %v", err)
	}

	for _, part := range []string{
		`"domain": "example.com"`,
		`"rating": "A"`,
		`"dkimSelectorsTried": [`,
		`"default"`,
		`"google"`,
		`"dkimSelectorsFound": [`,
	} {
		if !strings.Contains(out, part) {
			t.Fatalf("output missing %q:\n%s", part, out)
		}
	}
}

func TestRenderTextColorizesRatingWhenEnabled(t *testing.T) {
	result := model.RunResult{
		Domain: "example.com",
		Rating: "B",
	}

	out, err := RenderText(result, false)
	if err != nil {
		t.Fatalf("RenderText error = %v", err)
	}

	if !strings.Contains(out, "Rating: \x1b[32mB\x1b[0m") {
		t.Fatalf("rating line missing color:\n%s", out)
	}
}
