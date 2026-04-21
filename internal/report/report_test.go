package report

import (
	"strings"
	"testing"

	"github.com/AHaldner/mailcheck/internal/model"
)

func TestRenderTextIncludesChecksAndSuggestion(t *testing.T) {
	result := model.RunResult{
		Domain: "example.com",
		Rating: "B",
		Checks: []model.CheckResult{
			{Name: "MX", Status: model.StatusPass, Summary: "MX via example.com [2 records]: 10 mx1.example.com., 20 mx2.example.com."},
			{Name: "DKIM", Status: model.StatusWarn, Summary: "DKIM via example.com [2 selectors tried]: no matching record found", Suggestion: "Try --selector <name> or use a selector from a real DKIM-Signature header."},
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
		"Suggestion: Try --selector <name> or use a selector from a real DKIM-Signature header.",
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

func TestRenderTextColorizesBracketMetadataWhenEnabled(t *testing.T) {
	result := model.RunResult{
		Domain: "example.com",
		Rating: "A",
		Checks: []model.CheckResult{
			{Name: "DKIM", Status: model.StatusPass, Summary: "DKIM via example.com [2 selectors]: selector1, selector2"},
		},
	}

	out, err := RenderText(result, false)
	if err != nil {
		t.Fatalf("RenderText error = %v", err)
	}

	if !strings.Contains(out, "DKIM via example.com \x1b[38;5;117m[2 selectors]\x1b[0m: selector1, selector2") {
		t.Fatalf("bracket metadata missing color:\n%s", out)
	}
}
