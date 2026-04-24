package report

import (
	"strings"
	"testing"

	"github.com/AHaldner/mailcheck/internal/model"
)

func TestRenderTextGroupsCoreAdvancedActionsAndHidesDetailsByDefault(t *testing.T) {
	result := model.RunResult{
		Domain:       "example.com",
		Rating:       "B",
		RatingReason: "DMARC is set to monitoring only.",
		Checks: []model.CheckResult{
			{Name: "MX", Status: model.StatusPass, Summary: "2 mail servers found; all resolve to IP addresses", Details: []string{"10 mx1.example.com.", "20 mx2.example.com."}},
			{Name: "SPF", Status: model.StatusPass, Summary: "SPF is valid and ends with -all", Details: []string{"v=spf1 -all"}},
			{Name: "DMARC", Status: model.StatusWarn, Summary: "Policy is monitoring only (p=none)", Suggestion: "Switch to quarantine or reject after reviewing reports."},
			{Name: "DKIM", Status: model.StatusPass, Summary: "DKIM records found for common selectors"},
			{Name: "DNSSEC", Status: model.StatusInfo, Summary: "Not checked: system resolver does not expose DNSSEC status"},
			{Name: "DNS-TIME", Status: model.StatusWarn, Summary: "1 slow DNS response observed", Details: []string{"TXT example.com: 1700ms"}},
		},
	}

	out, err := RenderText(result, TextOptions{NoColor: true})
	if err != nil {
		t.Fatalf("RenderText error = %v", err)
	}

	for _, part := range []string{
		"┌─────────────────────────┐",
		"│    Mailcheck Results    │\n└─────────────────────────┘\n\nDomain: example.com",
		"Domain: example.com",
		"Rating: B",
		"Reason: DMARC is set to monitoring only.",
		"== Core mail checks ==",
		"MX    PASS",
		"DMARC WARN  Policy is monitoring only (p=none)",
		"== Advanced DNS ==",
		"DNSSEC   INFO",
		"DNS-TIME WARN",
		"== Actions ==",
		"DMARC  Switch to quarantine or reject after reviewing reports.",
	} {
		if !strings.Contains(out, part) {
			t.Fatalf("output missing %q:\n%s", part, out)
		}
	}

	for _, raw := range []string{"10 mx1.example.com.", "v=spf1 -all", "TXT example.com: 1700ms"} {
		if strings.Contains(out, raw) {
			t.Fatalf("output included raw detail %q without details mode:\n%s", raw, out)
		}
	}
}

func TestRenderTextIncludesRawDetailsWhenRequested(t *testing.T) {
	result := model.RunResult{
		Domain: "example.com",
		Rating: "A",
		Checks: []model.CheckResult{
			{Name: "MX", Status: model.StatusPass, Summary: "2 mail servers found; all resolve to IP addresses", Details: []string{"10 mx1.example.com.", "20 mx2.example.com."}},
		},
	}

	out, err := RenderText(result, TextOptions{NoColor: true, Details: true})
	if err != nil {
		t.Fatalf("RenderText error = %v", err)
	}

	for _, part := range []string{
		"---- Technical details --------------------------------------------------",
		"Raw DNS records and lookup details",
		"10 mx1.example.com.",
	} {
		if !strings.Contains(out, part) {
			t.Fatalf("output missing details part %q:\n%s", part, out)
		}
	}
}

func TestRenderTextColorizesSectionTitlesWhenEnabled(t *testing.T) {
	result := model.RunResult{
		Domain: "example.com",
		Rating: "A",
		Checks: []model.CheckResult{
			{Name: "MX", Status: model.StatusPass, Summary: "2 mail servers found; all resolve to IP addresses"},
		},
	}

	out, err := RenderText(result, TextOptions{NoColor: false})
	if err != nil {
		t.Fatalf("RenderText error = %v", err)
	}

	if !strings.Contains(out, "\x1b[1;36m┌─────────────────────────┐\x1b[0m\n\x1b[1;36m│    Mailcheck Results    │\x1b[0m\n\x1b[1;36m└─────────────────────────┘\x1b[0m\n\nDomain: example.com") {
		t.Fatalf("output missing colored report title:\n%s", out)
	}

	if !strings.Contains(out, "\x1b[1m== Core mail checks ==\x1b[0m") {
		t.Fatalf("output missing bold section title:\n%s", out)
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

	out, err := RenderText(result, TextOptions{NoColor: false})
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

	out, err := RenderText(result, TextOptions{NoColor: false})
	if err != nil {
		t.Fatalf("RenderText error = %v", err)
	}

	if !strings.Contains(out, "DKIM via example.com \x1b[38;5;117m[2 selectors]\x1b[0m: selector1, selector2") {
		t.Fatalf("bracket metadata missing color:\n%s", out)
	}
}
