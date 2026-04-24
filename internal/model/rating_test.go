package model

import "testing"

func TestRatingFromChecks(t *testing.T) {
	tests := []struct {
		name   string
		checks []CheckResult
		want   string
	}{
		{
			name: "A when core passes and dkim passes",
			checks: []CheckResult{
				{Name: "MX", Status: StatusPass},
				{Name: "SPF", Status: StatusPass},
				{Name: "DMARC", Status: StatusPass},
				{Name: "DKIM", Status: StatusPass},
			},
			want: "A",
		},
		{
			name: "B when core passes and dkim warns",
			checks: []CheckResult{
				{Name: "MX", Status: StatusPass},
				{Name: "SPF", Status: StatusPass},
				{Name: "DMARC", Status: StatusPass},
				{Name: "DKIM", Status: StatusWarn},
			},
			want: "B",
		},
		{
			name: "D when one core check fails",
			checks: []CheckResult{
				{Name: "MX", Status: StatusFail},
				{Name: "SPF", Status: StatusPass},
				{Name: "DMARC", Status: StatusPass},
				{Name: "DKIM", Status: StatusWarn},
			},
			want: "D",
		},
		{
			name: "D when core passes and dkim fails",
			checks: []CheckResult{
				{Name: "MX", Status: StatusPass},
				{Name: "SPF", Status: StatusPass},
				{Name: "DMARC", Status: StatusPass},
				{Name: "DKIM", Status: StatusFail},
			},
			want: "D",
		},
		{
			name: "F when two core checks fail",
			checks: []CheckResult{
				{Name: "MX", Status: StatusFail},
				{Name: "SPF", Status: StatusFail},
				{Name: "DMARC", Status: StatusPass},
				{Name: "DKIM", Status: StatusWarn},
			},
			want: "F",
		},
		{
			name: "B when only diagnostics warn",
			checks: []CheckResult{
				{Name: "MX", Status: StatusPass},
				{Name: "SPF", Status: StatusPass},
				{Name: "DMARC", Status: StatusPass},
				{Name: "DKIM", Status: StatusWarn},
				{Name: "PTR", Status: StatusWarn},
				{Name: "DNSSEC", Status: StatusWarn},
				{Name: "DNS-TIME", Status: StatusWarn},
			},
			want: "B",
		},
		{
			name: "B when only DMARC monitors and DKIM passes",
			checks: []CheckResult{
				{Name: "MX", Status: StatusPass},
				{Name: "SPF", Status: StatusPass},
				{Name: "DMARC", Status: StatusWarn},
				{Name: "DKIM", Status: StatusPass},
			},
			want: "B",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RatingFromChecks(tt.checks)
			if got != tt.want {
				t.Fatalf("RatingFromChecks() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRatingFromChecksWithReason(t *testing.T) {
	tests := []struct {
		name       string
		checks     []CheckResult
		wantRating string
		wantReason string
	}{
		{
			name: "explains DMARC monitoring only",
			checks: []CheckResult{
				{Name: "MX", Status: StatusPass},
				{Name: "SPF", Status: StatusPass},
				{Name: "DMARC", Status: StatusWarn, Summary: "Policy is monitoring only (p=none)"},
				{Name: "DKIM", Status: StatusPass},
			},
			wantRating: "B",
			wantReason: "DMARC is set to monitoring only.",
		},
		{
			name: "explains DMARC monitoring plus DKIM uncertainty",
			checks: []CheckResult{
				{Name: "MX", Status: StatusPass},
				{Name: "SPF", Status: StatusPass},
				{Name: "DMARC", Status: StatusWarn, Summary: "Policy is monitoring only (p=none)"},
				{Name: "DKIM", Status: StatusWarn},
			},
			wantRating: "C",
			wantReason: "DMARC is monitoring only and DKIM could not be confirmed.",
		},
		{
			name: "explains DKIM uncertainty",
			checks: []CheckResult{
				{Name: "MX", Status: StatusPass},
				{Name: "SPF", Status: StatusPass},
				{Name: "DMARC", Status: StatusPass},
				{Name: "DKIM", Status: StatusWarn},
			},
			wantRating: "B",
			wantReason: "Core mail records pass; DKIM could not be confirmed from guessed selectors.",
		},
		{
			name: "explains multiple core failures",
			checks: []CheckResult{
				{Name: "MX", Status: StatusFail},
				{Name: "SPF", Status: StatusFail},
				{Name: "DMARC", Status: StatusPass},
				{Name: "DKIM", Status: StatusWarn},
			},
			wantRating: "F",
			wantReason: "Multiple core mail checks failed.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRating, gotReason := RatingFromChecksWithReason(tt.checks)
			if gotRating != tt.wantRating {
				t.Fatalf("rating = %q, want %q", gotRating, tt.wantRating)
			}
			if gotReason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", gotReason, tt.wantReason)
			}
		})
	}
}
