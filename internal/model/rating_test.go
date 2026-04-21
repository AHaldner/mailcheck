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
