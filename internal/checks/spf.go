package checks

import (
	"context"
	"fmt"
	"strings"

	"mailcheck/internal/dns"
	"mailcheck/internal/model"
)

func CheckSPF(ctx context.Context, r dns.Resolver, domain string) model.CheckResult {
	txts, err := r.LookupTXT(ctx, domain)
	if err != nil {
		if isSubdomain(domain) {
			if fallback := checkHelperSPF(ctx, r, resendHelperHost(domain)); fallback != nil {
				return *fallback
			}
		}

		return model.CheckResult{
			Name:    "SPF",
			Status:  model.StatusFail,
			Summary: fmt.Sprintf("lookup error: %v", err),
		}
	}

	records := matchingRecords(txts, "v=spf1")
	switch len(records) {
	case 0:
		if isSubdomain(domain) {
			if fallback := checkHelperSPF(ctx, r, resendHelperHost(domain)); fallback != nil {
				return *fallback
			}
		}

		return model.CheckResult{
			Name:    "SPF",
			Status:  model.StatusFail,
			Summary: "no SPF record found",
		}
	case 1:
		return model.CheckResult{
			Name:    "SPF",
			Status:  model.StatusPass,
			Summary: records[0],
		}
	default:
		return model.CheckResult{
			Name:    "SPF",
			Status:  model.StatusFail,
			Summary: fmt.Sprintf("multiple SPF records found (%d)", len(records)),
			Details: records,
		}
	}
}

func checkHelperSPF(ctx context.Context, r dns.Resolver, host string) *model.CheckResult {
	txts, err := r.LookupTXT(ctx, host)
	if err != nil {
		return nil
	}

	records := matchingRecords(txts, "v=spf1")
	switch len(records) {
	case 0:
		return nil
	case 1:
		result := model.CheckResult{
			Name:    "SPF",
			Status:  model.StatusPass,
			Summary: fmt.Sprintf("using helper host %s: %s", host, records[0]),
		}
		return &result
	default:
		result := model.CheckResult{
			Name:    "SPF",
			Status:  model.StatusFail,
			Summary: fmt.Sprintf("multiple SPF records found on helper host %s (%d)", host, len(records)),
			Details: records,
		}
		return &result
	}
}

func matchingRecords(records []string, prefix string) []string {
	matches := make([]string, 0, len(records))
	for _, record := range records {
		record = strings.TrimSpace(record)

		if strings.HasPrefix(record, prefix) {
			matches = append(matches, record)
		}
	}

	return matches
}
