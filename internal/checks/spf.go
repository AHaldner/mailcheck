package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/AHaldner/mailcheck/internal/dns"
	"github.com/AHaldner/mailcheck/internal/model"
)

func CheckSPF(ctx context.Context, r dns.Resolver, domain string) model.CheckResult {
	txts, err := r.LookupTXT(ctx, domain)
	if err != nil {
		if fallback := checkSubdomainHelperResult(domain, func(host string) *model.CheckResult {
			return checkHelperSPF(ctx, r, host)
		}); fallback != nil {
			return *fallback
		}

		return model.CheckResult{
			Name:    "SPF",
			Status:  model.StatusFail,
			Summary: lookupFailureSummary("SPF", domain, err),
		}
	}

	records := matchingRecords(txts, "v=spf1")
	switch len(records) {
	case 0:
		if fallback := checkSubdomainHelperResult(domain, func(host string) *model.CheckResult {
			return checkHelperSPF(ctx, r, host)
		}); fallback != nil {
			return *fallback
		}

		return model.CheckResult{
			Name:    "SPF",
			Status:  model.StatusFail,
			Summary: missingRecordSummary("SPF", domain),
		}
	case 1:
		return model.CheckResult{
			Name:    "SPF",
			Status:  model.StatusPass,
			Summary: fmt.Sprintf("SPF via %s [1 record]: %s", domain, records[0]),
		}
	default:
		return model.CheckResult{
			Name:    "SPF",
			Status:  model.StatusFail,
			Summary: multipleRecordsSummary("SPF", domain, len(records)),
			Details: recordDetails(records),
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
			Summary: fmt.Sprintf("SPF via %s [1 record]: %s", host, records[0]),
		}
		return &result
	default:
		result := model.CheckResult{
			Name:    "SPF",
			Status:  model.StatusFail,
			Summary: multipleRecordsSummary("SPF", host, len(records)),
			Details: recordDetails(records),
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
