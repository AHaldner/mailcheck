package checks

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/AHaldner/mailcheck/internal/dns"
	"github.com/AHaldner/mailcheck/internal/model"
)

func CheckMX(ctx context.Context, r dns.Resolver, domain string) model.CheckResult {
	records, err := r.LookupMX(ctx, domain)
	if err != nil {
		if fallback := checkSubdomainHelperResult(domain, func(host string) *model.CheckResult {
			return checkHelperMX(ctx, r, host)
		}); fallback != nil {
			return *fallback
		}

		return model.CheckResult{
			Name:    "MX",
			Status:  model.StatusFail,
			Summary: lookupFailureSummary("MX", domain, err),
		}
	}

	if len(records) == 0 {
		if fallback := checkSubdomainHelperResult(domain, func(host string) *model.CheckResult {
			return checkHelperMX(ctx, r, host)
		}); fallback != nil {
			return *fallback
		}

		return model.CheckResult{
			Name:    "MX",
			Status:  model.StatusFail,
			Summary: missingRecordSummary("MX", domain),
		}
	}

	sort.Slice(records, func(i, j int) bool {
		if records[i].Pref == records[j].Pref {
			return records[i].Host < records[j].Host
		}

		return records[i].Pref < records[j].Pref
	})

	parts := make([]string, 0, len(records))
	for _, record := range records {
		parts = append(parts, fmt.Sprintf("%d %s", record.Pref, record.Host))
	}

	if len(records) == 1 {
		return model.CheckResult{
			Name:    "MX",
			Status:  model.StatusPass,
			Summary: fmt.Sprintf("MX via %s [1 record]: %s", domain, parts[0]),
		}
	}

	return model.CheckResult{
		Name:    "MX",
		Status:  model.StatusPass,
		Summary: fmt.Sprintf("MX via %s [%d records]: %s", domain, len(records), strings.Join(parts, ", ")),
	}
}

func checkHelperMX(ctx context.Context, r dns.Resolver, host string) *model.CheckResult {
	records, err := r.LookupMX(ctx, host)
	if err != nil || len(records) == 0 {
		return nil
	}

	sort.Slice(records, func(i, j int) bool {
		if records[i].Pref == records[j].Pref {
			return records[i].Host < records[j].Host
		}

		return records[i].Pref < records[j].Pref
	})

	parts := make([]string, 0, len(records))
	for _, record := range records {
		parts = append(parts, fmt.Sprintf("%d %s", record.Pref, record.Host))
	}

	if len(records) == 1 {
		result := model.CheckResult{
			Name:    "MX",
			Status:  model.StatusPass,
			Summary: fmt.Sprintf("MX via %s [1 record]: %s", host, parts[0]),
		}

		return &result
	}

	result := model.CheckResult{
		Name:    "MX",
		Status:  model.StatusPass,
		Summary: fmt.Sprintf("MX via %s [%d records]: %s", host, len(records), strings.Join(parts, ", ")),
	}

	return &result
}
