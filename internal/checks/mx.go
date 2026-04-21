package checks

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"mailcheck/internal/dns"
	"mailcheck/internal/model"
)

func CheckMX(ctx context.Context, r dns.Resolver, domain string) model.CheckResult {
	records, err := r.LookupMX(ctx, domain)
	if err != nil {
		if isSubdomain(domain) {
			if fallback := checkHelperMX(ctx, r, resendHelperHost(domain)); fallback != nil {
				return *fallback
			}
		}

		return model.CheckResult{
			Name:    "MX",
			Status:  model.StatusFail,
			Summary: fmt.Sprintf("lookup error: %v", err),
		}
	}

	if len(records) == 0 {
		if isSubdomain(domain) {
			if fallback := checkHelperMX(ctx, r, resendHelperHost(domain)); fallback != nil {
				return *fallback
			}
		}

		return model.CheckResult{
			Name:    "MX",
			Status:  model.StatusFail,
			Summary: "no MX records found",
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

	return model.CheckResult{
		Name:    "MX",
		Status:  model.StatusPass,
		Summary: fmt.Sprintf("%d records found: %s", len(records), strings.Join(parts, ", ")),
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

	result := model.CheckResult{
		Name:    "MX",
		Status:  model.StatusPass,
		Summary: fmt.Sprintf("using helper host %s with %d MX record(s): %s", host, len(records), strings.Join(parts, ", ")),
	}

	return &result
}
