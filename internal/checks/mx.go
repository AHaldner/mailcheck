package checks

import (
	"context"
	"fmt"
	"net"
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

	return mxResult(ctx, r, domain, records)
}

func mxResult(ctx context.Context, r dns.Resolver, source string, records []*net.MX) model.CheckResult {
	sortMX(records)
	parts := make([]string, 0, len(records))
	details := make([]string, 0, len(records)+1)
	resolvedTargets := 0

	for _, record := range records {
		parts = append(parts, fmt.Sprintf("%d %s", record.Pref, record.Host))
	}
	details = append(details, fmt.Sprintf("MX via %s: %s", source, strings.Join(parts, ", ")))

	if hasNullMX(records) {
		return model.CheckResult{
			Name:    "MX",
			Status:  model.StatusFail,
			Summary: "Domain publishes a null MX and does not accept mail",
			Details: details,
		}
	}

	for _, record := range records {
		ips, err := r.LookupIPAddr(ctx, record.Host)
		if err != nil || len(ips) == 0 {
			if err != nil {
				details = append(details, lookupErrorDetail(record.Host+" A/AAAA", err))
			} else {
				details = append(details, fmt.Sprintf("%s A/AAAA [0 records]", record.Host))
			}
			continue
		}

		resolvedTargets++
		details = append(details, fmt.Sprintf("%s A/AAAA: %s", record.Host, joinIPAddrs(ips)))
	}

	if resolvedTargets == 0 {
		return model.CheckResult{
			Name:    "MX",
			Status:  model.StatusFail,
			Summary: fmt.Sprintf("%s found, but none resolve to IP addresses", mailServerCount(len(records))),
			Details: details,
		}
	}

	if resolvedTargets == len(records) {
		return model.CheckResult{
			Name:    "MX",
			Status:  model.StatusPass,
			Summary: fmt.Sprintf("%s found; all resolve to IP addresses", mailServerCount(len(records))),
			Details: details,
		}
	}

	return model.CheckResult{
		Name:    "MX",
		Status:  model.StatusPass,
		Summary: fmt.Sprintf("%s found; %d resolve to IP addresses", mailServerCount(len(records)), resolvedTargets),
		Details: details,
	}
}

func mailServerCount(count int) string {
	if count == 1 {
		return "1 mail server"
	}

	return fmt.Sprintf("%d mail servers", count)
}

func checkHelperMX(ctx context.Context, r dns.Resolver, host string) *model.CheckResult {
	records, err := r.LookupMX(ctx, host)
	if err != nil || len(records) == 0 {
		return nil
	}

	result := mxResult(ctx, r, host, records)
	return &result
}

func hasNullMX(records []*net.MX) bool {
	return len(records) == 1 && strings.TrimSuffix(records[0].Host, ".") == ""
}

func sortMX(records []*net.MX) {
	sort.Slice(records, func(i, j int) bool {
		if records[i].Pref == records[j].Pref {
			return records[i].Host < records[j].Host
		}

		return records[i].Pref < records[j].Pref
	})
}

func joinIPAddrs(records []net.IPAddr) string {
	values := make([]string, 0, len(records))
	for _, record := range records {
		values = append(values, record.IP.String())
	}
	sort.Strings(values)

	return strings.Join(values, ", ")
}
