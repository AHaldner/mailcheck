package checks

import (
	"context"
	"fmt"
	"strings"

	"mailcheck/internal/dns"
	"mailcheck/internal/model"
)

func CheckDMARC(ctx context.Context, r dns.Resolver, domain string) model.CheckResult {
	txts, err := r.LookupTXT(ctx, "_dmarc."+domain)
	if err != nil {
		if inherited := checkInheritedDMARC(ctx, r, domain); inherited != nil {
			return *inherited
		}

		return model.CheckResult{
			Name:    "DMARC",
			Status:  model.StatusFail,
			Summary: fmt.Sprintf("lookup error: %v", err),
		}
	}

	records := matchingRecords(txts, "v=DMARC1")
	switch len(records) {
	case 0:
		if inherited := checkInheritedDMARC(ctx, r, domain); inherited != nil {
			return *inherited
		}

		return model.CheckResult{
			Name:    "DMARC",
			Status:  model.StatusFail,
			Summary: "no DMARC record found",
		}
	case 1:
		if !hasTag(records[0], "p") {
			return model.CheckResult{
				Name:    "DMARC",
				Status:  model.StatusFail,
				Summary: "DMARC record missing p= policy",
				Details: []string{records[0]},
			}
		}

		return model.CheckResult{
			Name:    "DMARC",
			Status:  model.StatusPass,
			Summary: records[0],
		}
	default:
		return model.CheckResult{
			Name:    "DMARC",
			Status:  model.StatusFail,
			Summary: fmt.Sprintf("multiple DMARC records found (%d)", len(records)),
			Details: records,
		}
	}
}

func checkInheritedDMARC(ctx context.Context, r dns.Resolver, domain string) *model.CheckResult {
	for _, parent := range parentDomains(domain) {
		txts, err := r.LookupTXT(ctx, "_dmarc."+parent)
		if err != nil {
			continue
		}

		records := matchingRecords(txts, "v=DMARC1")
		switch len(records) {
		case 0:
			continue
		case 1:
			if !hasTag(records[0], "p") {
				continue
			}

			result := model.CheckResult{
				Name:    "DMARC",
				Status:  model.StatusPass,
				Summary: fmt.Sprintf("using inherited DMARC policy from %s: %s", parent, records[0]),
			}
			return &result
		default:
			result := model.CheckResult{
				Name:    "DMARC",
				Status:  model.StatusFail,
				Summary: fmt.Sprintf("multiple inherited DMARC records found on %s (%d)", parent, len(records)),
				Details: records,
			}
			return &result
		}
	}

	return nil
}

func hasTag(record string, key string) bool {
	for part := range strings.SplitSeq(record, ";") {
		part = strings.TrimSpace(part)

		if strings.HasPrefix(part, key+"=") {
			return true
		}
	}

	return false
}
