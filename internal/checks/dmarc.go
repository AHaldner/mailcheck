package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/AHaldner/mailcheck/internal/dns"
	"github.com/AHaldner/mailcheck/internal/model"
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
			Summary: lookupFailureSummary("DMARC", domain, err),
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
			Summary: missingRecordSummary("DMARC", domain),
		}
	case 1:
		return dmarcRecordResult(domain, records[0])
	default:
		return model.CheckResult{
			Name:    "DMARC",
			Status:  model.StatusFail,
			Summary: multipleRecordsSummary("DMARC", domain, len(records)),
			Details: recordDetails(records),
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
			result := dmarcRecordResult(parent, records[0])
			if result.Status == model.StatusFail {
				continue
			}

			return &result
		default:
			result := model.CheckResult{
				Name:    "DMARC",
				Status:  model.StatusFail,
				Summary: multipleRecordsSummary("DMARC", parent, len(records)),
				Details: recordDetails(records),
			}
			return &result
		}
	}

	return nil
}

func dmarcRecordResult(source string, record string) model.CheckResult {
	tags := parseTagList(record)
	policy, ok := tags["p"]
	if !ok {
		return model.CheckResult{
			Name:    "DMARC",
			Status:  model.StatusFail,
			Summary: invalidRecordSummary("DMARC", source, "missing p= policy"),
			Details: recordDetails([]string{record}),
		}
	}

	switch strings.ToLower(policy) {
	case "none":
		return model.CheckResult{
			Name:       "DMARC",
			Status:     model.StatusWarn,
			Summary:    "Policy is monitoring only (p=none)",
			Details:    []string{fmt.Sprintf("DMARC via %s: %s", source, record)},
			Suggestion: "Switch to quarantine or reject after reviewing reports.",
		}
	case "quarantine":
		return model.CheckResult{
			Name:    "DMARC",
			Status:  model.StatusPass,
			Summary: "Policy quarantines failing mail",
			Details: []string{fmt.Sprintf("DMARC via %s: %s", source, record)},
		}
	case "reject":
		return model.CheckResult{
			Name:    "DMARC",
			Status:  model.StatusPass,
			Summary: "Policy rejects failing mail",
			Details: []string{fmt.Sprintf("DMARC via %s: %s", source, record)},
		}
	default:
		return model.CheckResult{
			Name:    "DMARC",
			Status:  model.StatusFail,
			Summary: invalidRecordSummary("DMARC", source, "invalid p= policy"),
			Details: recordDetails([]string{record}),
		}
	}
}
