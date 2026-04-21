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
		if !hasTag(records[0], "p") {
			return model.CheckResult{
				Name:    "DMARC",
				Status:  model.StatusFail,
				Summary: invalidRecordSummary("DMARC", domain, "missing p= policy"),
				Details: recordDetails(records[:1]),
			}
		}

		return model.CheckResult{
			Name:    "DMARC",
			Status:  model.StatusPass,
			Summary: fmt.Sprintf("DMARC via %s [1 record]: %s", domain, records[0]),
		}
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
			if !hasTag(records[0], "p") {
				continue
			}

			result := model.CheckResult{
				Name:    "DMARC",
				Status:  model.StatusPass,
				Summary: fmt.Sprintf("DMARC via %s [1 record]: %s", parent, records[0]),
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

func hasTag(record string, key string) bool {
	for part := range strings.SplitSeq(record, ";") {
		part = strings.TrimSpace(part)

		if strings.HasPrefix(part, key+"=") {
			return true
		}
	}

	return false
}
