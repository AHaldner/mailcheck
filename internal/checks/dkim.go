package checks

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/AHaldner/mailcheck/internal/dns"
	"github.com/AHaldner/mailcheck/internal/model"
)

const dkimConcurrentLookups = 24

type DKIMOptions struct {
	Selectors []string
	Deep      bool
}

type dkimLookupResult struct {
	index    int
	selector string
	fqdn     string
	records  []string
	err      error
}

func CheckDKIM(ctx context.Context, r dns.Resolver, domain string, opts DKIMOptions) (model.CheckResult, []string, []string) {
	tried := dkimSelectorCandidates(opts.Selectors, opts.Deep)
	results := lookupDKIMSelectors(ctx, r, domain, tried)

	found := make([]dkimLookupResult, 0)
	lookupErrors := make([]string, 0)

	for _, result := range results {
		if len(result.records) > 0 {
			found = append(found, result)
			continue
		}

		if result.err != nil && !isNotFoundError(result.err) {
			lookupErrors = append(lookupErrors, lookupErrorDetail("selector "+result.selector, result.err))
		}
	}

	foundSelectors := make([]string, 0, len(found))
	details := make([]string, 0, len(found)+1)
	for _, result := range found {
		foundSelectors = append(foundSelectors, result.selector)
		details = append(details, result.fqdn)
	}

	if len(foundSelectors) > 0 {
		details = append(details, detectProviderHints(ctx, r, domain, foundSelectors)...)

		return model.CheckResult{
			Name:    "DKIM",
			Status:  model.StatusPass,
			Summary: "DKIM records found for common selectors",
			Details: details,
		}, tried, foundSelectors
	}

	if len(lookupErrors) > 5 {
		lookupErrors = append(lookupErrors[:5], fmt.Sprintf("and %d more lookup errors", len(lookupErrors)-5))
	}

	return model.CheckResult{
		Name:       "DKIM",
		Status:     model.StatusWarn,
		Summary:    "DKIM records were not found for guessed selectors",
		Details:    lookupErrors,
		Suggestion: dkimSuggestion(opts.Deep),
	}, tried, nil
}

func dkimSuggestion(deep bool) string {
	if deep {
		return "Try --selector <name> or use a selector from a real DKIM-Signature header."
	}

	return "Try --selector <name>, --dkim-deep, or use a selector from a real DKIM-Signature header."
}

func lookupDKIMSelectors(ctx context.Context, r dns.Resolver, domain string, selectors []string) []dkimLookupResult {
	results := make(chan dkimLookupResult, len(selectors))
	sem := make(chan struct{}, min(dkimConcurrentLookups, len(selectors)))

	var wg sync.WaitGroup
	for index, selector := range selectors {
		wg.Add(1)

		go func(index int, selector string) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results <- dkimLookupResult{index: index, selector: selector, err: ctx.Err()}
				return
			}
			defer func() {
				<-sem
			}()

			fqdn := selector + "._domainkey." + domain
			txts, err := r.LookupTXT(ctx, fqdn)
			if err != nil {
				results <- dkimLookupResult{
					index:    index,
					selector: selector,
					fqdn:     fqdn,
					err:      err,
				}
				return
			}

			results <- dkimLookupResult{
				index:    index,
				selector: selector,
				fqdn:     fqdn,
				records:  matchingDKIMRecords(txts),
			}
		}(index, selector)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	ordered := make([]dkimLookupResult, len(selectors))
	for result := range results {
		ordered[result.index] = result
	}

	return ordered
}

func matchingDKIMRecords(records []string) []string {
	matches := make([]string, 0, len(records))

	for _, record := range records {
		record = strings.TrimSpace(record)
		if plausibleDKIM(record) {
			matches = append(matches, record)
		}
	}

	return matches
}

func plausibleDKIM(record string) bool {
	tags := parseTagList(record)
	publicKey, ok := tags["p"]
	if !ok || strings.TrimSpace(publicKey) == "" {
		return false
	}

	version, ok := tags["v"]
	if ok && !strings.EqualFold(strings.TrimSpace(version), "DKIM1") {
		return false
	}

	return true
}

func parseTagList(record string) map[string]string {
	tags := make(map[string]string)

	for part := range strings.SplitSeq(record, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}

		tags[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}

	return tags
}

func dkimFoundSummary(domain string, found []string) string {
	if len(found) == 1 {
		return fmt.Sprintf("DKIM via %s [1 selector]: %s", domain, found[0])
	}

	return fmt.Sprintf("DKIM via %s [%d selectors]: %s", domain, len(found), strings.Join(found, ", "))
}

func detectProviderHints(ctx context.Context, r dns.Resolver, domain string, foundSelectors []string) []string {
	found := make(map[string]struct{}, len(foundSelectors))
	for _, selector := range foundSelectors {
		found[selector] = struct{}{}
	}

	details := make([]string, 0, 1)

	if _, ok := found["resend"]; ok {
		host := "send." + domain
		recordTypes := make([]string, 0, 2)

		txts, err := r.LookupTXT(ctx, host)
		if err == nil && len(txts) > 0 {
			recordTypes = append(recordTypes, "TXT")
		}

		mxs, err := r.LookupMX(ctx, host)
		if err == nil && len(mxs) > 0 {
			recordTypes = append(recordTypes, "MX")
		}

		if len(recordTypes) > 0 {
			details = append(details, fmt.Sprintf("Resend helper host: %s (%s)", host, strings.Join(recordTypes, ", ")))
		}
	}

	return details
}
