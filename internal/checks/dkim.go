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
	if len(opts.Selectors) != 0 {
		return checkDKIMWithGivenSelectors(ctx, r, domain, opts)
	}

	tried := dkimSelectorCandidates(nil, opts.Deep)
	found, lookupErrors := collectDKIMLookupResults(lookupDKIMSelectors(ctx, r, domain, tried))
	if len(found) > 0 {
		result, foundSelectors := dkimFoundResult(ctx, r, domain, found, opts)
		return result, tried, foundSelectors
	}

	return model.CheckResult{
		Name:       "DKIM",
		Status:     model.StatusWarn,
		Summary:    "DKIM records were not found for guessed selectors",
		Details:    limitedLookupErrors(lookupErrors),
		Suggestion: dkimSuggestion(opts.Deep),
	}, tried, nil
}

func checkDKIMWithGivenSelectors(ctx context.Context, r dns.Resolver, domain string, opts DKIMOptions) (model.CheckResult, []string, []string) {
	givenTried := givenDKIMSelectors(opts.Selectors)
	givenFound, givenErrors := collectDKIMLookupResults(lookupDKIMSelectors(ctx, r, domain, givenTried))
	if len(givenFound) > 0 {
		result, foundSelectors := dkimFoundResult(ctx, r, domain, givenFound, opts)
		return result, givenTried, foundSelectors
	}

	commonTried := dkimSelectorCandidates(nil, opts.Deep)
	commonFound, commonErrors := collectDKIMLookupResults(lookupDKIMSelectors(ctx, r, domain, commonTried))
	tried := combinedSelectors(givenTried, commonTried)
	if len(commonFound) > 0 {
		result, foundSelectors := dkimFoundResult(ctx, r, domain, commonFound, opts)
		result.Status = model.StatusWarn
		result.Summary = "DKIM records found for common selectors, but not for given selectors"
		result.Suggestion = dkimSuggestion(opts.Deep)
		result.Details = append(result.Details, givenErrors...)
		return result, tried, foundSelectors
	}

	lookupErrors := append(givenErrors, commonErrors...)
	return model.CheckResult{
		Name:       "DKIM",
		Status:     model.StatusFail,
		Summary:    "DKIM records were not found for given selectors",
		Details:    limitedLookupErrors(lookupErrors),
		Suggestion: dkimSuggestion(opts.Deep),
	}, tried, nil
}

func collectDKIMLookupResults(results []dkimLookupResult) ([]dkimLookupResult, []string) {
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

	return found, lookupErrors
}

func dkimFoundResult(ctx context.Context, r dns.Resolver, domain string, found []dkimLookupResult, opts DKIMOptions) (model.CheckResult, []string) {
	foundSelectors := make([]string, 0, len(found))
	details := make([]string, 0, len(found)+1)
	for _, result := range found {
		foundSelectors = append(foundSelectors, result.selector)
		details = append(details, result.fqdn)
	}

	details = append(details, detectProviderHints(ctx, r, domain, foundSelectors)...)

	return model.CheckResult{
		Name:    "DKIM",
		Status:  model.StatusPass,
		Summary: dkimSelectorSourceSummary(foundSelectors, opts),
		Details: details,
	}, foundSelectors
}

func limitedLookupErrors(lookupErrors []string) []string {
	if len(lookupErrors) > 5 {
		return append(lookupErrors[:5], fmt.Sprintf("and %d more lookup errors", len(lookupErrors)-5))
	}

	return lookupErrors
}

func dkimSuggestion(deep bool) string {
	if deep {
		return "Try --selector <name> or use a selector from a real DKIM-Signature header."
	}

	return "Try --selector <name>, --dkim-deep, or use a selector from a real DKIM-Signature header."
}

func dkimSelectorSourceSummary(foundSelectors []string, opts DKIMOptions) string {
	given := selectorSet(opts.Selectors)
	common := selectorSet(dkimSelectorCandidates(nil, opts.Deep))

	foundGivenOnly := false
	foundCommonOnly := false
	foundGivenAndCommon := false
	for _, selector := range foundSelectors {
		selector = normalizeSelector(selector)
		_, isGiven := given[selector]
		_, isCommon := common[selector]

		switch {
		case isGiven && isCommon:
			foundGivenAndCommon = true
		case isGiven:
			foundGivenOnly = true
		case isCommon:
			foundCommonOnly = true
		}
	}

	switch {
	case foundGivenOnly && foundCommonOnly:
		return "DKIM records found for given selectors and common selectors"
	case foundGivenAndCommon:
		return "DKIM records found for a given selector that is also common"
	case foundGivenOnly:
		return "DKIM records found for given selectors"
	default:
		return "DKIM records found for common selectors"
	}
}

func selectorSet(selectors []string) map[string]struct{} {
	set := make(map[string]struct{}, len(selectors))
	for _, selector := range selectors {
		selector = normalizeSelector(selector)
		if selector == "" {
			continue
		}

		set[selector] = struct{}{}
	}

	return set
}

func givenDKIMSelectors(selectors []string) []string {
	seen := make(map[string]struct{}, len(selectors))
	candidates := make([]string, 0, len(selectors))
	for _, selector := range selectors {
		selector = normalizeSelector(selector)
		if selector == "" {
			continue
		}
		if _, ok := seen[selector]; ok {
			continue
		}

		seen[selector] = struct{}{}
		candidates = append(candidates, selector)
	}

	return candidates
}

func combinedSelectors(first []string, second []string) []string {
	seen := make(map[string]struct{}, len(first)+len(second))
	combined := make([]string, 0, len(first)+len(second))
	add := func(selector string) {
		selector = normalizeSelector(selector)
		if selector == "" {
			return
		}
		if _, ok := seen[selector]; ok {
			return
		}

		seen[selector] = struct{}{}
		combined = append(combined, selector)
	}

	for _, selector := range first {
		add(selector)
	}
	for _, selector := range second {
		add(selector)
	}

	return combined
}

func lookupDKIMSelectors(ctx context.Context, r dns.Resolver, domain string, selectors []string) []dkimLookupResult {
	lookupCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan dkimLookupResult, len(selectors))
	jobs := make(chan dkimLookupResult, len(selectors))
	for index, selector := range selectors {
		jobs <- dkimLookupResult{index: index, selector: selector}
	}
	close(jobs)

	var wg sync.WaitGroup
	for range min(dkimConcurrentLookups, len(selectors)) {
		wg.Go(func() {
			for job := range jobs {
				select {
				case <-lookupCtx.Done():
					results <- dkimLookupResult{index: job.index, selector: job.selector, err: lookupCtx.Err()}
					continue
				default:
				}

				fqdn := job.selector + "._domainkey." + domain
				txts, err := r.LookupTXT(lookupCtx, fqdn)
				if err != nil {
					results <- dkimLookupResult{
						index:    job.index,
						selector: job.selector,
						fqdn:     fqdn,
						err:      err,
					}
					continue
				}

				results <- dkimLookupResult{
					index:    job.index,
					selector: job.selector,
					fqdn:     fqdn,
					records:  matchingDKIMRecords(txts),
				}
			}
		})
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	ordered := make([]dkimLookupResult, len(selectors))
	collected := make([]bool, len(selectors))
	for result := range results {
		ordered[result.index] = result
		collected[result.index] = true
		if len(result.records) > 0 {
			cancel()
			return collectedDKIMResults(ordered, collected)
		}
	}

	return ordered
}

func collectedDKIMResults(results []dkimLookupResult, collected []bool) []dkimLookupResult {
	ordered := make([]dkimLookupResult, 0, len(results))
	for index, result := range results {
		if collected[index] {
			ordered = append(ordered, result)
		}
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
