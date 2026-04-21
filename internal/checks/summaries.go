package checks

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
)

func lookupFailureSummary(name string, source string, err error) string {
	switch {
	case isNotFoundError(err):
		return fmt.Sprintf("%s via %s [lookup failed]: domain not found in DNS", name, source)
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Sprintf("%s via %s [lookup failed]: lookup timed out", name, source)
	case errors.Is(err, context.Canceled):
		return fmt.Sprintf("%s via %s [lookup failed]: lookup canceled", name, source)
	default:
		return fmt.Sprintf("%s via %s [lookup failed]: %v", name, source, err)
	}
}

func missingRecordSummary(name string, source string) string {
	return fmt.Sprintf("%s via %s [0 records]: no %s record found", name, source, name)
}

func multipleRecordsSummary(name string, source string, count int) string {
	return fmt.Sprintf("%s via %s [%d records]: multiple %s records found", name, source, count, name)
}

func invalidRecordSummary(name string, source string, reason string) string {
	return fmt.Sprintf("%s via %s [invalid record]: %s", name, source, reason)
}

func lookupErrorDetail(scope string, err error) string {
	switch {
	case isNotFoundError(err):
		return fmt.Sprintf("%s [lookup failed]: domain not found in DNS", scope)
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Sprintf("%s [lookup failed]: lookup timed out", scope)
	case errors.Is(err, context.Canceled):
		return fmt.Sprintf("%s [lookup failed]: lookup canceled", scope)
	default:
		return fmt.Sprintf("%s [lookup failed]: %v", scope, err)
	}
}

func recordDetails(records []string) []string {
	details := make([]string, 0, len(records))
	for index, record := range records {
		details = append(details, fmt.Sprintf("record %d: %s", index+1, record))
	}

	return details
}

func isNotFoundError(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return true
	}

	message := strings.ToLower(err.Error())
	return strings.Contains(message, "no such host") || strings.Contains(message, "nxdomain")
}
