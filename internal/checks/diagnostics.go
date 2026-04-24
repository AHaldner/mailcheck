package checks

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/AHaldner/mailcheck/internal/dns"
	"github.com/AHaldner/mailcheck/internal/model"
)

const slowDNSQueryMS int64 = 1000

func CheckMXA(ctx context.Context, r dns.Resolver, domain string) model.CheckResult {
	return checkMXAddressFamily(ctx, r, domain, "MX-A", false)
}

func CheckMXAAAA(ctx context.Context, r dns.Resolver, domain string) model.CheckResult {
	return checkMXAddressFamily(ctx, r, domain, "MX-AAAA", true)
}

func checkMXAddressFamily(ctx context.Context, r dns.Resolver, domain string, name string, ipv6 bool) model.CheckResult {
	mxs, err := r.LookupMX(ctx, domain)
	if err != nil {
		return model.CheckResult{
			Name:    name,
			Status:  model.StatusWarn,
			Summary: lookupFailureSummary(name, domain, err),
		}
	}
	if len(mxs) == 0 {
		return model.CheckResult{
			Name:    name,
			Status:  model.StatusWarn,
			Summary: missingRecordSummary(name, domain),
		}
	}

	sortMX(mxs)
	matches := make([]string, 0)
	for _, mx := range mxs {
		ips, err := r.LookupIPAddr(ctx, mx.Host)
		if err != nil {
			continue
		}

		for _, ip := range ips {
			isIPv6 := ip.IP.To4() == nil
			if isIPv6 != ipv6 {
				continue
			}

			matches = append(matches, ip.IP.String())
		}
	}
	sort.Strings(matches)

	if len(matches) == 0 {
		reason := "MX hosts do not have IPv4"
		if ipv6 {
			reason = "MX hosts do not have IPv6"
		}

		return model.CheckResult{
			Name:    name,
			Status:  model.StatusWarn,
			Summary: reason,
		}
	}

	summary := "MX hosts have IPv4"
	if ipv6 {
		summary = "MX hosts have IPv6"
	}

	return model.CheckResult{
		Name:    name,
		Status:  model.StatusPass,
		Summary: summary,
		Details: []string{fmt.Sprintf("%s addresses via %s: %s", name, domain, strings.Join(matches, ", "))},
	}
}

func CheckPTR(ctx context.Context, r dns.Resolver, domain string) model.CheckResult {
	mxs, err := r.LookupMX(ctx, domain)
	if err != nil {
		return model.CheckResult{
			Name:    "PTR",
			Status:  model.StatusWarn,
			Summary: lookupFailureSummary("PTR", domain, err),
		}
	}
	if len(mxs) == 0 {
		return model.CheckResult{
			Name:    "PTR",
			Status:  model.StatusWarn,
			Summary: "PTR via " + domain + " [0 MX targets]: no reverse DNS checked",
		}
	}

	sortMX(mxs)
	details := make([]string, 0)
	missing := 0
	checked := 0

	for _, mx := range mxs {
		ips, err := r.LookupIPAddr(ctx, mx.Host)
		if err != nil || len(ips) == 0 {
			continue
		}

		for _, ip := range ips {
			checked++
			addr := ip.IP.String()
			names, err := r.LookupAddr(ctx, addr)
			if err != nil || len(names) == 0 {
				missing++
				details = append(details, fmt.Sprintf("%s missing reverse DNS", addr))
				continue
			}

			forwardConfirmed := false
			for _, name := range names {
				if ptrNameContainsIP(ctx, r, name, ip.IP) {
					forwardConfirmed = true
					break
				}
			}

			sort.Strings(names)
			if forwardConfirmed {
				details = append(details, fmt.Sprintf("%s PTR %s forward-confirmed", addr, strings.Join(names, ", ")))
				continue
			}

			missing++
			details = append(details, fmt.Sprintf("%s PTR %s not forward-confirmed", addr, strings.Join(names, ", ")))
		}
	}

	if checked == 0 {
		return model.CheckResult{
			Name:    "PTR",
			Status:  model.StatusWarn,
			Summary: "PTR via " + domain + " [0 addresses]: no MX target addresses resolved",
			Details: details,
		}
	}

	if missing > 0 {
		return model.CheckResult{
			Name:    "PTR",
			Status:  model.StatusWarn,
			Summary: fmt.Sprintf("%d reverse DNS issue(s) found", missing),
			Details: details,
		}
	}

	return model.CheckResult{
		Name:    "PTR",
		Status:  model.StatusPass,
		Summary: "Reverse DNS forward-confirms",
		Details: details,
	}
}

func ptrNameContainsIP(ctx context.Context, r dns.Resolver, name string, want net.IP) bool {
	ips, err := r.LookupIPAddr(ctx, name)
	if err != nil {
		return false
	}

	for _, ip := range ips {
		if ip.IP.Equal(want) {
			return true
		}
	}

	return false
}

func CheckNS(ctx context.Context, r dns.Resolver, domain string) model.CheckResult {
	records, err := r.LookupNS(ctx, domain)
	if err != nil {
		return model.CheckResult{
			Name:    "NS",
			Status:  model.StatusWarn,
			Summary: lookupFailureSummary("NS", domain, err),
		}
	}
	if len(records) == 0 {
		return model.CheckResult{
			Name:    "NS",
			Status:  model.StatusWarn,
			Summary: missingRecordSummary("NS", domain),
		}
	}

	hosts := make([]string, 0, len(records))
	for _, record := range records {
		hosts = append(hosts, record.Host)
	}
	sort.Strings(hosts)

	if len(hosts) == 1 {
		return model.CheckResult{
			Name:    "NS",
			Status:  model.StatusPass,
			Summary: "1 authoritative nameserver found",
			Details: []string{fmt.Sprintf("NS via %s: %s", domain, hosts[0])},
		}
	}

	return model.CheckResult{
		Name:    "NS",
		Status:  model.StatusPass,
		Summary: fmt.Sprintf("%d authoritative nameservers found", len(hosts)),
		Details: []string{fmt.Sprintf("NS via %s: %s", domain, strings.Join(hosts, ", "))},
	}
}

func CheckSOA(ctx context.Context, r dns.Resolver, domain string) model.CheckResult {
	record, err := r.LookupSOA(ctx, domain)
	if err != nil {
		status := model.StatusWarn
		reason := lookupFailureSummary("SOA", domain, err)
		if errors.Is(err, dns.ErrUnsupported) {
			status = model.StatusInfo
			reason = "Not checked: system resolver does not expose SOA records"
		}

		return model.CheckResult{
			Name:    "SOA",
			Status:  status,
			Summary: reason,
		}
	}
	if record == nil {
		return model.CheckResult{
			Name:    "SOA",
			Status:  model.StatusWarn,
			Summary: missingRecordSummary("SOA", domain),
		}
	}

	return model.CheckResult{
		Name:    "SOA",
		Status:  model.StatusPass,
		Summary: "SOA record found",
		Details: []string{fmt.Sprintf("SOA via %s: ns=%s serial=%d", domain, record.NS, record.Serial)},
	}
}

func CheckDNSSEC(ctx context.Context, r dns.Resolver, domain string) model.CheckResult {
	status, err := r.LookupDNSSEC(ctx, domain)
	if err != nil {
		return model.CheckResult{
			Name:    "DNSSEC",
			Status:  model.StatusInfo,
			Summary: "Not checked: DNSSEC validation status unavailable",
			Details: []string{lookupErrorDetail("DNSSEC", err)},
		}
	}
	if !status.Validated {
		return model.CheckResult{
			Name:    "DNSSEC",
			Status:  model.StatusWarn,
			Summary: "DNSSEC not validated by resolver",
			Details: []string{status.Source},
		}
	}

	return model.CheckResult{
		Name:    "DNSSEC",
		Status:  model.StatusPass,
		Summary: "Validated by DNS resolver",
		Details: []string{status.Source},
	}
}

func CheckDNSTime(r dns.MetricsResolver) model.CheckResult {
	metrics := r.QueryMetrics()
	if len(metrics) == 0 {
		return model.CheckResult{
			Name:    "DNS-TIME",
			Status:  model.StatusPass,
			Summary: "DNS query timing [0 queries]: no timings recorded",
		}
	}

	slow := make([]string, 0)
	for _, metric := range metrics {
		if metric.DurationMS < slowDNSQueryMS {
			continue
		}

		slow = append(slow, fmt.Sprintf("%s %s: %dms", metric.Type, metric.Name, metric.DurationMS))
	}

	if len(slow) == 0 {
		return model.CheckResult{
			Name:    "DNS-TIME",
			Status:  model.StatusPass,
			Summary: fmt.Sprintf("DNS query timing [%d queries]: no slow queries", len(metrics)),
		}
	}

	return model.CheckResult{
		Name:    "DNS-TIME",
		Status:  model.StatusWarn,
		Summary: fmt.Sprintf("%d slow DNS response(s) observed", len(slow)),
		Details: slow,
	}
}
