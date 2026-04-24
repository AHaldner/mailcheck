package checks

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	internaldns "github.com/AHaldner/mailcheck/internal/dns"
	"github.com/AHaldner/mailcheck/internal/model"
)

type fakeResolver struct {
	mx      map[string][]*net.MX
	txt     map[string][]string
	ips     map[string][]net.IPAddr
	ptr     map[string][]string
	ns      map[string][]*net.NS
	soa     map[string]*internaldns.SOA
	dnssec  map[string]internaldns.DNSSECStatus
	mxErr   map[string]error
	txtErr  map[string]error
	ipErr   map[string]error
	ptrErr  map[string]error
	nsErr   map[string]error
	soaErr  map[string]error
	dnsErr  map[string]error
	metrics []internaldns.QueryMetric
}

func (f fakeResolver) LookupMX(_ context.Context, domain string) ([]*net.MX, error) {
	if err := f.mxErr[domain]; err != nil {
		return nil, err
	}

	return f.mx[domain], nil
}

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if err := f.txtErr[name]; err != nil {
		return nil, err
	}

	return f.txt[name], nil
}

func (f fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if err := f.ipErr[host]; err != nil {
		return nil, err
	}

	return f.ips[host], nil
}

func (f fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if err := f.ptrErr[addr]; err != nil {
		return nil, err
	}

	return f.ptr[addr], nil
}

func (f fakeResolver) LookupNS(_ context.Context, name string) ([]*net.NS, error) {
	if err := f.nsErr[name]; err != nil {
		return nil, err
	}

	return f.ns[name], nil
}

func (f fakeResolver) LookupSOA(_ context.Context, name string) (*internaldns.SOA, error) {
	if err := f.soaErr[name]; err != nil {
		return nil, err
	}

	return f.soa[name], nil
}

func (f fakeResolver) LookupDNSSEC(_ context.Context, name string) (internaldns.DNSSECStatus, error) {
	if err := f.dnsErr[name]; err != nil {
		return internaldns.DNSSECStatus{}, err
	}

	return f.dnssec[name], nil
}

func (f fakeResolver) QueryMetrics() []internaldns.QueryMetric {
	return f.metrics
}

func TestCheckSPFFailsOnMultipleRecords(t *testing.T) {
	r := fakeResolver{
		txt: map[string][]string{
			"example.com": {
				"v=spf1 include:_spf.one ~all",
				"v=spf1 include:_spf.two ~all",
			},
		},
	}

	got := CheckSPF(context.Background(), r, "example.com")
	if got.Status != model.StatusFail {
		t.Fatalf("status = %s, want FAIL", got.Status)
	}

	if !slices.Equal(got.Details, []string{
		"record 1: v=spf1 include:_spf.one ~all",
		"record 2: v=spf1 include:_spf.two ~all",
	}) {
		t.Fatalf("details = %v", got.Details)
	}
}

func TestCheckSPFWarnsWithoutTerminalMechanism(t *testing.T) {
	r := fakeResolver{
		txt: map[string][]string{
			"example.com": {"v=spf1 include:_spf.example.com"},
		},
	}

	got := CheckSPF(context.Background(), r, "example.com")
	if got.Status != model.StatusWarn {
		t.Fatalf("status = %s, want WARN", got.Status)
	}

	if !strings.Contains(got.Summary, "missing terminal all mechanism") {
		t.Fatalf("summary = %q, want missing terminal policy warning", got.Summary)
	}
}

func TestCheckSPFPassesWithRedirectPolicy(t *testing.T) {
	r := fakeResolver{
		txt: map[string][]string{
			"example.com": {"v=spf1 redirect=_spf.example.com"},
		},
	}

	got := CheckSPF(context.Background(), r, "example.com")
	if got.Status != model.StatusPass {
		t.Fatalf("status = %s, want PASS", got.Status)
	}

	if got.Summary != "SPF is valid and delegates with redirect" {
		t.Fatalf("summary = %q, want human-readable SPF pass", got.Summary)
	}
}

func TestCheckDMARCFailsWithoutPolicy(t *testing.T) {
	r := fakeResolver{
		txt: map[string][]string{
			"_dmarc.example.com": {"v=DMARC1; rua=mailto:d@example.com"},
		},
	}

	got := CheckDMARC(context.Background(), r, "example.com")
	if got.Status != model.StatusFail {
		t.Fatalf("status = %s, want FAIL", got.Status)
	}

	if !slices.Equal(got.Details, []string{"record 1: v=DMARC1; rua=mailto:d@example.com"}) {
		t.Fatalf("details = %v", got.Details)
	}
}

func TestCheckDMARCWarnsForNonePolicy(t *testing.T) {
	r := fakeResolver{
		txt: map[string][]string{
			"_dmarc.example.com": {"v=DMARC1; p=none; rua=mailto:d@example.com"},
		},
	}

	got := CheckDMARC(context.Background(), r, "example.com")
	if got.Status != model.StatusWarn {
		t.Fatalf("status = %s, want WARN", got.Status)
	}

	if got.Summary != "Policy is monitoring only (p=none)" {
		t.Fatalf("summary = %q, want p=none warning", got.Summary)
	}

	if got.Suggestion != "Switch to quarantine or reject after reviewing reports." {
		t.Fatalf("suggestion = %q, want DMARC action", got.Suggestion)
	}
}

func TestCheckDMARCFailsForInvalidPolicy(t *testing.T) {
	r := fakeResolver{
		txt: map[string][]string{
			"_dmarc.example.com": {"v=DMARC1; p=monitor"},
		},
	}

	got := CheckDMARC(context.Background(), r, "example.com")
	if got.Status != model.StatusFail {
		t.Fatalf("status = %s, want FAIL", got.Status)
	}

	if !strings.Contains(got.Summary, "invalid p= policy") {
		t.Fatalf("summary = %q, want invalid policy summary", got.Summary)
	}
}

func TestCheckDMARCAcceptsPolicyCaseInsensitively(t *testing.T) {
	r := fakeResolver{
		txt: map[string][]string{
			"_dmarc.example.com": {"v=DMARC1; p=Reject"},
		},
	}

	got := CheckDMARC(context.Background(), r, "example.com")
	if got.Status != model.StatusPass {
		t.Fatalf("status = %s, want PASS", got.Status)
	}
}

func TestCheckMXFailsWithFriendlyLookupSummary(t *testing.T) {
	r := fakeResolver{
		mxErr: map[string]error{
			"example.com": errors.New("no such host"),
		},
	}

	got := CheckMX(context.Background(), r, "example.com")
	if got.Status != model.StatusFail {
		t.Fatalf("status = %s, want FAIL", got.Status)
	}

	if got.Summary != "MX via example.com [lookup failed]: domain not found in DNS" {
		t.Fatalf("summary = %q", got.Summary)
	}
}

func TestCheckMXFailsWhenTargetsDoNotResolve(t *testing.T) {
	r := fakeResolver{
		mx: map[string][]*net.MX{
			"example.com": {{Host: "mx1.example.com.", Pref: 10}},
		},
		ipErr: map[string]error{
			"mx1.example.com.": errors.New("no such host"),
		},
	}

	got := CheckMX(context.Background(), r, "example.com")
	if got.Status != model.StatusFail {
		t.Fatalf("status = %s, want FAIL", got.Status)
	}

	if got.Summary != "1 mail server found, but none resolve to IP addresses" {
		t.Fatalf("summary = %q, want address failure", got.Summary)
	}
}

func TestCheckMXReportsNullMXAsNoMailAccepted(t *testing.T) {
	r := fakeResolver{
		mx: map[string][]*net.MX{
			"example.com": {{Host: ".", Pref: 0}},
		},
	}

	got := CheckMX(context.Background(), r, "example.com")
	if got.Status != model.StatusFail {
		t.Fatalf("status = %s, want FAIL", got.Status)
	}

	if got.Summary != "Domain publishes a null MX and does not accept mail" {
		t.Fatalf("summary = %q, want null MX summary", got.Summary)
	}
}

func TestCheckMXPassesWhenAtLeastOneTargetResolves(t *testing.T) {
	r := fakeResolver{
		mx: map[string][]*net.MX{
			"example.com": {
				{Host: "mx1.example.com.", Pref: 10},
				{Host: "mx2.example.com.", Pref: 20},
			},
		},
		ips: map[string][]net.IPAddr{
			"mx1.example.com.": {
				{IP: net.ParseIP("192.0.2.10")},
				{IP: net.ParseIP("2001:db8::10")},
			},
		},
		ipErr: map[string]error{
			"mx2.example.com.": errors.New("no such host"),
		},
	}

	got := CheckMX(context.Background(), r, "example.com")
	if got.Status != model.StatusPass {
		t.Fatalf("status = %s, want PASS", got.Status)
	}

	if !containsSubstring(got.Details, "mx1.example.com. A/AAAA: 192.0.2.10, 2001:db8::10") {
		t.Fatalf("details = %v, want resolved MX target addresses", got.Details)
	}
}

func TestCheckMXAPassesWhenAnyMXTargetHasIPv4(t *testing.T) {
	r := fakeResolver{
		mx: map[string][]*net.MX{
			"example.com": {{Host: "mx1.example.com.", Pref: 10}},
		},
		ips: map[string][]net.IPAddr{
			"mx1.example.com.": {
				{IP: net.ParseIP("192.0.2.10")},
				{IP: net.ParseIP("2001:db8::10")},
			},
		},
	}

	got := CheckMXA(context.Background(), r, "example.com")
	if got.Status != model.StatusPass {
		t.Fatalf("status = %s, want PASS", got.Status)
	}

	if got.Summary != "MX hosts have IPv4" {
		t.Fatalf("summary = %q, want IPv4 summary", got.Summary)
	}
	if !containsSubstring(got.Details, "192.0.2.10") {
		t.Fatalf("details = %v, want IPv4 address", got.Details)
	}
}

func TestCheckMXAReportsNullMXAsNotApplicable(t *testing.T) {
	r := fakeResolver{
		mx: map[string][]*net.MX{
			"example.com": {{Host: ".", Pref: 0}},
		},
	}

	got := CheckMXA(context.Background(), r, "example.com")
	if got.Status != model.StatusInfo {
		t.Fatalf("status = %s, want INFO", got.Status)
	}

	if got.Summary != "Not checked: domain publishes a null MX and does not accept mail" {
		t.Fatalf("summary = %q, want null MX diagnostic summary", got.Summary)
	}
}

func TestCheckMXAAAAWarnsWhenNoMXTargetHasIPv6(t *testing.T) {
	r := fakeResolver{
		mx: map[string][]*net.MX{
			"example.com": {{Host: "mx1.example.com.", Pref: 10}},
		},
		ips: map[string][]net.IPAddr{
			"mx1.example.com.": {{IP: net.ParseIP("192.0.2.10")}},
		},
	}

	got := CheckMXAAAA(context.Background(), r, "example.com")
	if got.Status != model.StatusWarn {
		t.Fatalf("status = %s, want WARN", got.Status)
	}

	if !strings.Contains(got.Summary, "do not have IPv6") {
		t.Fatalf("summary = %q, want no IPv6 warning", got.Summary)
	}
}

func TestCheckMXUsesHelperHostForSubdomain(t *testing.T) {
	r := fakeResolver{
		mxErr: map[string]error{
			"notifications.example.com": errors.New("no such host"),
		},
		mx: map[string][]*net.MX{
			"send.notifications.example.com": {
				{Host: "feedback-smtp.eu-west-1.amazonses.com.", Pref: 10},
			},
		},
		ips: map[string][]net.IPAddr{
			"feedback-smtp.eu-west-1.amazonses.com.": {{IP: net.ParseIP("192.0.2.25")}},
		},
	}

	got := CheckMX(context.Background(), r, "notifications.example.com")
	if got.Status != model.StatusPass {
		t.Fatalf("status = %s, want PASS", got.Status)
	}

	if !containsSubstring(got.Details, "MX via send.notifications.example.com") {
		t.Fatalf("details = %v, want helper host", got.Details)
	}
}

func TestCheckSPFUsesHelperHostForSubdomain(t *testing.T) {
	r := fakeResolver{
		txtErr: map[string]error{
			"notifications.example.com": errors.New("no such host"),
		},
		txt: map[string][]string{
			"send.notifications.example.com": {"v=spf1 include:amazonses.com ~all"},
		},
	}

	got := CheckSPF(context.Background(), r, "notifications.example.com")
	if got.Status != model.StatusPass {
		t.Fatalf("status = %s, want PASS", got.Status)
	}

	if !containsSubstring(got.Details, "SPF via send.notifications.example.com") {
		t.Fatalf("details = %v, want helper host", got.Details)
	}
}

func TestCheckDMARCInheritsFromParentDomain(t *testing.T) {
	r := fakeResolver{
		txtErr: map[string]error{
			"_dmarc.notifications.example.com": errors.New("no such host"),
		},
		txt: map[string][]string{
			"_dmarc.example.com": {"v=DMARC1; p=quarantine; rua=mailto:d@example.com"},
		},
	}

	got := CheckDMARC(context.Background(), r, "notifications.example.com")
	if got.Status != model.StatusPass {
		t.Fatalf("status = %s, want PASS", got.Status)
	}

	if !containsSubstring(got.Details, "DMARC via example.com") {
		t.Fatalf("details = %v, want inherited DMARC", got.Details)
	}
}

func TestDKIMDefaultCandidatesStayBoundedAndIncludeExplicitSelectors(t *testing.T) {
	got := dkimSelectorCandidates([]string{"custom"}, false)

	if len(got) > 40 {
		t.Fatalf("len(got) = %d, want default DKIM candidate set to stay bounded", len(got))
	}

	for _, selector := range []string{"google", "default", "selector1", "k3", "custom"} {
		if !containsString(got, selector) {
			t.Fatalf("candidates missing %q: %v", selector, got)
		}
	}
}

func TestDKIMDefaultCandidatesIncludeCurrentGmailSelector(t *testing.T) {
	got := dkimSelectorCandidates(nil, false)

	if !containsString(got, "20230601") {
		t.Fatalf("default candidates missing current Gmail selector 20230601: %v", got)
	}
}

func TestDKIMExplicitSelectorsAreTriedFirst(t *testing.T) {
	got := dkimSelectorCandidates([]string{"custom", "google"}, false)

	wantPrefix := []string{"custom", "google"}
	if !slices.Equal(got[:len(wantPrefix)], wantPrefix) {
		t.Fatalf("candidate prefix = %v, want %v", got[:len(wantPrefix)], wantPrefix)
	}
}

func TestDKIMDeepCandidatesUseExtendedSelectorSweep(t *testing.T) {
	fast := dkimSelectorCandidates(nil, false)
	deep := dkimSelectorCandidates(nil, true)

	if len(deep) <= len(fast) {
		t.Fatalf("len(deep) = %d, len(fast) = %d; want deep selector sweep to include more candidates", len(deep), len(fast))
	}

	if !containsString(deep, "scph0923") {
		t.Fatalf("deep candidates missing curated selector scph0923")
	}
}

func TestCheckDKIMWarnsWhenNoSelectorMatches(t *testing.T) {
	r := fakeResolver{
		txtErr: map[string]error{
			"default._domainkey.example.com":   errors.New("not found"),
			"selector1._domainkey.example.com": errors.New("SERVFAIL"),
		},
	}

	got, tried, found := CheckDKIM(context.Background(), r, "example.com", DKIMOptions{Selectors: []string{"default", "selector1"}})
	if got.Status != model.StatusWarn {
		t.Fatalf("status = %s, want WARN", got.Status)
	}

	if len(tried) < 2 {
		t.Fatalf("len(tried) = %d, want at least 2", len(tried))
	}

	if len(found) != 0 {
		t.Fatalf("len(found) = %d, want 0", len(found))
	}

	if got.Summary != "DKIM records were not found for guessed selectors" {
		t.Fatalf("summary = %q, want DKIM uncertainty", got.Summary)
	}

	if !containsString(got.Details, "selector selector1 [lookup failed]: SERVFAIL") {
		t.Fatalf("details = %v, want friendly DKIM lookup detail", got.Details)
	}
}

func TestCheckDKIMPassesAndReturnsFoundSelectors(t *testing.T) {
	r := fakeResolver{
		txt: map[string][]string{
			"resend._domainkey.example.com": {
				"v=DKIM1; k=rsa; p=abc123",
			},
			"send.example.com": {
				"v=spf1 include:amazonses.com ~all",
			},
		},
		mx: map[string][]*net.MX{
			"send.example.com": {
				{Host: "feedback-smtp.eu-west-1.amazonses.com.", Pref: 10},
			},
		},
	}

	got, tried, found := CheckDKIM(context.Background(), r, "example.com", DKIMOptions{})
	if got.Status != model.StatusPass {
		t.Fatalf("status = %s, want PASS", got.Status)
	}

	if len(tried) == 0 {
		t.Fatal("len(tried) = 0, want candidates")
	}

	if len(found) != 1 || found[0] != "resend" {
		t.Fatalf("found = %v, want [resend]", found)
	}

	if got.Summary != "DKIM records found for common selectors" {
		t.Fatalf("summary = %q, want resend selector", got.Summary)
	}

	if !containsString(got.Details, "resend._domainkey.example.com") {
		t.Fatalf("details = %v, want resend fqdn", got.Details)
	}

	if !containsSubstring(got.Details, "Resend helper host: send.example.com") {
		t.Fatalf("details = %v, want resend helper host detail", got.Details)
	}
}

func TestCheckDKIMReturnsAfterFirstMatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct {
		result model.CheckResult
		found  []string
	}, 1)
	go func() {
		result, _, found := CheckDKIM(ctx, blockingDKIMResolver{}, "example.com", DKIMOptions{
			Selectors: []string{"custom"},
		})
		done <- struct {
			result model.CheckResult
			found  []string
		}{result: result, found: found}
	}()

	select {
	case got := <-done:
		if got.result.Status != model.StatusPass {
			t.Fatalf("status = %s, want PASS", got.result.Status)
		}
		if !slices.Equal(got.found, []string{"custom"}) {
			t.Fatalf("found = %v, want [custom]", got.found)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("CheckDKIM waited for slow missing selectors after finding a valid DKIM record")
	}
}

func TestCheckDKIMIgnoresInvalidRecords(t *testing.T) {
	r := fakeResolver{
		txt: map[string][]string{
			"default._domainkey.example.com": {
				"v=DKIM1; p=",
			},
			"selector1._domainkey.example.com": {
				"v=TLSRPTv1; rua=mailto:reports@example.com",
			},
		},
	}

	got, _, found := CheckDKIM(context.Background(), r, "example.com", DKIMOptions{Selectors: []string{"default", "selector1"}})
	if got.Status != model.StatusWarn {
		t.Fatalf("status = %s, want WARN", got.Status)
	}

	if len(found) != 0 {
		t.Fatalf("found = %v, want no selectors", found)
	}
}

type blockingDKIMResolver struct {
	fakeResolver
}

func (blockingDKIMResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if name == "custom._domainkey.example.com" {
		return []string{"v=DKIM1; p=abc123"}, nil
	}

	<-ctx.Done()
	return nil, ctx.Err()
}

func TestCheckPTRPassesWithForwardConfirmedReverseDNS(t *testing.T) {
	r := fakeResolver{
		mx: map[string][]*net.MX{
			"example.com": {{Host: "mx1.example.com.", Pref: 10}},
		},
		ips: map[string][]net.IPAddr{
			"mx1.example.com.":  {{IP: net.ParseIP("192.0.2.10")}},
			"mail.example.com.": {{IP: net.ParseIP("192.0.2.10")}},
		},
		ptr: map[string][]string{
			"192.0.2.10": {"mail.example.com."},
		},
	}

	got := CheckPTR(context.Background(), r, "example.com")
	if got.Status != model.StatusPass {
		t.Fatalf("status = %s, want PASS", got.Status)
	}

	if !containsSubstring(got.Details, "192.0.2.10 PTR mail.example.com. forward-confirmed") {
		t.Fatalf("details = %v, want forward-confirmed PTR detail", got.Details)
	}
}

func TestCheckPTRWarnsWhenReverseDNSIsMissing(t *testing.T) {
	r := fakeResolver{
		mx: map[string][]*net.MX{
			"example.com": {{Host: "mx1.example.com.", Pref: 10}},
		},
		ips: map[string][]net.IPAddr{
			"mx1.example.com.": {{IP: net.ParseIP("2001:db8::10")}},
		},
		ptrErr: map[string]error{
			"2001:db8::10": errors.New("no such host"),
		},
	}

	got := CheckPTR(context.Background(), r, "example.com")
	if got.Status != model.StatusWarn {
		t.Fatalf("status = %s, want WARN", got.Status)
	}

	if !strings.Contains(got.Summary, "reverse DNS issue") {
		t.Fatalf("summary = %q, want missing reverse DNS warning", got.Summary)
	}
}

func TestCheckNSPassesWithAuthoritativeNameservers(t *testing.T) {
	r := fakeResolver{
		ns: map[string][]*net.NS{
			"example.com": {{Host: "ns1.example.com."}, {Host: "ns2.example.com."}},
		},
	}

	got := CheckNS(context.Background(), r, "example.com")
	if got.Status != model.StatusPass {
		t.Fatalf("status = %s, want PASS", got.Status)
	}

	if !strings.Contains(got.Summary, "2 authoritative nameservers") {
		t.Fatalf("summary = %q, want NS count", got.Summary)
	}
}

func TestCheckSOAWarnsWhenResolverDoesNotSupportSOA(t *testing.T) {
	r := fakeResolver{
		soaErr: map[string]error{
			"example.com": internaldns.ErrUnsupported,
		},
	}

	got := CheckSOA(context.Background(), r, "example.com")
	if got.Status != model.StatusInfo {
		t.Fatalf("status = %s, want INFO", got.Status)
	}

	if !strings.Contains(got.Summary, "Not checked") {
		t.Fatalf("summary = %q, want unsupported summary", got.Summary)
	}
}

func TestCheckSOAPassesWithSOARecord(t *testing.T) {
	r := fakeResolver{
		soa: map[string]*internaldns.SOA{
			"example.com": {NS: "ns1.example.com.", Serial: 2026042401},
		},
	}

	got := CheckSOA(context.Background(), r, "example.com")
	if got.Status != model.StatusPass {
		t.Fatalf("status = %s, want PASS", got.Status)
	}

	if got.Summary != "SOA record found" {
		t.Fatalf("summary = %q, want SOA pass", got.Summary)
	}
}

func TestCheckDNSSECPassesWhenResolverValidated(t *testing.T) {
	r := fakeResolver{
		dnssec: map[string]internaldns.DNSSECStatus{
			"example.com": {Validated: true, Source: "resolver AD bit"},
		},
	}

	got := CheckDNSSEC(context.Background(), r, "example.com")
	if got.Status != model.StatusPass {
		t.Fatalf("status = %s, want PASS", got.Status)
	}

	if got.Summary != "Validated by DNS resolver" {
		t.Fatalf("summary = %q, want validated summary", got.Summary)
	}
}

func TestCheckDNSSECWarnsWhenResolverDoesNotValidate(t *testing.T) {
	r := fakeResolver{
		dnssec: map[string]internaldns.DNSSECStatus{
			"example.com": {Validated: false, Source: "resolver AD bit"},
		},
	}

	got := CheckDNSSEC(context.Background(), r, "example.com")
	if got.Status != model.StatusWarn {
		t.Fatalf("status = %s, want WARN", got.Status)
	}

	if !strings.Contains(got.Summary, "not validated") {
		t.Fatalf("summary = %q, want not validated summary", got.Summary)
	}
}

func TestCheckDNSTimeWarnsOnSlowQueries(t *testing.T) {
	r := fakeResolver{
		metrics: []internaldns.QueryMetric{
			{Name: "example.com", Type: "MX", DurationMS: 120},
			{Name: "example.com", Type: "TXT", DurationMS: 1700},
		},
	}

	got := CheckDNSTime(r)
	if got.Status != model.StatusWarn {
		t.Fatalf("status = %s, want WARN", got.Status)
	}

	if !containsSubstring(got.Details, "TXT example.com: 1700ms") {
		t.Fatalf("details = %v, want slow query detail", got.Details)
	}
}

func containsString(values []string, want string) bool {
	return slices.Contains(values, want)
}

func containsSubstring(values []string, want string) bool {
	for _, value := range values {
		if strings.Contains(value, want) {
			return true
		}
	}

	return false
}
