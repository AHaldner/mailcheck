package checks

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"

	"mailcheck/internal/model"
)

type fakeResolver struct {
	mx     map[string][]*net.MX
	txt    map[string][]string
	mxErr  map[string]error
	txtErr map[string]error
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
	}

	got := CheckMX(context.Background(), r, "notifications.example.com")
	if got.Status != model.StatusPass {
		t.Fatalf("status = %s, want PASS", got.Status)
	}

	if !strings.Contains(got.Summary, "send.notifications.example.com") {
		t.Fatalf("summary = %q, want helper host", got.Summary)
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

	if !strings.Contains(got.Summary, "send.notifications.example.com") {
		t.Fatalf("summary = %q, want helper host", got.Summary)
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

	if !strings.Contains(got.Summary, "inherited DMARC policy from example.com") {
		t.Fatalf("summary = %q, want inherited DMARC", got.Summary)
	}
}

func TestCheckDKIMFailsWhenNoSelectorMatches(t *testing.T) {
	r := fakeResolver{
		txtErr: map[string]error{
			"default._domainkey.example.com":   errors.New("not found"),
			"selector1._domainkey.example.com": errors.New("not found"),
		},
	}

	got, tried, found := CheckDKIM(context.Background(), r, "example.com", []string{"default", "selector1"})
	if got.Status != model.StatusFail {
		t.Fatalf("status = %s, want FAIL", got.Status)
	}

	if len(tried) < 2 {
		t.Fatalf("len(tried) = %d, want at least 2", len(tried))
	}

	if len(found) != 0 {
		t.Fatalf("len(found) = %d, want 0", len(found))
	}

	if !strings.Contains(got.Summary, "no DKIM record found") {
		t.Fatalf("summary = %q, want DKIM miss", got.Summary)
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

	got, tried, found := CheckDKIM(context.Background(), r, "example.com", nil)
	if got.Status != model.StatusPass {
		t.Fatalf("status = %s, want PASS", got.Status)
	}

	if len(tried) == 0 {
		t.Fatal("len(tried) = 0, want candidates")
	}

	if len(found) != 1 || found[0] != "resend" {
		t.Fatalf("found = %v, want [resend]", found)
	}

	if !strings.Contains(got.Summary, "resend") {
		t.Fatalf("summary = %q, want resend selector", got.Summary)
	}

	if !containsString(got.Details, "resend._domainkey.example.com") {
		t.Fatalf("details = %v, want resend fqdn", got.Details)
	}

	if !containsSubstring(got.Details, "detected Resend helper host send.example.com") {
		t.Fatalf("details = %v, want resend helper host detail", got.Details)
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

	got, _, found := CheckDKIM(context.Background(), r, "example.com", []string{"default", "selector1"})
	if got.Status != model.StatusFail {
		t.Fatalf("status = %s, want FAIL", got.Status)
	}

	if len(found) != 0 {
		t.Fatalf("found = %v, want no selectors", found)
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
