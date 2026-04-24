package main

import (
	"context"
	"errors"
	"net"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/AHaldner/mailcheck/internal/cli"
	internaldns "github.com/AHaldner/mailcheck/internal/dns"
	"github.com/AHaldner/mailcheck/internal/help"
	"github.com/AHaldner/mailcheck/internal/model"
	appversion "github.com/AHaldner/mailcheck/internal/version"
)

func TestRunVersionPrintsVersion(t *testing.T) {
	oldValue := appversion.Value
	appversion.Value = "v1.2.3"
	defer func() { appversion.Value = oldValue }()

	stdoutFile, err := os.CreateTemp(t.TempDir(), "stdout-version")
	if err != nil {
		t.Fatalf("CreateTemp(stdout) error = %v", err)
	}
	defer stdoutFile.Close()

	stderrFile, err := os.CreateTemp(t.TempDir(), "stderr-version")
	if err != nil {
		t.Fatalf("CreateTemp(stderr) error = %v", err)
	}
	defer stderrFile.Close()

	code := run([]string{"--version"}, stdoutFile, stderrFile)
	if code != 0 {
		t.Fatalf("run() code = %d, want 0", code)
	}

	stdoutData, err := os.ReadFile(stdoutFile.Name())
	if err != nil {
		t.Fatalf("ReadFile(stdout) error = %v", err)
	}

	if strings.TrimSpace(string(stdoutData)) != "v1.2.3" {
		t.Fatalf("stdout = %q, want %q", strings.TrimSpace(string(stdoutData)), "v1.2.3")
	}
}

func TestRunShortVersionPrintsVersion(t *testing.T) {
	oldValue := appversion.Value
	appversion.Value = "v1.2.3"
	defer func() { appversion.Value = oldValue }()

	stdoutFile, err := os.CreateTemp(t.TempDir(), "stdout-short-version")
	if err != nil {
		t.Fatalf("CreateTemp(stdout) error = %v", err)
	}
	defer stdoutFile.Close()

	stderrFile, err := os.CreateTemp(t.TempDir(), "stderr-short-version")
	if err != nil {
		t.Fatalf("CreateTemp(stderr) error = %v", err)
	}
	defer stderrFile.Close()

	code := run([]string{"-v"}, stdoutFile, stderrFile)
	if code != 0 {
		t.Fatalf("run() code = %d, want 0", code)
	}

	stdoutData, err := os.ReadFile(stdoutFile.Name())
	if err != nil {
		t.Fatalf("ReadFile(stdout) error = %v", err)
	}

	if strings.TrimSpace(string(stdoutData)) != "v1.2.3" {
		t.Fatalf("stdout = %q, want %q", strings.TrimSpace(string(stdoutData)), "v1.2.3")
	}
}

func TestRunHelpPrintsHelp(t *testing.T) {
	stdoutFile, err := os.CreateTemp(t.TempDir(), "stdout-help")
	if err != nil {
		t.Fatalf("CreateTemp(stdout) error = %v", err)
	}
	defer stdoutFile.Close()

	stderrFile, err := os.CreateTemp(t.TempDir(), "stderr-help")
	if err != nil {
		t.Fatalf("CreateTemp(stderr) error = %v", err)
	}
	defer stderrFile.Close()

	code := run([]string{"--help"}, stdoutFile, stderrFile)
	if code != 0 {
		t.Fatalf("run() code = %d, want 0", code)
	}

	stdoutData, err := os.ReadFile(stdoutFile.Name())
	if err != nil {
		t.Fatalf("ReadFile(stdout) error = %v", err)
	}

	if strings.TrimSpace(string(stdoutData)) != help.GetHelp() {
		t.Fatalf("stdout = %q, want %q", strings.TrimSpace(string(stdoutData)), help.GetHelp())
	}
}

func TestRunHelpWithDomainPrintsHelpToStderr(t *testing.T) {
	stdoutFile, err := os.CreateTemp(t.TempDir(), "stdout-help-invalid")
	if err != nil {
		t.Fatalf("CreateTemp(stdout) error = %v", err)
	}
	defer stdoutFile.Close()

	stderrFile, err := os.CreateTemp(t.TempDir(), "stderr-help-invalid")
	if err != nil {
		t.Fatalf("CreateTemp(stderr) error = %v", err)
	}
	defer stderrFile.Close()

	code := run([]string{"--help", "example.com"}, stdoutFile, stderrFile)
	if code != 2 {
		t.Fatalf("run() code = %d, want 2", code)
	}

	stderrData, err := os.ReadFile(stderrFile.Name())
	if err != nil {
		t.Fatalf("ReadFile(stderr) error = %v", err)
	}

	want := help.GetHelp() + "\n\nerror: --help does not accept a domain argument"
	if strings.TrimSpace(string(stderrData)) != want {
		t.Fatalf("stderr = %q, want %q", strings.TrimSpace(string(stderrData)), want)
	}
}

func TestRunDoesNotEmitProgressToNonTTYStderr(t *testing.T) {
	stdoutFile, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatalf("CreateTemp(stdout) error = %v", err)
	}
	defer stdoutFile.Close()

	stderrFile, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatalf("CreateTemp(stderr) error = %v", err)
	}
	defer stderrFile.Close()

	code := run([]string{"example.com"}, stdoutFile, stderrFile)
	if code != 1 {
		t.Fatalf("run() code = %d, want 1", code)
	}

	stderrData, err := os.ReadFile(stderrFile.Name())
	if err != nil {
		t.Fatalf("ReadFile(stderr) error = %v", err)
	}

	if strings.Contains(string(stderrData), "MX") {
		t.Fatalf("stderr contained progress output:\n%s", string(stderrData))
	}
}

func TestRunJSONDoesNotEmitProgress(t *testing.T) {
	stdoutFile, err := os.CreateTemp(t.TempDir(), "stdout-json")
	if err != nil {
		t.Fatalf("CreateTemp(stdout) error = %v", err)
	}
	defer stdoutFile.Close()

	stderrFile, err := os.CreateTemp(t.TempDir(), "stderr-json")
	if err != nil {
		t.Fatalf("CreateTemp(stderr) error = %v", err)
	}
	defer stderrFile.Close()

	_ = run([]string{"example.com", "--json"}, stdoutFile, stderrFile)

	stderrData, err := os.ReadFile(stderrFile.Name())
	if err != nil {
		t.Fatalf("ReadFile(stderr) error = %v", err)
	}

	if strings.Contains(string(stderrData), "[") {
		t.Fatalf("stderr contained progress output in json mode:\n%s", string(stderrData))
	}
}

func TestRunChecksDefaultsToCoreChecks(t *testing.T) {
	result := runChecks(context.Background(), mainFakeResolver{}, cli.Options{Domain: "example.com"})
	got := checkNames(result.Checks)
	want := []string{"MX", "SPF", "DMARC", "DKIM"}

	if !slices.Equal(got, want) {
		t.Fatalf("check names = %v, want %v", got, want)
	}
}

func TestRunChecksAdvancedIncludesDiagnostics(t *testing.T) {
	result := runChecks(context.Background(), mainFakeResolver{}, cli.Options{Domain: "example.com", Advanced: true})
	got := checkNames(result.Checks)
	want := []string{"MX", "SPF", "DMARC", "DKIM", "MX-A", "MX-AAAA", "PTR", "NS", "SOA", "DNSSEC", "DNS-TIME"}

	if !slices.Equal(got, want) {
		t.Fatalf("check names = %v, want %v", got, want)
	}
}

func checkNames(checks []model.CheckResult) []string {
	names := make([]string, 0, len(checks))
	for _, check := range checks {
		names = append(names, check.Name)
	}

	return names
}

type mainFakeResolver struct{}

func (mainFakeResolver) LookupMX(_ context.Context, domain string) ([]*net.MX, error) {
	if domain != "example.com" {
		return nil, errors.New("not found")
	}

	return []*net.MX{{Host: "mx.example.com.", Pref: 10}}, nil
}

func (mainFakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	switch name {
	case "example.com":
		return []string{"v=spf1 -all"}, nil
	case "_dmarc.example.com":
		return []string{"v=DMARC1; p=reject"}, nil
	case "google._domainkey.example.com":
		return []string{"v=DKIM1; p=abc123"}, nil
	default:
		return nil, errors.New("not found")
	}
}

func (mainFakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	switch host {
	case "mx.example.com.", "mail.example.com.":
		return []net.IPAddr{{IP: net.ParseIP("192.0.2.10")}}, nil
	default:
		return nil, errors.New("not found")
	}
}

func (mainFakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if addr == "192.0.2.10" {
		return []string{"mail.example.com."}, nil
	}

	return nil, errors.New("not found")
}

func (mainFakeResolver) LookupNS(_ context.Context, name string) ([]*net.NS, error) {
	if name == "example.com" {
		return []*net.NS{{Host: "ns1.example.com."}}, nil
	}

	return nil, errors.New("not found")
}

func (mainFakeResolver) LookupSOA(_ context.Context, _ string) (*internaldns.SOA, error) {
	return nil, internaldns.ErrUnsupported
}

func (mainFakeResolver) LookupDNSSEC(_ context.Context, _ string) (internaldns.DNSSECStatus, error) {
	return internaldns.DNSSECStatus{Validated: false, Source: "test resolver"}, nil
}

func (mainFakeResolver) QueryMetrics() []internaldns.QueryMetric {
	return []internaldns.QueryMetric{{Name: "example.com", Type: "MX", DurationMS: 12}}
}
