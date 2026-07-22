package main

import (
	"context"
	"errors"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AHaldner/mailcheck/internal/cli"
	internaldns "github.com/AHaldner/mailcheck/internal/dns"
	"github.com/AHaldner/mailcheck/internal/model"
	"github.com/AHaldner/mailcheck/internal/update"
	appversion "github.com/AHaldner/mailcheck/internal/version"
)

func TestRunUpgrade(t *testing.T) {
	oldVersion := appversion.Value
	appversion.Value = "v1.2.3"
	t.Cleanup(func() { appversion.Value = oldVersion })

	tests := []struct {
		name       string
		result     update.Result
		err        error
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{
			name:       "changed",
			result:     update.Result{From: "v1.2.3", To: "v1.3.0", Changed: true},
			wantCode:   0,
			wantStdout: "upgraded mailcheck from v1.2.3 to v1.3.0\n",
		},
		{
			name:       "unchanged",
			result:     update.Result{From: "v1.2.3", To: "v1.2.3"},
			wantCode:   0,
			wantStdout: "mailcheck is already up to date (v1.2.3)\n",
		},
		{
			name:       "error",
			err:        errors.New("permission denied"),
			wantCode:   1,
			wantStderr: "error: failed to upgrade mailcheck: permission denied\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldUpgrade := upgradeMailcheck
			t.Cleanup(func() { upgradeMailcheck = oldUpgrade })

			var gotCurrent string
			upgradeMailcheck = func(_ context.Context, current string) (update.Result, error) {
				gotCurrent = current
				return tt.result, tt.err
			}

			var stdout strings.Builder
			var stderr strings.Builder
			code := run([]string{"upgrade"}, &stdout, &stderr)

			if code != tt.wantCode {
				t.Fatalf("run() code = %d, want %d", code, tt.wantCode)
			}
			if gotCurrent != "v1.2.3" {
				t.Fatalf("upgrade current = %q, want %q", gotCurrent, "v1.2.3")
			}
			if got := stdout.String(); got != tt.wantStdout {
				t.Fatalf("stdout = %q, want %q", got, tt.wantStdout)
			}
			if got := stderr.String(); got != tt.wantStderr {
				t.Fatalf("stderr = %q, want %q", got, tt.wantStderr)
			}
		})
	}
}

func TestRunUpdateNoticeAfterFailingTextReport(t *testing.T) {
	oldVersion := appversion.Value
	appversion.Value = "v1.2.3"
	t.Cleanup(func() { appversion.Value = oldVersion })

	oldCheck := checkUpdateNotice
	t.Cleanup(func() { checkUpdateNotice = oldCheck })

	const notice = `A new mailcheck version is available: v1.3.0 (current: v1.2.3). Run "mailcheck upgrade".`
	var stdout strings.Builder
	var stderr strings.Builder
	var gotCurrent string
	calledBeforeReport := false
	checkUpdateNotice = func(_ context.Context, current string) string {
		gotCurrent = current
		calledBeforeReport = stdout.Len() == 0
		return notice
	}

	code := run([]string{"example.com", "--timeout", "1ns", "--no-progress", "--no-color"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("run() code = %d, want 1", code)
	}
	if gotCurrent != "v1.2.3" {
		t.Fatalf("notice current = %q, want %q", gotCurrent, "v1.2.3")
	}
	if calledBeforeReport {
		t.Fatal("update notice checked before report was written")
	}
	if strings.Contains(stdout.String(), notice) {
		t.Fatalf("stdout contained update notice:\n%s", stdout.String())
	}
	if got := stderr.String(); got != notice+"\n" {
		t.Fatalf("stderr = %q, want %q", got, notice+"\n")
	}
}

func TestRunUpdateNoticeExclusions(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "json", args: []string{"example.com", "--json", "--timeout", "1ns", "--no-progress"}},
		{name: "help", args: []string{"--help"}},
		{name: "version", args: []string{"--version"}},
		{name: "upgrade", args: []string{"upgrade"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldCheck := checkUpdateNotice
			t.Cleanup(func() { checkUpdateNotice = oldCheck })
			called := false
			checkUpdateNotice = func(context.Context, string) string {
				called = true
				return "unexpected notice"
			}

			if tt.name == "upgrade" {
				oldUpgrade := upgradeMailcheck
				t.Cleanup(func() { upgradeMailcheck = oldUpgrade })
				upgradeMailcheck = func(context.Context, string) (update.Result, error) {
					return update.Result{From: "v1.2.3", To: "v1.2.3"}, nil
				}
			}

			var stdout strings.Builder
			var stderr strings.Builder
			_ = run(tt.args, &stdout, &stderr)

			if called {
				t.Fatalf("checkUpdateNotice called for %s mode", tt.name)
			}
		})
	}
}

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

	if strings.TrimSpace(string(stdoutData)) != cli.Help() {
		t.Fatalf("stdout = %q, want %q", strings.TrimSpace(string(stdoutData)), cli.Help())
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

	want := cli.Help() + "\n\nerror: --help does not accept a domain argument"
	if strings.TrimSpace(string(stderrData)) != want {
		t.Fatalf("stderr = %q, want %q", strings.TrimSpace(string(stderrData)), want)
	}
}

func TestRunDoesNotEmitProgressToNonTTYStderr(t *testing.T) {
	oldCheck := checkUpdateNotice
	checkUpdateNotice = func(context.Context, string) string { return "" }
	t.Cleanup(func() { checkUpdateNotice = oldCheck })

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

func TestRunChecksUsesCallerTimeoutForDKIM(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := runChecks(ctx, dkimDeadlineResolver{}, cli.Options{Domain: "example.com"})
	dkim := checkByName(result.Checks, "DKIM")
	if dkim.Status != model.StatusPass {
		t.Fatalf("DKIM status = %s, want PASS; summary = %q details = %v", dkim.Status, dkim.Summary, dkim.Details)
	}
}

func TestRunChecksNoCacheBypassesCachedResolver(t *testing.T) {
	resolver := &countingMainResolver{}

	result := runChecks(context.Background(), resolver, cli.Options{
		Domain:   "example.com",
		Advanced: true,
		NoCache:  true,
	})

	if got := checkNames(result.Checks); !slices.Equal(got, []string{"MX", "SPF", "DMARC", "DKIM", "MX-A", "MX-AAAA", "PTR", "NS", "SOA", "DNSSEC", "DNS-TIME"}) {
		t.Fatalf("check names = %v", got)
	}

	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	if resolver.mxCalls <= 1 {
		t.Fatalf("LookupMX calls = %d, want repeated uncached lookups", resolver.mxCalls)
	}
}

func TestRunChecksStartsCoreChecksConcurrently(t *testing.T) {
	resolver := newConcurrentStartResolver()
	done := make(chan model.RunResult, 1)

	go func() {
		done <- runChecks(context.Background(), resolver, cli.Options{Domain: "example.com"})
	}()

	wantStarted := map[string]bool{
		"mx":    false,
		"spf":   false,
		"dmarc": false,
		"dkim":  false,
	}
	deadline := time.After(500 * time.Millisecond)
	for {
		if allStarted(wantStarted) {
			close(resolver.release)
			break
		}

		select {
		case name := <-resolver.started:
			wantStarted[name] = true
		case <-deadline:
			t.Fatalf("checks did not start concurrently; started = %v", wantStarted)
		}
	}

	select {
	case result := <-done:
		if got := checkNames(result.Checks); !slices.Equal(got, []string{"MX", "SPF", "DMARC", "DKIM"}) {
			t.Fatalf("check names = %v", got)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("runChecks did not finish after releasing lookups")
	}
}

func checkNames(checks []model.CheckResult) []string {
	names := make([]string, 0, len(checks))
	for _, check := range checks {
		names = append(names, check.Name)
	}

	return names
}

func checkByName(checks []model.CheckResult, name string) model.CheckResult {
	for _, check := range checks {
		if check.Name == name {
			return check
		}
	}

	return model.CheckResult{}
}

func allStarted(started map[string]bool) bool {
	for _, ok := range started {
		if !ok {
			return false
		}
	}

	return true
}

type mainFakeResolver struct{}

type dkimDeadlineResolver struct {
	mainFakeResolver
}

type countingMainResolver struct {
	mainFakeResolver
	mu      sync.Mutex
	mxCalls int
}

type concurrentStartResolver struct {
	mainFakeResolver
	started chan string
	release chan struct{}
}

func newConcurrentStartResolver() *concurrentStartResolver {
	return &concurrentStartResolver{
		started: make(chan string, 4),
		release: make(chan struct{}),
	}
}

func (r *concurrentStartResolver) waitForRelease(name string) {
	select {
	case r.started <- name:
	default:
	}
	<-r.release
}

func (r *concurrentStartResolver) LookupMX(ctx context.Context, domain string) ([]*net.MX, error) {
	if domain == "example.com" {
		r.waitForRelease("mx")
	}

	return r.mainFakeResolver.LookupMX(ctx, domain)
}

func (r *concurrentStartResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	switch name {
	case "example.com":
		r.waitForRelease("spf")
	case "_dmarc.example.com":
		r.waitForRelease("dmarc")
	case "google._domainkey.example.com":
		r.waitForRelease("dkim")
	}

	return r.mainFakeResolver.LookupTXT(ctx, name)
}

func (dkimDeadlineResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if name != "google._domainkey.example.com" {
		return mainFakeResolver{}.LookupTXT(ctx, name)
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, errors.New("missing deadline")
	}
	if time.Until(deadline) < 5*time.Second {
		return nil, errors.New("deadline too short")
	}

	return []string{"v=DKIM1; p=abc123"}, nil
}

func (r *countingMainResolver) LookupMX(ctx context.Context, domain string) ([]*net.MX, error) {
	r.mu.Lock()
	r.mxCalls++
	r.mu.Unlock()

	return r.mainFakeResolver.LookupMX(ctx, domain)
}

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
