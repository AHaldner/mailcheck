package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/AHaldner/mailcheck/internal/checks"
	"github.com/AHaldner/mailcheck/internal/cli"
	"github.com/AHaldner/mailcheck/internal/dns"
	"github.com/AHaldner/mailcheck/internal/help"
	"github.com/AHaldner/mailcheck/internal/model"
	"github.com/AHaldner/mailcheck/internal/report"
	"github.com/AHaldner/mailcheck/internal/ui"
	appversion "github.com/AHaldner/mailcheck/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	opts, err := cli.ParseArgs(args, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	if opts.Version {
		return writeFlagOutput(stdout, stderr, "version", appversion.Current())
	}

	if opts.Help {
		return writeFlagOutput(stdout, stderr, "help", help.GetHelp())
	}

	if err := cli.ValidateDomain(opts.Domain); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	resolver := dns.NewNetResolver()
	progress := ui.NewProgressWriter(stderr, !opts.JSON && !opts.NoProgress, !opts.NoColor, checkCount(opts))

	runResult := runChecks(ctx, resolver, opts, progress)
	progress.Finish()

	var output string
	if opts.JSON {
		output, err = report.RenderJSON(runResult)
	} else {
		output, err = report.RenderText(runResult, report.TextOptions{
			NoColor: opts.NoColor,
			Details: opts.Details,
		})
	}

	if err != nil {
		fmt.Fprintf(stderr, "error: failed to render report: %v\n", err)
		return 1
	}

	if _, err := fmt.Fprintln(stdout, output); err != nil {
		fmt.Fprintf(stderr, "error: failed to write report: %v\n", err)
		return 1
	}

	if hasFail(runResult.Checks) {
		return 1
	}

	return 0
}

type checkResolver interface {
	dns.Resolver
	dns.MetricsResolver
}

type progressStarter interface {
	Start(name string)
}

func runChecks(ctx context.Context, resolver checkResolver, opts cli.Options, progress ...progressStarter) model.RunResult {
	start := func(name string) {
		if len(progress) > 0 && progress[0] != nil {
			progress[0].Start(name)
		}
	}

	capacity := 4
	if opts.Advanced {
		capacity = 11
	}

	results := make([]model.CheckResult, 0, capacity)
	start("MX")
	results = append(results, checks.CheckMX(ctx, resolver, opts.Domain))

	start("SPF")
	results = append(results, checks.CheckSPF(ctx, resolver, opts.Domain))

	start("DMARC")
	results = append(results, checks.CheckDMARC(ctx, resolver, opts.Domain))

	start("DKIM")
	dkimCtx, dkimCancel := context.WithTimeout(ctx, cli.DefaultDKIMTimeout)
	dkimResult, selectorsTried, selectorsFound := checks.CheckDKIM(dkimCtx, resolver, opts.Domain, checks.DKIMOptions{
		Selectors: opts.Selectors,
		Deep:      opts.DeepDKIM,
	})
	dkimCancel()
	results = append(results, dkimResult)

	if opts.Advanced {
		start("MX-A")
		results = append(results, checks.CheckMXA(ctx, resolver, opts.Domain))

		start("MX-AAAA")
		results = append(results, checks.CheckMXAAAA(ctx, resolver, opts.Domain))

		start("PTR")
		results = append(results, checks.CheckPTR(ctx, resolver, opts.Domain))

		start("NS")
		results = append(results, checks.CheckNS(ctx, resolver, opts.Domain))

		start("SOA")
		results = append(results, checks.CheckSOA(ctx, resolver, opts.Domain))

		start("DNSSEC")
		results = append(results, checks.CheckDNSSEC(ctx, resolver, opts.Domain))

		start("DNS-TIME")
		results = append(results, checks.CheckDNSTime(resolver))
	}

	runResult := model.RunResult{
		Domain:             opts.Domain,
		Checks:             results,
		DKIMSelectorsTried: selectorsTried,
		DKIMSelectorsFound: selectorsFound,
	}
	runResult.Rating, runResult.RatingReason = model.RatingFromChecksWithReason(runResult.Checks)

	return runResult
}

func checkCount(opts cli.Options) int {
	if opts.Advanced {
		return 11
	}

	return 4
}

func hasFail(checks []model.CheckResult) bool {
	for _, check := range checks {
		if check.Status == model.StatusFail {
			return true
		}
	}

	return false
}

func writeFlagOutput(stdout io.Writer, stderr io.Writer, name string, value string) int {
	if _, err := fmt.Fprintln(stdout, value); err != nil {
		fmt.Fprintf(stderr, "error: failed to write %s: %v\n", name, err)
		return 1
	}

	return 0
}
