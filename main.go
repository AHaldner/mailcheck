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
		if _, err := fmt.Fprintln(stdout, appversion.Current()); err != nil {
			fmt.Fprintf(stderr, "error: failed to write version: %v\n", err)
			return 1
		}
		return 0
	}

	if opts.Help {
		if _, err := fmt.Fprintln(stdout, help.GetHelp()); err != nil {
			fmt.Fprintf(stderr, "error: failed to write help: %v\n", err)
			return 1
		}
		return 0
	}

	if err := cli.ValidateDomain(opts.Domain); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	resolver := dns.NewNetResolver()
	progress := ui.NewProgressWriter(stderr, !opts.JSON && !opts.NoProgress, !opts.NoColor)

	results := make([]model.CheckResult, 0, 4)
	progress.Start("MX")
	results = append(results, checks.CheckMX(ctx, resolver, opts.Domain))

	progress.Start("SPF")
	results = append(results, checks.CheckSPF(ctx, resolver, opts.Domain))

	progress.Start("DMARC")
	results = append(results, checks.CheckDMARC(ctx, resolver, opts.Domain))

	progress.Start("DKIM")
	dkimResult, selectorsTried, selectorsFound := checks.CheckDKIM(ctx, resolver, opts.Domain, opts.Selectors)
	results = append(results, dkimResult)

	runResult := model.RunResult{
		Domain:             opts.Domain,
		Checks:             results,
		DKIMSelectorsTried: selectorsTried,
		DKIMSelectorsFound: selectorsFound,
	}
	runResult.Rating = model.RatingFromChecks(runResult.Checks)
	progress.Finish()

	var output string
	if opts.JSON {
		output, err = report.RenderJSON(runResult)
	} else {
		output, err = report.RenderText(runResult, opts.NoColor)
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

func hasFail(checks []model.CheckResult) bool {
	for _, check := range checks {
		if check.Status == model.StatusFail {
			return true
		}
	}

	return false
}
