package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"mailcheck/internal/checks"
	"mailcheck/internal/cli"
	"mailcheck/internal/dns"
	"mailcheck/internal/model"
	"mailcheck/internal/report"
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

	if err := cli.ValidateDomain(opts.Domain); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	resolver := dns.NewNetResolver()
	results := []model.CheckResult{
		checks.CheckMX(ctx, resolver, opts.Domain),
		checks.CheckSPF(ctx, resolver, opts.Domain),
		checks.CheckDMARC(ctx, resolver, opts.Domain),
	}
	dkimResult, selectorsTried, selectorsFound := checks.CheckDKIM(ctx, resolver, opts.Domain, opts.Selectors)
	results = append(results, dkimResult)

	runResult := model.RunResult{
		Domain:             opts.Domain,
		Checks:             results,
		DKIMSelectorsTried: selectorsTried,
		DKIMSelectorsFound: selectorsFound,
	}
	runResult.Rating = model.RatingFromChecks(runResult.Checks)

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
