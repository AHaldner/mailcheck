package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"

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
	resolver = dns.NewCachedResolver(resolver)

	start := func(name string) {
		if len(progress) > 0 && progress[0] != nil {
			progress[0].Start(name)
		}
	}

	capacity := 4
	if opts.Advanced {
		capacity = 11
	}

	results := make([]model.CheckResult, capacity)
	selectorsTried := []string(nil)
	selectorsFound := []string(nil)

	runBatch(start, []checkTask{
		{
			name: "MX",
			run: func() model.CheckResult {
				return checks.CheckMX(ctx, resolver, opts.Domain)
			},
		},
		{
			name: "SPF",
			run: func() model.CheckResult {
				return checks.CheckSPF(ctx, resolver, opts.Domain)
			},
		},
		{
			name: "DMARC",
			run: func() model.CheckResult {
				return checks.CheckDMARC(ctx, resolver, opts.Domain)
			},
		},
		{
			name: "DKIM",
			run: func() model.CheckResult {
				result, tried, found := checks.CheckDKIM(ctx, resolver, opts.Domain, checks.DKIMOptions{
					Selectors: opts.Selectors,
					Deep:      opts.DeepDKIM,
				})
				selectorsTried = tried
				selectorsFound = found
				return result
			},
		},
	}, results)

	if opts.Advanced {
		runBatch(start, []checkTask{
			{
				name: "MX-A",
				run: func() model.CheckResult {
					return checks.CheckMXA(ctx, resolver, opts.Domain)
				},
			},
			{
				name: "MX-AAAA",
				run: func() model.CheckResult {
					return checks.CheckMXAAAA(ctx, resolver, opts.Domain)
				},
			},
			{
				name: "PTR",
				run: func() model.CheckResult {
					return checks.CheckPTR(ctx, resolver, opts.Domain)
				},
			},
			{
				name: "NS",
				run: func() model.CheckResult {
					return checks.CheckNS(ctx, resolver, opts.Domain)
				},
			},
			{
				name: "SOA",
				run: func() model.CheckResult {
					return checks.CheckSOA(ctx, resolver, opts.Domain)
				},
			},
			{
				name: "DNSSEC",
				run: func() model.CheckResult {
					return checks.CheckDNSSEC(ctx, resolver, opts.Domain)
				},
			},
		}, results[4:])
		start("DNS-TIME")
		results[10] = checks.CheckDNSTime(resolver)
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

type checkTask struct {
	name string
	run  func() model.CheckResult
}

func runBatch(start func(string), tasks []checkTask, results []model.CheckResult) {
	var wg sync.WaitGroup
	for index, task := range tasks {
		start(task.name)
		wg.Add(1)

		go func(index int, task checkTask) {
			defer wg.Done()
			results[index] = task.run()
		}(index, task)
	}

	wg.Wait()
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
