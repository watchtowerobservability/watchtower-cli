package main

import (
	"context"
	"fmt"
	"io"
)

// mergeRetry folds the results of a retry run into run: a monitor that passed on retry replaces
// its failure and is marked flaky; one that failed again keeps the newest error. The run status
// is recomputed (a pending monitor keeps it failed, as it was).
func mergeRetry(run *runDoc, retry runDoc) {
	byID := map[string]runResult{}
	for _, r := range retry.Results {
		byID[r.MonitorID] = r
	}
	failed := false
	for i, r := range run.Results {
		if n, ok := byID[r.MonitorID]; ok && r.Status == "failed" {
			n.Flaky = n.Status == "passed"
			run.Results[i] = n
			r = n
		}
		failed = failed || r.Status != "passed"
	}
	if !failed {
		run.Status = "passed"
	}
}

// runWithRetries is runChecks that re-runs only the failed monitors up to retries more times
// (needs wait). Monitors that pass on a retry are reported as flaky; the exit code then passes.
func runWithRetries(ctx context.Context, o runOpts, retries int, out io.Writer) (runDoc, error) {
	run, err := runChecks(ctx, o, out)
	for n := 1; err == nil && o.wait && run.Status == "failed" && n <= retries; n++ {
		var ids []string
		for _, r := range run.Results {
			if r.Status == "failed" {
				ids = append(ids, r.MonitorID)
			}
		}
		fmt.Fprintf(out, "retry %d/%d of %d failed check(s)\n", n, retries, len(ids))
		o2 := o
		o2.ids = ids
		var retry runDoc
		if retry, err = runChecks(ctx, o2, out); err != nil {
			break
		}
		mergeRetry(&run, retry)
	}
	for _, r := range run.Results {
		if r.Flaky {
			fmt.Fprintf(out, "FLAKY %s (passed on retry)\n", r.Name)
		}
	}
	return run, err
}
