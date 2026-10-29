package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Exit codes of `wtctl release gate`.
const (
	gatePass    = 0
	gateFail    = 1
	gateTimeout = 2 // still pending at the deadline, or insufficient data
)

type gateOpts struct {
	api, key, project, version string
	wait                       bool
	timeout, poll              time.Duration
}

type gateResult struct {
	GateName string `json:"gate_name"`
	EnvID    string `json:"env_id"`
	Verdict  string `json:"verdict"`
}

// gateVerdict folds the results: any fail wins (no need to wait for the rest), then any
// pending or insufficient_data, else pass. No gates apply means pass.
func gateVerdict(rs []gateResult) (code int, pending bool) {
	insufficient := false
	for _, r := range rs {
		switch r.Verdict {
		case "fail":
			return gateFail, false
		case "pending":
			pending = true
		case "pass":
		default:
			insufficient = true
		}
	}
	if pending || insufficient {
		return gateTimeout, pending
	}
	return gatePass, false
}

// gateCheck reads the gate results of a release; with wait it polls until none is pending or
// the timeout elapses (exit 2).
func gateCheck(ctx context.Context, o gateOpts, out io.Writer) (int, error) {
	u := strings.TrimRight(o.api, "/") + "/v1/projects/" + o.project + "/releases/" + url.PathEscape(o.version) + "/gates"
	deadline := time.Now().Add(o.timeout)
	for {
		var res struct {
			Data []gateResult `json:"data"`
		}
		if err := call(ctx, http.MethodGet, u, o.key, nil, &res); err != nil {
			return gateTimeout, err
		}
		code, pending := gateVerdict(res.Data)
		if !pending || !o.wait || code == gateFail {
			for _, r := range res.Data {
				fmt.Fprintf(out, "gate %s (env %s): %s\n", r.GateName, r.EnvID, r.Verdict)
			}
			return code, nil
		}
		if !time.Now().Add(o.poll).Before(deadline) {
			fmt.Fprintf(out, "timed out after %s with gates pending\n", o.timeout)
			return gateTimeout, nil
		}
		select {
		case <-ctx.Done():
			return gateTimeout, ctx.Err()
		case <-time.After(o.poll):
		}
	}
}

// gateMain runs `wtctl release gate <version> ...` and returns the process exit code.
func gateMain(ctx context.Context, args []string, out io.Writer) (int, error) {
	if len(args) < 1 || strings.HasPrefix(args[0], "-") {
		return gateTimeout, errors.New("usage: wtctl release gate <version> --api <url> --key <key> --project <prj_...> [--wait] [--timeout 30m]")
	}
	o := gateOpts{version: args[0]}
	fs := flag.NewFlagSet("release gate", flag.ContinueOnError)
	fs.StringVar(&o.api, "api", "", "API base URL")
	fs.StringVar(&o.key, "key", os.Getenv("WT_API_KEY"), "API key; default $WT_API_KEY")
	fs.StringVar(&o.project, "project", "", "project id")
	fs.BoolVar(&o.wait, "wait", false, "wait for gates that are still pending")
	fs.DurationVar(&o.timeout, "timeout", 30*time.Minute, "how long --wait waits")
	fs.DurationVar(&o.poll, "poll", 15*time.Second, "poll interval with --wait")
	if err := fs.Parse(args[1:]); err != nil {
		return gateTimeout, err
	}
	if o.api == "" || o.key == "" || o.project == "" {
		return gateTimeout, errors.New("--api, --key and --project are required")
	}
	if o.poll <= 0 {
		o.poll = time.Second
	}
	return gateCheck(ctx, o, out)
}
