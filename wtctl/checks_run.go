package main

import (
	"context"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Exit codes of `wtctl checks run`.
const (
	exitPass  = 0
	exitFail  = 1 // a check failed
	exitError = 2 // the run could not be started or finished (bad flags, API error, timeout)
)

type runResult struct {
	MonitorID string `json:"monitor_id"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	Error     string `json:"error"`
}

type runDoc struct {
	ID      string      `json:"id"`
	Tag     string      `json:"tag"`
	Status  string      `json:"status"` // running, passed, failed or timed_out
	Results []runResult `json:"results"`
}

type junitSuites struct {
	XMLName xml.Name    `xml:"testsuites"`
	Suites  []junitSute `xml:"testsuite"`
}

type junitSute struct {
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Errors   int         `xml:"errors,attr"`
	Cases    []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name    string     `xml:"name,attr"`
	Class   string     `xml:"classname,attr"`
	Failure *junitFail `xml:"failure,omitempty"`
	Err     *junitFail `xml:"error,omitempty"`
}

type junitFail struct {
	Message string `xml:"message,attr"`
}

// junit renders a run as JUnit XML: one testcase per monitor, a failure for a failed one and an
// error for one that never reported.
func junit(r runDoc) ([]byte, error) {
	s := junitSute{Name: "watchtower checks: " + r.Tag}
	for _, x := range r.Results {
		c := junitCase{Name: x.Name, Class: "watchtower." + r.Tag}
		switch x.Status {
		case "failed":
			s.Failures++
			c.Failure = &junitFail{Message: x.Error}
		case "pending":
			s.Errors++
			c.Err = &junitFail{Message: "no result before the run ended"}
		}
		s.Cases = append(s.Cases, c)
	}
	s.Tests = len(s.Cases)
	out, err := xml.MarshalIndent(junitSuites{Suites: []junitSute{s}}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), out...), nil
}

// exitCode is returned by a subcommand that decides the process exit code itself.
type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

// checksRun is `wtctl checks run` (args after `run`); it returns the process exit code.
func checksRun(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("checks run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	api := fs.String("api", os.Getenv("WT_API"), "API base URL")
	key := fs.String("key", os.Getenv("WT_API_KEY"), "API key (wtk_...)")
	project := fs.String("project", os.Getenv("WT_PROJECT"), "project id")
	tag := fs.String("tag", "ci", "run the monitors with this tag")
	wait := fs.Bool("wait", false, "wait for the result")
	timeout := fs.Duration("timeout", 5*time.Minute, "give up waiting after this long")
	junitPath := fs.String("junit", "", "write JUnit XML here (needs --wait)")
	poll := fs.Duration("poll", 2*time.Second, "poll interval")
	startURL := fs.String("start-url", "", "override the first navigation URL of every monitor (e.g. a PR preview)")
	var vars, locations, ids repeated
	fs.Var(&vars, "var", "override variable K=V (repeatable)")
	fs.Var(&locations, "location", "run only these locations (repeatable)")
	fs.Var(&ids, "id", "run exactly these monitors (mon_…) instead of --tag (repeatable)")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if *api == "" || *key == "" || *project == "" || (*junitPath != "" && !*wait) {
		fmt.Fprintln(stderr, "--api, --key and --project are required; --junit needs --wait")
		return exitError
	}
	varMap := map[string]string{}
	for _, kv := range vars {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			fmt.Fprintf(stderr, "--var %q: want K=V\n", kv)
			return exitError
		}
		varMap[k] = v
	}
	run, err := runChecks(ctx, runOpts{
		api: *api, key: *key, project: *project, tag: *tag, wait: *wait, timeout: *timeout, poll: *poll,
		startURL: *startURL, vars: varMap, locations: locations, ids: ids,
	}, stdout)
	if err != nil {
		fmt.Fprintln(stderr, "checks run failed:", err)
		if *junitPath != "" && run.ID != "" { // CI wants the report most when the run did not finish
			if x, jerr := junit(run); jerr == nil {
				_ = os.WriteFile(*junitPath, x, 0o644)
			}
		}
		return exitError
	}
	if !*wait {
		fmt.Fprintln(stderr, "warning: --wait not set; the exit code does not reflect the checks")
	}
	if *junitPath != "" {
		x, err := junit(run)
		if err == nil {
			err = os.WriteFile(*junitPath, x, 0o644)
		}
		if err != nil {
			fmt.Fprintln(stderr, "junit:", err)
			return exitError
		}
	}
	switch run.Status {
	case "failed":
		return exitFail
	case "passed":
		return exitPass
	case "running":
		return exitPass // started, not waited for
	default:
		return exitError
	}
}

type runOpts struct {
	api, key, project, tag string
	wait                   bool
	timeout, poll          time.Duration
	// D12 CI overrides, recorded on the run and applied to every monitor in it.
	startURL  string
	vars      map[string]string
	locations []string
	ids       []string
}

// body is the POST /check-runs request: the tag or explicit monitor ids, plus any CI overrides.
func (o runOpts) body() map[string]any {
	b := map[string]any{"tag": o.tag}
	if len(o.ids) > 0 {
		b["monitor_ids"] = o.ids
	}
	ov := map[string]any{}
	if o.startURL != "" {
		ov["start_url"] = o.startURL
	}
	if len(o.vars) > 0 {
		ov["variables"] = o.vars
	}
	if len(o.locations) > 0 {
		ov["locations"] = o.locations
	}
	if len(ov) > 0 {
		b["overrides"] = ov
	}
	return b
}

// runChecks starts a run and, with wait, polls it until it is over or the timeout passes (the
// returned run is then still "running", which the caller reports as an error).
func runChecks(ctx context.Context, o runOpts, out io.Writer) (runDoc, error) {
	base := strings.TrimRight(o.api, "/") + "/v1/projects/" + o.project + "/check-runs"
	var run runDoc
	if err := call(ctx, http.MethodPost, base, o.key, o.body(), &run); err != nil {
		return run, err
	}
	fmt.Fprintf(out, "run %s started (%d checks tagged %q)\n", run.ID, len(run.Results), o.tag)
	if !o.wait {
		return run, nil
	}
	deadline := time.Now().Add(o.timeout)
	for run.Status == "running" {
		if time.Now().After(deadline) {
			return run, fmt.Errorf("timed out after %s waiting for run %s", o.timeout, run.ID)
		}
		select {
		case <-ctx.Done():
			return run, ctx.Err()
		case <-time.After(o.poll):
		}
		if err := call(ctx, http.MethodGet, base+"/"+run.ID, o.key, nil, &run); err != nil {
			return run, err
		}
	}
	for _, r := range run.Results {
		if r.Status == "failed" {
			fmt.Fprintf(out, "FAIL %s: %s\n", r.Name, r.Error)
		} else {
			fmt.Fprintf(out, "%s %s\n", strings.ToUpper(r.Status), r.Name)
		}
	}
	fmt.Fprintf(out, "run %s: %s\n", run.ID, run.Status)
	return run, nil
}
