package main

import (
	"context"
	"encoding/json"
	"encoding/xml"
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

// ttRun is one trace test run as the API returns it.
type ttRun struct {
	ID       string `json:"id"`
	TestID   string `json:"test_id"`
	TestName string `json:"test_name"`
	State    string `json:"state"` // pending, running, passed, failed or error
	TraceID  string `json:"trace_id"`
	Result   struct {
		Error      string `json:"error"`
		Assertions []struct {
			Name   string `json:"name"`
			OK     bool   `json:"ok"`
			Detail string `json:"detail"`
		} `json:"assertions"`
	} `json:"result"`
}

func (r ttRun) done() bool { return r.State != "pending" && r.State != "running" }

// ttJunit renders runs as JUnit XML (one testcase per assertion, so T1's test visibility can track
// each); a run that errored before any assertion becomes one errored case.
func ttJunit(suite string, runs []ttRun) ([]byte, error) {
	s := junitSute{Name: "watchtower trace tests: " + suite}
	for _, r := range runs {
		class := "watchtower.trace_test." + r.TestName
		if len(r.Result.Assertions) == 0 {
			c := junitCase{Name: r.TestName, Class: class}
			switch r.State {
			case "failed":
				s.Failures++
				c.Failure = &junitFail{Message: r.Result.Error}
			case "error", "pending", "running":
				s.Errors++
				c.Err = &junitFail{Message: strings.TrimSpace(r.State + " " + r.Result.Error)}
			}
			s.Cases = append(s.Cases, c)
			continue
		}
		for _, a := range r.Result.Assertions {
			c := junitCase{Name: a.Name, Class: class}
			if !a.OK {
				s.Failures++
				c.Failure = &junitFail{Message: a.Detail}
			}
			s.Cases = append(s.Cases, c)
		}
	}
	s.Tests = len(s.Cases)
	out, err := xml.MarshalIndent(junitSuites{Suites: []junitSute{s}}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), out...), nil
}

// testMain is `wtctl test run ...`.
func testMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "run" {
		return errors.New("usage: wtctl test run --suite <id> [--wait] [--junit out.xml] --api <url> --key <key> --project <id>")
	}
	if code := traceTestRun(ctx, args[1:], out, os.Stderr); code != exitPass {
		return exitCode(code)
	}
	return nil
}

// traceTestRun starts a suite run and returns the process exit code: 0 passed, 1 a test failed,
// 2 the run could not be started or finished.
func traceTestRun(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("test run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	api := fs.String("api", os.Getenv("WT_API"), "API base URL")
	key := fs.String("key", os.Getenv("WT_API_KEY"), "API key (wtk_...)")
	project := fs.String("project", os.Getenv("WT_PROJECT"), "project id")
	suite := fs.String("suite", "", "trace test suite id")
	ciRef := fs.String("ci-ref", os.Getenv("GITHUB_RUN_ID"), "CI run reference stored with the runs")
	wait := fs.Bool("wait", false, "wait for the result")
	timeout := fs.Duration("timeout", 10*time.Minute, "give up waiting after this long")
	junitPath := fs.String("junit", "", "write JUnit XML here (needs --wait)")
	poll := fs.Duration("poll", 2*time.Second, "poll interval")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if *api == "" || *key == "" || *project == "" || *suite == "" || (*junitPath != "" && !*wait) {
		fmt.Fprintln(stderr, "--api, --key, --project and --suite are required; --junit needs --wait")
		return exitError
	}
	base := strings.TrimRight(*api, "/") + "/v1/projects/" + *project
	var started struct {
		Ref  string  `json:"ref"`
		Runs []ttRun `json:"runs"`
	}
	if err := call(ctx, http.MethodPost, base+"/trace-test-suites/"+*suite+"/runs", *key, map[string]string{"ci_ref": *ciRef}, &started); err != nil {
		fmt.Fprintln(stderr, "test run failed:", err)
		return exitError
	}
	fmt.Fprintf(stdout, "suite run %s started (%d tests)\n", started.Ref, len(started.Runs))
	if !*wait {
		fmt.Fprintln(stderr, "warning: --wait not set; the exit code does not reflect the tests")
		return exitPass
	}
	runs, err := waitTraceRuns(ctx, base, *key, started.Ref, *timeout, *poll)
	if *junitPath != "" && len(runs) > 0 { // CI wants the report most when the run did not finish
		if x, jerr := ttJunit(*suite, runs); jerr == nil {
			_ = os.WriteFile(*junitPath, x, 0o644)
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, "test run failed:", err)
		return exitError
	}
	code := exitPass
	for _, r := range runs {
		fmt.Fprintf(stdout, "%s %s\n", strings.ToUpper(r.State), r.TestName)
		if r.State != "passed" {
			code = exitFail
			if r.Result.Error != "" {
				fmt.Fprintf(stdout, "  %s\n", r.Result.Error)
			}
		}
	}
	return code
}

// waitTraceRuns polls the runs of ref until none is pending or running, or the timeout passes (the
// last known runs are returned with the error).
func waitTraceRuns(ctx context.Context, base, key, ref string, timeout, poll time.Duration) ([]ttRun, error) {
	deadline := time.Now().Add(timeout)
	for {
		var page struct {
			Data []ttRun `json:"data"`
		}
		if err := call(ctx, http.MethodGet, base+"/trace-test-runs?limit=200&ref="+url.QueryEscape(ref), key, nil, &page); err != nil {
			return nil, err
		}
		pending := false
		for _, r := range page.Data {
			pending = pending || !r.done()
		}
		if !pending && len(page.Data) > 0 {
			return page.Data, nil
		}
		if time.Now().After(deadline) {
			b, _ := json.Marshal(len(page.Data))
			return page.Data, fmt.Errorf("timed out after %s waiting for suite run %s (%s runs seen)", timeout, ref, b)
		}
		select {
		case <-ctx.Done():
			return page.Data, ctx.Err()
		case <-time.After(poll):
		}
	}
}
