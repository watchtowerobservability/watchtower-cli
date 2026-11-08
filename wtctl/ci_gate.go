package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const ciGateUsage = "usage: wtctl ci gate evaluate --api <url> --key <key> --project <id> --gate <id> --sha <sha> " +
	"[--branch b] [--provider github|gitlab --repo <owner/repo|project_id> --token <scm_token> [--gitlab-url url] [--status-context name]]"

type gateBreach struct {
	Kind    string  `json:"kind"`
	Limit   float64 `json:"limit"`
	Actual  float64 `json:"actual"`
	Message string  `json:"message"`
}

type ciGateResult struct {
	Gate        string       `json:"gate"`
	Passed      bool         `json:"passed"`
	Skipped     bool         `json:"skipped"`
	Breaches    []gateBreach `json:"breaches"`
	FailedTests uint64       `json:"failed_tests"`
	NewFlaky    uint64       `json:"new_flaky_tests"`
	Coverage    *float64     `json:"coverage_pct"`
}

type ciGateOpts struct {
	api, key, project, gate, sha, branch string
	provider, repo, token, gitlabURL     string
	statusContext                        string
}

// ciGateMain runs `wtctl ci gate evaluate ...`: it evaluates the gate against a commit, prints the
// result, optionally posts a commit status, and returns exitCode(1) when the gate breached.
func ciGateMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "evaluate" {
		return errors.New(ciGateUsage)
	}
	var o ciGateOpts
	fs := flag.NewFlagSet("ci gate evaluate", flag.ContinueOnError)
	fs.StringVar(&o.api, "api", "", "API base URL")
	fs.StringVar(&o.key, "key", os.Getenv("WT_API_KEY"), "API key; default $WT_API_KEY")
	fs.StringVar(&o.project, "project", "", "project id")
	fs.StringVar(&o.gate, "gate", "", "gate id")
	fs.StringVar(&o.sha, "sha", "", "commit sha to evaluate")
	fs.StringVar(&o.branch, "branch", "", "branch of the commit")
	fs.StringVar(&o.provider, "provider", "", "post a commit status to github or gitlab")
	fs.StringVar(&o.repo, "repo", "", "owner/repo (github) or project id (gitlab)")
	fs.StringVar(&o.token, "token", os.Getenv("WT_SCM_TOKEN"), "SCM token; default $WT_SCM_TOKEN")
	fs.StringVar(&o.gitlabURL, "gitlab-url", "https://gitlab.com", "GitLab base URL")
	fs.StringVar(&o.statusContext, "status-context", "watchtower/quality-gate", "commit status context")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if o.api == "" || o.key == "" || o.project == "" || o.gate == "" || o.sha == "" {
		return errors.New("--api, --key, --project, --gate and --sha are required")
	}

	u := strings.TrimRight(o.api, "/") + "/v1/projects/" + o.project + "/ci/gates/" +
		url.PathEscape(o.gate) + "/evaluate?sha=" + url.QueryEscape(o.sha)
	if o.branch != "" {
		u += "&branch=" + url.QueryEscape(o.branch)
	}
	var res ciGateResult
	if err := call(ctx, http.MethodPost, u, o.key, nil, &res); err != nil {
		return err
	}

	switch {
	case res.Skipped:
		fmt.Fprintf(out, "gate %q skipped (branch not in scope)\n", res.Gate)
	case res.Passed:
		fmt.Fprintf(out, "gate %q passed (%d failed tests, %d new flaky)\n", res.Gate, res.FailedTests, res.NewFlaky)
	default:
		fmt.Fprintf(out, "gate %q FAILED:\n", res.Gate)
		for _, b := range res.Breaches {
			fmt.Fprintf(out, "  - %s\n", b.Message)
		}
	}

	if o.provider != "" {
		if err := postCommitStatus(ctx, o, &res); err != nil {
			fmt.Fprintln(out, "warning: could not post commit status:", err)
		} else {
			fmt.Fprintf(out, "posted %s commit status to %s@%s\n", o.provider, o.repo, short(o.sha))
		}
	}

	if !res.Passed {
		return exitCode(1)
	}
	return nil
}

// statusFor maps a gate result to a commit-status state and a short description (both providers
// accept success/failure and cap the description).
func statusFor(res *ciGateResult) (state, desc string) {
	if res.Passed || res.Skipped {
		return "success", "quality gate passed"
	}
	desc = fmt.Sprintf("%d breach(es)", len(res.Breaches))
	if len(res.Breaches) > 0 {
		desc = res.Breaches[0].Message
	}
	if len(desc) > 140 {
		desc = desc[:140]
	}
	return "failure", desc
}

func short(sha string) string {
	if len(sha) > 8 {
		return sha[:8]
	}
	return sha
}

// postCommitStatus reports the gate verdict to GitHub or GitLab as a commit status.
func postCommitStatus(ctx context.Context, o ciGateOpts, res *ciGateResult) error {
	if o.repo == "" || o.token == "" {
		return errors.New("--repo and --token are required to post a commit status")
	}
	state, desc := statusFor(res)
	var endpoint, tokenHeader, tokenValue string
	var body map[string]any
	switch o.provider {
	case "github":
		// GitHub uses pending/success/failure/error
		endpoint = "https://api.github.com/repos/" + o.repo + "/statuses/" + url.PathEscape(o.sha)
		tokenHeader, tokenValue = "Authorization", "token "+o.token
		body = map[string]any{"state": state, "context": o.statusContext, "description": desc}
	case "gitlab":
		endpoint = strings.TrimRight(o.gitlabURL, "/") + "/api/v4/projects/" +
			url.PathEscape(o.repo) + "/statuses/" + url.PathEscape(o.sha)
		tokenHeader, tokenValue = "PRIVATE-TOKEN", o.token
		body = map[string]any{"state": state, "name": o.statusContext, "description": desc}
	default:
		return fmt.Errorf("unknown provider %q (want github or gitlab)", o.provider)
	}
	return postJSON(ctx, endpoint, tokenHeader, tokenValue, body)
}

func postJSON(ctx context.Context, endpoint, hk, hv string, body map[string]any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hk, hv)
	resp, err := guardedClient(0).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return fmt.Errorf("%s: %s: %s", endpoint, resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}
