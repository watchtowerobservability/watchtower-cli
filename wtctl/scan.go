package main

// `wtctl scan` (D2 Code Security, SAST): run the open rule set over a repo, produce SARIF, and
// upload it to the Code Security endpoint. The server returns a quality gate that blocks on new
// high-severity findings; with --fail-on-gate (the default) a blocked gate is a non-zero exit, so
// CI fails the build.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	scanPass    = 0
	scanBlocked = 1 // the quality gate blocked (new high-severity findings)
	scanError   = 2 // bad flags, scan or API error
)

// sarifUploadResult mirrors the /code-security/sarif response.
type sarifUploadResult struct {
	Uploaded  int    `json:"uploaded"`
	NewHigh   int    `json:"new_high"`
	Gate      string `json:"gate"`
	PRComment string `json:"pr_comment"`
	PRPosted  bool   `json:"pr_posted"`
}

func scanMain(ctx context.Context, args []string, stdout io.Writer) error {
	code := scanRun(ctx, args, stdout, os.Stderr)
	if code != scanPass {
		os.Exit(code)
	}
	return nil
}

func scanRun(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	api := fs.String("api", os.Getenv("WT_API"), "API base URL")
	key := fs.String("key", os.Getenv("WT_API_KEY"), "API key (wtk_...)")
	project := fs.String("project", os.Getenv("WT_PROJECT"), "project id")
	dir := fs.String("dir", ".", "directory to scan")
	repo := fs.String("repo", os.Getenv("WT_REPO"), "repository (owner/name)")
	sha := fs.String("sha", os.Getenv("WT_SHA"), "commit SHA scanned")
	service := fs.String("service", os.Getenv("WT_SERVICE"), "service the repo builds (default: repo name)")
	sarifOut := fs.String("sarif", "", "also write the SARIF log here")
	upload := fs.Bool("upload", true, "upload the SARIF to the API")
	reportDeps := fs.Bool("deps", true, "also report lockfile and manifest dependencies for the OSV sweep (SCA)")
	failOnGate := fs.Bool("fail-on-gate", true, "exit non-zero when the quality gate blocks")
	if err := fs.Parse(args); err != nil {
		return scanError
	}

	log, err := scanTree(*dir, os.ReadFile, filepath.WalkDir)
	if err != nil {
		fmt.Fprintln(stderr, "scan failed:", err)
		return scanError
	}
	n := len(log.Runs[0].Results)
	fmt.Fprintf(stdout, "scanned %s: %d finding(s)\n", *dir, n)

	body, err := json.Marshal(log)
	if err != nil {
		fmt.Fprintln(stderr, "encode SARIF:", err)
		return scanError
	}
	if *sarifOut != "" {
		if err := os.WriteFile(*sarifOut, body, 0o644); err != nil {
			fmt.Fprintln(stderr, "write SARIF:", err)
			return scanError
		}
	}
	if !*upload {
		return scanPass
	}
	if *api == "" || *key == "" || *project == "" || *repo == "" || *sha == "" {
		fmt.Fprintln(stderr, "--api, --key, --project, --repo and --sha are required to upload")
		return scanError
	}
	svc := *service
	if svc == "" {
		svc = *repo
		if i := strings.LastIndex(svc, "/"); i >= 0 {
			svc = svc[i+1:]
		}
	}
	url := fmt.Sprintf("%s/v1/projects/%s/code-security/sarif?repo=%s&sha=%s&service=%s",
		strings.TrimRight(*api, "/"), *project,
		queryEscape(*repo), queryEscape(*sha), queryEscape(svc))
	if *reportDeps {
		if deps, derr := collectDeps(*dir); derr != nil || len(deps) == 0 {
			fmt.Fprintln(stderr, "no dependencies reported (none found or unreadable)")
		} else {
			var dr struct {
				Accepted int `json:"accepted"`
			}
			du := fmt.Sprintf("%s/v1/projects/%s/code-security/dependencies", strings.TrimRight(*api, "/"), *project)
			if err := call(ctx, "POST", du, *key, map[string]any{"service": svc, "packages": deps}, &dr); err != nil {
				fmt.Fprintln(stderr, "dependency report failed:", err)
			} else {
				fmt.Fprintf(stdout, "reported %d dependencies for SCA\n", dr.Accepted)
			}
		}
	}
	var res sarifUploadResult
	// json.RawMessage is sent verbatim, so the server sees the exact SARIF bytes.
	if err := call(ctx, "POST", url, *key, json.RawMessage(body), &res); err != nil {
		fmt.Fprintln(stderr, "upload failed:", err)
		return scanError
	}
	fmt.Fprintf(stdout, "uploaded %d finding(s), %d new high-severity, gate: %s\n",
		res.Uploaded, res.NewHigh, res.Gate)
	if res.Gate == "blocked" && *failOnGate {
		fmt.Fprintln(stdout, res.PRComment)
		return scanBlocked
	}
	return scanPass
}

// queryEscape percent-encodes a query value without pulling in net/url for the whole file.
func queryEscape(s string) string {
	var b strings.Builder
	for _, r := range []byte(s) {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') ||
			r == '-' || r == '_' || r == '.' || r == '/' {
			b.WriteByte(r)
		} else {
			fmt.Fprintf(&b, "%%%02X", r)
		}
	}
	return b.String()
}
