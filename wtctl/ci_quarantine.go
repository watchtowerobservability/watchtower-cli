package main

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
)

const ciJunitUsage = "usage: wtctl ci junit <file.xml>... --api <url> --key <key> --project <id> [--respect-quarantine] [--suite name]"

const ciPlanUsage = "usage: wtctl ci plan --api <url> --key <key> --project <id> [--git-base <rev>] [--changed-files a,b] [--skip-list | --go-skip]"

// testPlan is the answer of POST /v1/projects/{prj}/tests/plan.
type testPlan struct {
	Quarantined []struct {
		ID        string  `json:"id"`
		TicketURL *string `json:"ticket_url"`
		Owner     *string `json:"owner"`
	} `json:"quarantined"`
	Disabled   []string `json:"disabled"`
	Skippable  []string `json:"skippable"`
	NewTests   []string `json:"new_tests"`
	EfdRetries int      `json:"efd_retries"`
}

// junitResult is one test case as the API names it: `suite::classname.name`.
type junitResult struct {
	ID     string
	Failed bool
}

// parseJunitIDs reads JUnit XML the way the API's parser does: the innermost <testsuite> name is
// the suite (`suite` overrides it, "" falls back to "default"), the test is classname.name, and a
// <failure> or <error> child fails the case. xUnit v2 (<assembly>, <test result>) and NUnit 3
// (<test-suite type="Assembly">, <test-case fullname result>) name tests the same way the API does.
func parseJunitIDs(r io.Reader, suite string) ([]junitResult, error) {
	d := xml.NewDecoder(r)
	var suites []string
	var out []junitResult
	cur := -1
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			attr := func(n string) string {
				for _, a := range t.Attr {
					if a.Name.Local == n {
						return a.Value
					}
				}
				return ""
			}
			switch t.Name.Local {
			case "testsuite":
				suites = append(suites, attr("name"))
			case "assembly":
				n := attr("name")
				suites = append(suites, n[strings.LastIndexAny(n, `/\`)+1:])
			case "test-suite":
				n := attr("name")
				if ty := attr("type"); ty != "" && ty != "Assembly" && len(suites) > 0 {
					n = suites[len(suites)-1]
				}
				suites = append(suites, n)
			case "testcase", "test", "test-case":
				s := suite
				if s == "" && len(suites) > 0 {
					s = suites[len(suites)-1]
				}
				if s == "" {
					s = "default"
				}
				name := attr("name")
				if c := attr("classname"); c != "" {
					name = c + "." + name
				}
				if f := attr("fullname"); f != "" && t.Name.Local == "test-case" {
					name = f
				}
				res := attr("result")
				failed := res == "Fail" || res == "Failed"
				out = append(out, junitResult{ID: s + "::" + name, Failed: failed})
				cur = len(out) - 1
			case "failure", "error":
				if cur >= 0 {
					out[cur].Failed = true
				}
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "testsuite", "assembly", "test-suite":
				if len(suites) > 0 {
					suites = suites[:len(suites)-1]
				}
			case "testcase", "test", "test-case":
				cur = -1
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no <testcase> in the JUnit XML")
	}
	return out, nil
}

// fetchPlan asks the API for the session plan.
func fetchPlan(ctx context.Context, api, key, project string, changed, tests []string) (testPlan, error) {
	var p testPlan
	body := map[string]any{"changed_files": nonNil(changed), "tests": nonNil(tests)}
	u := strings.TrimRight(api, "/") + "/v1/projects/" + url.PathEscape(project) + "/tests/plan"
	err := call(ctx, "POST", u, key, body, &p)
	return p, err
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

type ciFlags struct {
	api, key, project string
}

func (c *ciFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&c.api, "api", "", "API base URL")
	fs.StringVar(&c.key, "key", os.Getenv("WT_API_KEY"), "API key; default $WT_API_KEY")
	fs.StringVar(&c.project, "project", "", "project id")
}

func (c *ciFlags) check() error {
	if c.api == "" || c.key == "" || c.project == "" {
		return errors.New("--api, --key and --project are required")
	}
	return nil
}

// ciJunitMain gates a build on JUnit results. With --respect-quarantine a failure of a test the
// project quarantined does not count (its ticket is printed), and a disabled test's result is
// ignored; it exits 1 when any other test failed, 0 otherwise.
func ciJunitMain(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("ci junit", flag.ContinueOnError)
	var c ciFlags
	c.register(fs)
	respect := fs.Bool("respect-quarantine", false, "do not fail on quarantined or disabled tests")
	suite := fs.String("suite", "", "suite name (as passed to upload-junit)")
	files, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return errors.New(ciJunitUsage)
	}
	var results []junitResult
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			return err
		}
		r, err := parseJunitIDs(io.LimitReader(fh, maxJunitBytes), *suite)
		fh.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		results = append(results, r...)
	}
	var plan testPlan
	if *respect {
		if err := c.check(); err != nil {
			return err
		}
		if plan, err = fetchPlan(ctx, c.api, c.key, c.project, nil, nil); err != nil {
			return err
		}
	}
	code := gateJunit(results, plan, out)
	if code != 0 {
		return exitCode(code)
	}
	return nil
}

// gateJunit prints the verdict per failed test and returns the exit code.
func gateJunit(results []junitResult, plan testPlan, out io.Writer) int {
	tickets := map[string]string{}
	for _, q := range plan.Quarantined {
		t := "(no ticket)"
		if q.TicketURL != nil && *q.TicketURL != "" {
			t = *q.TicketURL
		}
		tickets[q.ID] = t
	}
	disabled := map[string]bool{}
	for _, d := range plan.Disabled {
		disabled[d] = true
	}
	failed, ignored := 0, 0
	for _, r := range results {
		if !r.Failed {
			continue
		}
		switch t, q := tickets[r.ID]; {
		case q:
			ignored++
			fmt.Fprintf(out, "quarantined  %s  %s\n", r.ID, t)
		case disabled[r.ID]:
			ignored++
			fmt.Fprintf(out, "disabled     %s\n", r.ID)
		default:
			failed++
			fmt.Fprintf(out, "FAILED       %s\n", r.ID)
		}
	}
	fmt.Fprintf(out, "%d tests, %d failed, %d failures ignored (quarantined or disabled)\n", len(results), failed, ignored)
	if failed > 0 {
		return 1
	}
	return 0
}

// ciPlanMain prints the session plan (JSON), or with --skip-list the ids a runner should not
// run: disabled tests and, for the changed files, the tests Test Impact Analysis lets it skip.
// --go-skip prints the same as a regexp for `go test -skip "$(wtctl ci plan ... --go-skip)"`.
func ciPlanMain(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("ci plan", flag.ContinueOnError)
	var c ciFlags
	c.register(fs)
	base := fs.String("git-base", "", "git revision to diff HEAD against for the changed files")
	changedCSV := fs.String("changed-files", "", "comma-separated changed files (instead of --git-base)")
	skipList := fs.Bool("skip-list", false, "print the ids to skip, one per line")
	goSkip := fs.Bool("go-skip", false, "print one `go test -skip` regexp for the top-level tests to skip")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := c.check(); err != nil {
		return err
	}
	var changed []string
	switch {
	case *changedCSV != "":
		for _, f := range strings.Split(*changedCSV, ",") {
			if f = strings.TrimSpace(f); f != "" {
				changed = append(changed, f)
			}
		}
	case *base != "":
		if strings.HasPrefix(*base, "-") {
			return errors.New("--git-base must be a revision")
		}
		b, err := exec.CommandContext(ctx, "git", "diff", "--name-only", *base+"...HEAD", "--").Output()
		if err != nil {
			return fmt.Errorf("git diff: %w", err)
		}
		changed = strings.Fields(string(b))
	}
	p, err := fetchPlan(ctx, c.api, c.key, c.project, changed, nil)
	if err != nil {
		return err
	}
	if !*skipList && !*goSkip {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(p)
	}
	ids := append(append([]string{}, p.Disabled...), p.Skippable...)
	sort.Strings(ids)
	if *goSkip {
		fmt.Fprintln(out, goSkipPattern(ids))
		return nil
	}
	for i, id := range ids {
		if i == 0 || ids[i-1] != id {
			fmt.Fprintln(out, id)
		}
	}
	return nil
}

// parseInterleaved parses flags that may come before or after the positional arguments.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	rest := args
	for len(rest) > 0 {
		if err := fs.Parse(rest); err != nil {
			return nil, err
		}
		rest = fs.Args()
		if len(rest) > 0 {
			pos = append(pos, rest[0])
			rest = rest[1:]
		}
	}
	return pos, nil
}
