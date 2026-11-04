package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

const ciGotestUsage = "usage: wtctl ci gotest [file.json] --api <url> --key <key> --project <id> [--run-id id] [--branch b] [--sha s] [--respect-quarantine] [--junit-out file]"

// maxGoOutput is how much output a failed test keeps for its <failure> body.
const maxGoOutput = 4 << 10

// goTestEvent is one line of `go test -json` (cmd/test2json).
type goTestEvent struct {
	Action  string
	Package string
	Test    string
	Elapsed float64
	Output  string
}

type jxSuites struct {
	XMLName xml.Name  `xml:"testsuites"`
	Suites  []jxSuite `xml:"testsuite"`
}

type jxSuite struct {
	Name  string   `xml:"name,attr"`
	Cases []jxCase `xml:"testcase"`
}

type jxCase struct {
	Name    string  `xml:"name,attr"`
	Time    string  `xml:"time,attr"`
	Failure *jxText `xml:"failure,omitempty"`
	Skipped *jxText `xml:"skipped,omitempty"`
}

type jxText struct {
	Message string `xml:"message,attr,omitempty"`
	Body    string `xml:",chardata"`
}

// goTestJunit turns a `go test -json` stream into JUnit XML: one <testsuite> per package, one
// <testcase> per finished test (a test run twice by -count or a retry wrapper appears twice, which
// the API numbers as retries), so ids are `<package>::<Test>`. Output lines go to echo so the log
// still reads like `go test`. A package that failed without a failing test (build or TestMain
// failure) gets a failed `(package)` case so it cannot pass the gate.
func goTestJunit(r io.Reader, echo io.Writer) ([]byte, error) {
	var order []string
	suites := map[string]*jxSuite{}
	outputs := map[string]string{}
	testFailed := map[string]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		line := sc.Bytes()
		var ev goTestEvent
		if len(line) == 0 || line[0] != '{' || json.Unmarshal(line, &ev) != nil {
			fmt.Fprintf(echo, "%s\n", line) // build errors and other non-JSON lines
			continue
		}
		if ev.Output != "" {
			fmt.Fprint(echo, ev.Output)
		}
		if ev.Package == "" {
			continue
		}
		key := ev.Package + "\x00" + ev.Test
		switch ev.Action {
		case "output":
			if o := outputs[key] + ev.Output; len(o) > maxGoOutput {
				outputs[key] = o[len(o)-maxGoOutput:]
			} else {
				outputs[key] = o
			}
			continue
		case "pass", "fail", "skip":
		default:
			continue
		}
		name := ev.Test
		if name == "" {
			// package result: only a failure without a failed test is reported
			if ev.Action != "fail" || testFailed[ev.Package] {
				continue
			}
			name = "(package)"
		}
		s := suites[ev.Package]
		if s == nil {
			s = &jxSuite{Name: ev.Package}
			suites[ev.Package] = s
			order = append(order, ev.Package)
		}
		c := jxCase{Name: name, Time: strconv.FormatFloat(ev.Elapsed, 'f', 3, 64)}
		switch ev.Action {
		case "fail":
			testFailed[ev.Package] = true
			c.Failure = &jxText{Message: "failed", Body: outputs[key]}
		case "skip":
			c.Skipped = &jxText{}
		}
		delete(outputs, key)
		s.Cases = append(s.Cases, c)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(order) == 0 {
		return nil, errors.New("no test results in the `go test -json` input")
	}
	doc := jxSuites{}
	for _, p := range order {
		doc.Suites = append(doc.Suites, *suites[p])
	}
	b, err := xml.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), b...), nil
}

// ciGotestMain reads `go test -json` (a file or stdin), prints the test log, uploads the results
// as JUnit when --run-id is set, and exits like `ci junit`: 1 when a test failed that the project
// has not quarantined or disabled (with --respect-quarantine), else 0. Use it as
// `set -o pipefail; go test -json ./... | wtctl ci gotest ...` or with `go test ... || true`
// since its exit code replaces go test's.
func ciGotestMain(ctx context.Context, args []string, in io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("ci gotest", flag.ContinueOnError)
	var c ciFlags
	c.register(fs)
	var u junitUpload
	fs.StringVar(&u.runID, "run-id", "", "CI run id; uploads the results when set")
	fs.StringVar(&u.branch, "branch", "", "branch")
	fs.StringVar(&u.sha, "sha", "", "commit sha")
	respect := fs.Bool("respect-quarantine", false, "do not fail on quarantined or disabled tests")
	junitOut := fs.String("junit-out", "", "also write the JUnit XML to this file")
	files, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if len(files) > 1 {
		return errors.New(ciGotestUsage)
	}
	if len(files) == 1 {
		fh, err := os.Open(files[0])
		if err != nil {
			return err
		}
		defer fh.Close()
		in = fh
	}
	if *respect || u.runID != "" {
		if err := c.check(); err != nil {
			return err
		}
	}
	doc, err := goTestJunit(in, out)
	if err != nil {
		return err
	}
	if *junitOut != "" {
		if err := os.WriteFile(*junitOut, doc, 0o644); err != nil {
			return err
		}
	}
	if u.runID != "" {
		u.api, u.key, u.project = c.api, c.key, c.project
		// telemetry down must not fail the build; the gate below still decides
		if _, err := uploadJunit(ctx, guardedClient(0), u, doc); err != nil {
			fmt.Fprintf(out, "wtctl: upload failed: %v\n", err)
		}
	}
	results, err := parseJunitIDs(bytes.NewReader(doc), "")
	if err != nil {
		return err
	}
	var plan testPlan
	if *respect {
		if plan, err = fetchPlan(ctx, c.api, c.key, c.project, nil, nil); err != nil {
			return err
		}
	}
	if code := gateJunit(results, plan, out); code != 0 {
		return exitCode(code)
	}
	return nil
}

// goSkipPattern is one `go test -skip` regexp for the top-level tests among ids
// (`<package>::<Test>`). shortcut: `-skip` is not package-scoped, so a name skipped in one
// package is skipped in every package; subtests are left to run. Fine while test names are
// unique per repo; upgrade to per-package `go test` invocations if they are not.
func goSkipPattern(ids []string) string {
	var names []string
	seen := map[string]bool{}
	for _, id := range ids {
		_, name, ok := strings.Cut(id, "::")
		if !ok || name == "" || strings.Contains(name, "/") || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, regexp.QuoteMeta(name))
	}
	if len(names) == 0 {
		return ""
	}
	return "^(" + strings.Join(names, "|") + ")$"
}
