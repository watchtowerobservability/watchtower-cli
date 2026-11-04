package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// `wtctl tests` (W46): Test Impact Analysis from CI.
//
//   - `tests select` diffs HEAD against --base, asks POST /v1/projects/{prj}/tia/select and prints
//     the tests to run or skip. Every safety rule (unknown diff, no coverage, configuration change,
//     a file no test executed) makes the skip list empty, so a runner fed the skip list runs all.
//   - `tests coverage upload` stores per-test coverage (PUT /v1/projects/{prj}/tests/coverage-map)
//     from an lcov file with per-test `TN:` records or a JSON map; `tests coverage go` records it
//     for Go by running each package's tests with -coverpkg=./... (per-package granularity).

const testsUsage = `usage: wtctl tests select --api <url> --key <key> --project <id> (--base <rev> | --changed-files a,b) [--tests-file ids.txt] [--format json|skip|run|go-skip]
       wtctl tests coverage upload (--lcov <file> | --map <file.json>) --api <url> --key <key> --project <id> [--suite s] [--sha s] [--root dir]
       wtctl tests coverage go [packages...] --api <url> --key <key> --project <id> [--sha s]`

// coverageChunk is how many tests one coverage-map PUT carries.
const coverageChunk = 1000

// tiaSelection is the answer of POST /v1/projects/{prj}/tia/select.
type tiaSelection struct {
	RunAll       bool     `json:"run_all"`
	Reasons      []string `json:"reasons"`
	Run          []string `json:"run"`
	Skip         []string `json:"skip"`
	UnknownFiles []string `json:"unknown_files"`
}

// coverageTest is one test of a coverage-map upload.
type coverageTest struct {
	Suite string   `json:"suite"`
	Test  string   `json:"test"`
	Files []string `json:"files"`
}

func testsMain(ctx context.Context, args []string, out io.Writer) error {
	switch {
	case len(args) > 0 && args[0] == "select":
		return testsSelectMain(ctx, args[1:], out, os.Stderr)
	case len(args) > 1 && args[0] == "coverage" && args[1] == "upload":
		return coverageUploadMain(ctx, args[2:], out)
	case len(args) > 1 && args[0] == "coverage" && args[1] == "go":
		return coverageGoMain(ctx, args[2:], out)
	}
	return errors.New(testsUsage)
}

// changedSince lists the files `git diff base...HEAD` touches (NUL-separated, so names with
// spaces survive).
func changedSince(ctx context.Context, base string) ([]string, error) {
	if strings.HasPrefix(base, "-") {
		return nil, errors.New("--base must be a revision")
	}
	b, err := exec.CommandContext(ctx, "git", "diff", "--name-only", "-z", base+"...HEAD", "--").Output()
	if err != nil {
		return nil, fmt.Errorf("git diff %s...HEAD: %w (fetch the base, e.g. `git fetch origin main`)", base, err)
	}
	var files []string
	for _, f := range strings.Split(string(b), "\x00") {
		if f = strings.TrimSpace(f); f != "" {
			files = append(files, f)
		}
	}
	return files, nil
}

func readLines(path string) ([]string, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	var out []string
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}

func testsSelectMain(ctx context.Context, args []string, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("tests select", flag.ContinueOnError)
	var c ciFlags
	c.register(fs)
	base := fs.String("base", "", "git revision to diff HEAD against, e.g. origin/main")
	changedCSV := fs.String("changed-files", "", "comma-separated changed files (instead of --base)")
	testsFile := fs.String("tests-file", "", "file with the test ids (suite::test) the runner knows, one per line")
	format := fs.String("format", "json", "json, skip (ids to skip), run (ids to run) or go-skip (one regexp for go test -skip)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := c.check(); err != nil {
		return err
	}
	if (*base == "") == (*changedCSV == "") {
		return errors.New("one of --base or --changed-files is required")
	}
	switch *format {
	case "json", "skip", "run", "go-skip":
	default:
		return fmt.Errorf("--format %q: json, skip, run or go-skip", *format)
	}
	var changed []string
	if *changedCSV != "" {
		for _, f := range strings.Split(*changedCSV, ",") {
			if f = strings.TrimSpace(f); f != "" {
				changed = append(changed, f)
			}
		}
	} else {
		var err error
		if changed, err = changedSince(ctx, *base); err != nil {
			return err
		}
	}
	var tests []string
	if *testsFile != "" {
		var err error
		if tests, err = readLines(*testsFile); err != nil {
			return err
		}
	}
	var sel tiaSelection
	u := strings.TrimRight(c.api, "/") + "/v1/projects/" + url.PathEscape(c.project) + "/tia/select"
	body := map[string]any{"changed_files": nonNil(changed), "tests": nonNil(tests)}
	if err := call(ctx, "POST", u, c.key, body, &sel); err != nil {
		return err
	}
	if sel.RunAll {
		fmt.Fprintf(errOut, "tia: running every test: %s\n", strings.Join(sel.Reasons, "; "))
	} else {
		fmt.Fprintf(errOut, "tia: %d to run, %d to skip for %d changed files\n", len(sel.Run), len(sel.Skip), len(changed))
	}
	return printSelection(out, sel, *format)
}

func printSelection(out io.Writer, sel tiaSelection, format string) error {
	switch format {
	case "skip":
		for _, id := range sel.Skip {
			fmt.Fprintln(out, id)
		}
	case "run":
		for _, id := range sel.Run {
			fmt.Fprintln(out, id)
		}
	case "go-skip":
		fmt.Fprintln(out, goSkipPattern(sel.Skip))
	default:
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(sel)
	}
	return nil
}

// splitID splits `suite::test`; without `::` the suite is def.
func splitID(id, def string) (string, string) {
	if s, t, ok := strings.Cut(id, "::"); ok && t != "" {
		return s, t
	}
	return def, id
}

// parseLcovPerTest reads lcov records grouped by their `TN:` test name and returns, per test
// name, the source files with at least one executed line or function. Records without a test
// name cannot be attributed and are left out.
func parseLcovPerTest(r io.Reader) (map[string][]string, error) {
	files := map[string]map[string]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	var tn, sf string
	hit := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "TN:"):
			tn = strings.TrimSpace(line[3:])
		case strings.HasPrefix(line, "SF:"):
			sf, hit = strings.TrimSpace(line[3:]), false
		case strings.HasPrefix(line, "DA:"), strings.HasPrefix(line, "FNDA:"):
			f := strings.Split(line[strings.Index(line, ":")+1:], ",")
			if len(f) >= 2 {
				n := f[1]
				if strings.HasPrefix(line, "FNDA:") {
					n = f[0]
				}
				if n != "0" && n != "" {
					hit = true
				}
			}
		case line == "end_of_record":
			if tn != "" && sf != "" && hit {
				if files[tn] == nil {
					files[tn] = map[string]bool{}
				}
				files[tn][sf] = true
			}
			sf, hit = "", false
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for t, fs := range files {
		for f := range fs {
			out[t] = append(out[t], f)
		}
		sort.Strings(out[t])
	}
	return out, nil
}

// repoRel makes a coverage path repository-relative (forward slashes): relative paths are taken
// from the working directory. Paths outside the root come back "" (dependencies, the toolchain).
func repoRel(root, cwd, p string) string {
	if !filepath.IsAbs(p) {
		p = filepath.Join(cwd, p)
	}
	rel, err := filepath.Rel(root, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return ""
	}
	return filepath.ToSlash(rel)
}

// gitRoot is the repository top level, or the working directory outside a repository.
func gitRoot(ctx context.Context) string {
	if b, err := exec.CommandContext(ctx, "git", "rev-parse", "--show-toplevel").Output(); err == nil {
		if r := strings.TrimSpace(string(b)); r != "" {
			return filepath.FromSlash(r)
		}
	}
	wd, _ := os.Getwd()
	return wd
}

// toCoverage turns test name -> files into upload entries with repository-relative files.
func toCoverage(m map[string][]string, suite, root, cwd string) []coverageTest {
	var out []coverageTest
	for id, files := range m {
		s, t := splitID(id, suite)
		ct := coverageTest{Suite: s, Test: t, Files: []string{}}
		seen := map[string]bool{}
		for _, f := range files {
			if r := repoRel(root, cwd, f); r != "" && !seen[r] && len(ct.Files) < 2000 {
				seen[r] = true
				ct.Files = append(ct.Files, r)
			}
		}
		out = append(out, ct)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Suite+"::"+out[i].Test < out[j].Suite+"::"+out[j].Test })
	return out
}

// putCoverage uploads the entries in chunks and returns how many were stored.
func putCoverage(ctx context.Context, c ciFlags, sha string, tests []coverageTest) (int, error) {
	u := strings.TrimRight(c.api, "/") + "/v1/projects/" + url.PathEscape(c.project) + "/tests/coverage-map"
	stored := 0
	for i := 0; i < len(tests); i += coverageChunk {
		chunk := tests[i:min(i+coverageChunk, len(tests))]
		var res struct {
			Stored int `json:"stored"`
		}
		if err := call(ctx, "PUT", u, c.key, map[string]any{"sha": sha, "tests": chunk}, &res); err != nil {
			return stored, err
		}
		stored += res.Stored
	}
	return stored, nil
}

func coverageUploadMain(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("tests coverage upload", flag.ContinueOnError)
	var c ciFlags
	c.register(fs)
	lcov := fs.String("lcov", "", "lcov file with per-test TN: records")
	mapFile := fs.String("map", "", `JSON object {"suite::test": ["file", ...]}`)
	suite := fs.String("suite", "default", "suite of test names that carry no suite:: prefix (match the JUnit suite)")
	sha := fs.String("sha", os.Getenv("GITHUB_SHA"), "commit the coverage was recorded at; default $GITHUB_SHA")
	root := fs.String("root", "", "repository root the files are made relative to; default the git top level")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := c.check(); err != nil {
		return err
	}
	if (*lcov == "") == (*mapFile == "") {
		return errors.New("one of --lcov or --map is required")
	}
	var m map[string][]string
	if *lcov != "" {
		fh, err := os.Open(*lcov)
		if err != nil {
			return err
		}
		m, err = parseLcovPerTest(fh)
		fh.Close()
		if err != nil {
			return err
		}
		if len(m) == 0 {
			return errors.New("the lcov file has no per-test records (TN:<test> before each SF:)")
		}
	} else {
		b, err := os.ReadFile(*mapFile)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(b, &m); err != nil {
			return fmt.Errorf("--map: %w", err)
		}
	}
	if *root == "" {
		*root = gitRoot(ctx)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	n, err := putCoverage(ctx, c, truncate(*sha, 64), toCoverage(m, *suite, *root, cwd))
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "stored coverage for %d tests\n", n)
	return nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
