package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// `wtctl tests coverage go`: per-test coverage for Go. Each package's tests run on their own with
// -coverpkg over every module package, so the profile holds every file they executed, in this
// package or another; each top-level test of the package is recorded with those files and the
// package's _test.go files. Ids are `<import path>::<Test>`, as `wtctl ci gotest` names them.
// shortcut: granularity is the package (all its tests share one file set), which can only make
// TIA run more tests, never fewer; upgrade to one `go test -run '^T$'` per test if packages are
// large and slow.

type goPkg struct {
	ImportPath   string
	Dir          string
	TestGoFiles  []string
	XTestGoFiles []string
}

func coverageGoMain(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("tests coverage go", flag.ContinueOnError)
	var c ciFlags
	c.register(fs)
	sha := fs.String("sha", os.Getenv("GITHUB_SHA"), "commit the coverage was recorded at; default $GITHUB_SHA")
	pkgs, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if err := c.check(); err != nil {
		return err
	}
	if len(pkgs) == 0 {
		pkgs = []string{"./..."}
	}
	mods, err := goModules(ctx)
	if err != nil {
		return err
	}
	list, err := goPackages(ctx, pkgs)
	if err != nil {
		return err
	}
	coverPkg := make([]string, 0, len(mods))
	for path := range mods {
		coverPkg = append(coverPkg, path+"/...")
	}
	sort.Strings(coverPkg)
	tmp, err := os.MkdirTemp("", "wt-gocover-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	root := gitRoot(ctx)
	var tests []coverageTest
	for i, p := range list {
		if len(p.TestGoFiles)+len(p.XTestGoFiles) == 0 {
			continue
		}
		prof := filepath.Join(tmp, fmt.Sprintf("%d.out", i))
		cmd := exec.CommandContext(ctx, "go", "test", "-json", "-count=1",
			"-coverpkg="+strings.Join(coverPkg, ","), "-coverprofile="+prof, p.ImportPath)
		var stdout bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "%s: go test: %v (coverage recorded for the tests that ran)\n", p.ImportPath, err)
		}
		names := goTopLevelTests(&stdout)
		fh, err := os.Open(prof)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: no coverage profile, skipped\n", p.ImportPath)
			continue
		}
		files := coveredGoFiles(fh, mods, root)
		fh.Close()
		for _, f := range append(append([]string{}, p.TestGoFiles...), p.XTestGoFiles...) {
			if r := repoRel(root, "", filepath.Join(p.Dir, f)); r != "" {
				files = append(files, r)
			}
		}
		if len(files) > 2000 {
			files = files[:2000]
		}
		for _, n := range names {
			tests = append(tests, coverageTest{Suite: p.ImportPath, Test: n, Files: files})
		}
	}
	if len(tests) == 0 {
		return errors.New("no Go tests ran")
	}
	n, err := putCoverage(ctx, c, truncate(*sha, 64), tests)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "stored coverage for %d tests\n", n)
	return nil
}

// goModules maps each main module's path to its directory (several in a go.work workspace).
func goModules(ctx context.Context) (map[string]string, error) {
	b, err := exec.CommandContext(ctx, "go", "list", "-m", "-f", "{{.Path}}\t{{.Dir}}").Output()
	if err != nil {
		return nil, fmt.Errorf("go list -m: %w", err)
	}
	mods := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if path, dir, ok := strings.Cut(strings.TrimSpace(l), "\t"); ok && path != "" && dir != "" {
			mods[path] = dir
		}
	}
	if len(mods) == 0 {
		return nil, errors.New("not inside a Go module")
	}
	return mods, nil
}

func goPackages(ctx context.Context, pkgs []string) ([]goPkg, error) {
	cmd := exec.CommandContext(ctx, "go", append([]string{"list", "-json=ImportPath,Dir,TestGoFiles,XTestGoFiles", "--"}, pkgs...)...)
	b, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list: %w", err)
	}
	var out []goPkg
	d := json.NewDecoder(bytes.NewReader(b))
	for d.More() {
		var p goPkg
		if err := d.Decode(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// goTopLevelTests lists the top-level tests a `go test -json` stream ran.
func goTopLevelTests(r io.Reader) []string {
	seen := map[string]bool{}
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		var e goTestEvent
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.Action != "run" || e.Test == "" || strings.Contains(e.Test, "/") {
			continue
		}
		if !seen[e.Test] {
			seen[e.Test] = true
			out = append(out, e.Test)
		}
	}
	return out
}

// coveredGoFiles reads a cover profile (`<import path>/<file>.go:l.c,l.c stmts count`) and returns
// the repository-relative files with a block executed at least once. Files outside the main
// modules (dependencies) are left out.
func coveredGoFiles(r io.Reader, mods map[string]string, root string) []string {
	set := map[string]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 3 || f[2] == "0" || strings.HasPrefix(f[0], "mode:") {
			continue
		}
		i := strings.LastIndexByte(f[0], ':')
		if i <= 0 {
			continue
		}
		if p := moduleFile(mods, f[0][:i]); p != "" {
			if r := repoRel(root, "", p); r != "" {
				set[r] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for f := range set {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// moduleFile maps `<module path>/<rel>` to `<module dir>/<rel>` by the longest module path.
func moduleFile(mods map[string]string, imp string) string {
	best := ""
	for path := range mods {
		if strings.HasPrefix(imp, path+"/") && len(path) > len(best) {
			best = path
		}
	}
	if best == "" {
		return ""
	}
	return filepath.Join(mods[best], filepath.FromSlash(strings.TrimPrefix(imp, best+"/")))
}
