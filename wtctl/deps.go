package main

// `wtctl deps upload`: report each dependency of a repo plus the symbols the source actually
// references from it, so the OSV sweep can decide reference-level reachability (an advisory's
// affected symbol is used or merely imported). Posts to /code-security/dependencies.
// shortcut: name-based symbol matching (`alias.Sym` uses and named imports), no type resolution;
// a Go method called on a returned value is not seen. Upgrade: go/types + per-language ASTs.

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type depEntry struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Ecosystem string   `json:"ecosystem"`
	Symbols   []string `json:"symbols"`
}

type depKey struct{ eco, name string }

func depsMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "upload" {
		return errors.New("usage: wtctl deps upload --project <prj> --service <svc> [--dir .] --api <url> --key <key>")
	}
	fs := flag.NewFlagSet("deps upload", flag.ContinueOnError)
	api := fs.String("api", os.Getenv("WT_API_URL"), "API base URL; default $WT_API_URL")
	key := fs.String("key", os.Getenv("WT_API_KEY"), "API key; default $WT_API_KEY")
	project := fs.String("project", os.Getenv("WT_PROJECT"), "project id")
	service := fs.String("service", os.Getenv("WT_SERVICE"), "service name")
	dir := fs.String("dir", ".", "repo directory")
	dry := fs.Bool("dry-run", false, "print the report instead of posting it")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	deps, err := collectDeps(*dir)
	if err != nil {
		return err
	}
	if len(deps) == 0 {
		return errors.New("no dependencies found (go.mod, package.json, requirements.txt or a lockfile)")
	}
	body := map[string]any{"service": *service, "packages": deps}
	if *dry {
		return json.NewEncoder(out).Encode(body)
	}
	if *api == "" || *key == "" || *project == "" || *service == "" {
		return errors.New("--api, --key, --project and --service are required")
	}
	var res struct {
		Accepted int `json:"accepted"`
	}
	u := fmt.Sprintf("%s/v1/projects/%s/code-security/dependencies", strings.TrimRight(*api, "/"), *project)
	if err := call(ctx, "POST", u, *key, body, &res); err != nil {
		return err
	}
	fmt.Fprintf(out, "reported %d dependencies\n", res.Accepted)
	return nil
}

type depSource struct{ rel, src string }

// collectDeps reads the manifests and sources under root and returns one entry per dependency.
func collectDeps(root string) ([]depEntry, error) {
	vers := map[depKey]string{}
	locked := map[depKey]string{} // lockfile pins beat manifest ranges
	var srcs []depSource
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDir[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil || len(b) > maxFileBytes {
			return nil
		}
		switch base := d.Name(); {
		case lockFiles[base].parse != nil:
			lk := lockFiles[base]
			m := lk.parse(b)
			if lk.eco == "PyPI" { // PyPI names compare normalised
				n := map[string]string{}
				for k, v := range m {
					n[pyNorm(k)] = v
				}
				m = n
			}
			addVers(locked, lk.eco, m)
		case base == "go.mod":
			addVers(vers, "Go", parseGoMod(string(b)))
		case base == "package.json":
			addVers(vers, "npm", parsePackageJSON(b))
		case base == "requirements.txt":
			addVers(vers, "PyPI", parseRequirements(string(b)))
		default:
			rel, _ := filepath.Rel(root, path)
			srcs = append(srcs, depSource{filepath.ToSlash(rel), string(b)})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for k, v := range locked {
		vers[k] = v
	}
	goMods := map[string]string{}
	for k, v := range vers {
		if k.eco == "Go" {
			goMods[k.name] = v
		}
	}
	used := map[depKey]map[string]bool{}
	for _, s := range srcs {
		switch strings.ToLower(filepath.Ext(s.rel)) {
		case ".go":
			if !strings.HasSuffix(s.rel, "_test.go") {
				merge(used, "Go", goSymbols(s.src, goMods))
			}
		case ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx":
			merge(used, "npm", jsSymbols(s.src))
		case ".py":
			merge(used, "PyPI", pySymbols(s.src))
		}
	}
	out := make([]depEntry, 0, len(vers))
	for k, v := range vers {
		syms := make([]string, 0, len(used[k]))
		for s := range used[k] {
			syms = append(syms, s)
		}
		sort.Strings(syms)
		out = append(out, depEntry{Name: k.name, Version: v, Ecosystem: k.eco, Symbols: syms})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ecosystem != out[j].Ecosystem {
			return out[i].Ecosystem < out[j].Ecosystem
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func addVers(dst map[depKey]string, eco string, in map[string]string) {
	for n, v := range in {
		k := depKey{eco, n}
		if _, ok := dst[k]; !ok { // first manifest (outermost walked) wins
			dst[k] = v
		}
	}
}

// merge folds a file's package -> symbols into the repo-wide set. Packages not in a manifest are
// kept; collectDeps only reads the ones it has a version for.
func merge(dst map[depKey]map[string]bool, eco string, in map[string][]string) {
	for pkg, syms := range in {
		k := depKey{eco, pkg}
		if dst[k] == nil {
			dst[k] = map[string]bool{}
		}
		for _, s := range syms {
			dst[k][s] = true
		}
	}
}

// ---- manifests ----

func parseGoMod(src string) map[string]string {
	out := map[string]string{}
	block := false
	for _, ln := range strings.Split(src, "\n") {
		ln = strings.TrimSpace(strings.SplitN(ln, "//", 2)[0])
		switch {
		case ln == "require (":
			block = true
			continue
		case ln == ")":
			block = false
			continue
		case strings.HasPrefix(ln, "require "):
			ln = strings.TrimSpace(strings.TrimPrefix(ln, "require "))
		case !block:
			continue
		}
		if f := strings.Fields(ln); len(f) >= 2 && strings.HasPrefix(f[1], "v") {
			out[f[0]] = strings.TrimPrefix(f[1], "v")
		}
	}
	return out
}

func parsePackageJSON(b []byte) map[string]string {
	var p struct {
		Deps map[string]string `json:"dependencies"`
		Dev  map[string]string `json:"devDependencies"`
	}
	out := map[string]string{}
	if json.Unmarshal(b, &p) != nil {
		return out
	}
	for _, m := range []map[string]string{p.Dev, p.Deps} {
		for n, v := range m {
			v = strings.TrimLeft(v, "^~>=< v")
			if v != "" && v[0] >= '0' && v[0] <= '9' {
				out[n] = v
			}
		}
	}
	return out
}

var reqLine = regexp.MustCompile(`^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*==\s*([^\s;#]+)`)

func parseRequirements(src string) map[string]string {
	out := map[string]string{}
	for _, ln := range strings.Split(src, "\n") {
		if m := reqLine.FindStringSubmatch(strings.TrimSpace(ln)); m != nil {
			out[pyNorm(m[1])] = m[2]
		}
	}
	return out
}

// ---- import -> package mapping ----

// goImportModule is the go.mod module an import path belongs to (longest prefix), or "".
func goImportModule(imp string, mods map[string]string) string {
	best := ""
	for m := range mods {
		if (imp == m || strings.HasPrefix(imp, m+"/")) && len(m) > len(best) {
			best = m
		}
	}
	return best
}

// jsPackage is the npm package for an import specifier (`@s/n/sub` -> `@s/n`), "" for relative
// or node: builtins.
func jsPackage(spec string) string {
	if spec == "" || spec[0] == '.' || spec[0] == '/' || strings.HasPrefix(spec, "node:") {
		return ""
	}
	p := strings.Split(spec, "/")
	if strings.HasPrefix(spec, "@") {
		if len(p) < 2 {
			return ""
		}
		return p[0] + "/" + p[1]
	}
	return p[0]
}

var pyAlias = map[string]string{"yaml": "pyyaml", "PIL": "pillow", "cv2": "opencv-python",
	"sklearn": "scikit-learn", "bs4": "beautifulsoup4", "dateutil": "python-dateutil"}

func pyNorm(s string) string {
	return strings.ToLower(strings.NewReplacer("_", "-", ".", "-").Replace(s))
}

// pyDist is the PyPI distribution (normalised) for a top-level import module.
func pyDist(module string) string {
	top := strings.SplitN(module, ".", 2)[0]
	if d, ok := pyAlias[top]; ok {
		return d
	}
	return pyNorm(top)
}

// ---- symbol extraction (per file: package -> symbols) ----

func add(m map[string][]string, pkg string, syms ...string) {
	if pkg != "" {
		m[pkg] = append(m[pkg], syms...)
	}
}

func goSymbols(src string, mods map[string]string) map[string][]string {
	out := map[string][]string{}
	f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, parser.ImportsOnly)
	if err != nil {
		return out
	}
	local := map[string]string{} // local name -> module
	for _, im := range f.Imports {
		path, _ := strconv.Unquote(im.Path.Value)
		mod := goImportModule(path, mods)
		if mod == "" {
			continue
		}
		name := filepath.Base(path)
		if i := strings.LastIndex(path, "/"); i > 0 && regexp.MustCompile(`^v\d+$`).MatchString(name) {
			name = filepath.Base(path[:i])
		}
		if im.Name != nil {
			name = im.Name.Name
		}
		local[name] = mod
		add(out, mod) // imported, even if no symbol is seen
	}
	code := regexp.MustCompile(`"[^"\n]*"`).ReplaceAllString(src, `""`) // import paths are not uses
	for l, mod := range local {
		for _, m := range regexp.MustCompile(`\b`+regexp.QuoteMeta(l)+`\.([A-Za-z_]\w*)`).FindAllStringSubmatch(code, -1) {
			add(out, mod, m[1])
		}
	}
	return out
}

var (
	jsImport  = regexp.MustCompile(`import\s+(?:(\w+)\s*,?\s*)?(?:\*\s+as\s+(\w+)|\{([^}]*)\})?\s*from\s*['"]([^'"]+)['"]`)
	jsRequire = regexp.MustCompile(`(?:const|let|var)\s+(\{[^}]*\}|\w+)\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)`)
)

func jsSymbols(src string) map[string][]string {
	out := map[string][]string{}
	named := func(pkg, list string) {
		for _, part := range strings.Split(strings.Trim(list, "{} \n"), ",") {
			f := strings.FieldsFunc(part, func(r rune) bool { return r == ':' || r == ' ' })
			if len(f) == 0 {
				continue
			}
			l := f[len(f)-1] // `a as b` / `a: b` -> b is the local name
			if len(regexp.MustCompile(`\b`+regexp.QuoteMeta(l)+`\b`).FindAllStringIndex(src, -1)) > 1 {
				add(out, pkg, f[0])
			}
		}
	}
	members := func(pkg, local string) {
		add(out, pkg)
		for _, m := range regexp.MustCompile(`\b`+regexp.QuoteMeta(local)+`\.([A-Za-z_$][\w$]*)`).FindAllStringSubmatch(src, -1) {
			add(out, pkg, m[1])
		}
	}
	for _, m := range jsImport.FindAllStringSubmatch(src, -1) {
		pkg := jsPackage(m[4])
		if pkg == "" {
			continue
		}
		add(out, pkg)
		for _, l := range []string{m[1], m[2]} {
			if l != "" {
				members(pkg, l)
			}
		}
		named(pkg, m[3])
	}
	for _, m := range jsRequire.FindAllStringSubmatch(src, -1) {
		pkg := jsPackage(m[2])
		if pkg == "" {
			continue
		}
		if strings.HasPrefix(m[1], "{") {
			add(out, pkg)
			named(pkg, m[1])
		} else {
			members(pkg, m[1])
		}
	}
	return out
}

var (
	pyImport = regexp.MustCompile(`(?m)^\s*import\s+([^\n#]+)`)
	pyFrom   = regexp.MustCompile(`(?m)^\s*from\s+([\w.]+)\s+import\s+(\([^)]*\)|[^\n#]+)`)
)

func pySymbols(src string) map[string][]string {
	out := map[string][]string{}
	for _, m := range pyImport.FindAllStringSubmatch(src, -1) {
		for _, item := range strings.Split(m[1], ",") {
			f := strings.Fields(item)
			if len(f) == 0 {
				continue
			}
			pkg, local := pyDist(f[0]), strings.SplitN(f[0], ".", 2)[0]
			if len(f) == 3 && f[1] == "as" {
				local = f[2]
			}
			add(out, pkg)
			for _, u := range regexp.MustCompile(`\b`+regexp.QuoteMeta(local)+`\.([A-Za-z_]\w*)`).FindAllStringSubmatch(src, -1) {
				add(out, pkg, u[1])
			}
		}
	}
	for _, m := range pyFrom.FindAllStringSubmatch(src, -1) {
		pkg := pyDist(m[1])
		add(out, pkg)
		for _, item := range strings.Split(strings.Trim(m[2], "() \n"), ",") {
			if f := strings.Fields(item); len(f) > 0 && f[0] != "*" {
				add(out, pkg, f[0])
			}
		}
	}
	return out
}
