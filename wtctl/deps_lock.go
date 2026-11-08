package main

// Lockfile parsing for `wtctl deps upload` (C7): a lockfile pins the versions that actually ship,
// so a dependency in a service that never ran is still reported. A lockfile wins over the manifest
// range for the same package (addVers keeps the first writer, and lockfiles are read first).
// shortcut: npm lockfile v1-v3, yarn.lock v1, poetry.lock/Cargo.lock/Pipfile.lock and go.sum are
// read for name+version only; no dev/prod split, no transitive-path info. Upgrade: per-ecosystem
// resolvers if a finding needs the dependency path.

import (
	"encoding/json"
	"regexp"
	"strings"
)

// lockFiles maps a base file name to its OSV ecosystem and parser.
var lockFiles = map[string]struct {
	eco   string
	parse func(b []byte) map[string]string
}{
	"package-lock.json":   {"npm", parsePackageLock},
	"npm-shrinkwrap.json": {"npm", parsePackageLock},
	"yarn.lock":           {"npm", parseYarnLock},
	"poetry.lock":         {"PyPI", parseTOMLPackages},
	"Cargo.lock":          {"crates.io", parseTOMLPackages},
	"Pipfile.lock":        {"PyPI", parsePipfileLock},
	"go.sum":              {"Go", parseGoSum},
}

func parsePackageLock(b []byte) map[string]string {
	var p struct {
		Packages     map[string]struct{ Version string } `json:"packages"`
		Dependencies map[string]struct{ Version string } `json:"dependencies"`
	}
	out := map[string]string{}
	if json.Unmarshal(b, &p) != nil {
		return out
	}
	for path, v := range p.Packages { // v2/v3: "node_modules/a/node_modules/@s/b"
		if i := strings.LastIndex(path, "node_modules/"); i >= 0 && v.Version != "" {
			out[path[i+len("node_modules/"):]] = v.Version
		}
	}
	for n, v := range p.Dependencies { // v1 (and the v2 mirror)
		if _, ok := out[n]; !ok && v.Version != "" {
			out[n] = v.Version
		}
	}
	return out
}

var yarnHead = regexp.MustCompile(`^"?(@?[^@\s"]+)@`)

func parseYarnLock(b []byte) map[string]string {
	out := map[string]string{}
	name := ""
	for _, ln := range strings.Split(string(b), "\n") {
		switch {
		case ln != "" && ln[0] != ' ' && ln[0] != '#':
			if m := yarnHead.FindStringSubmatch(ln); m != nil {
				name = m[1]
			}
		case name != "" && strings.HasPrefix(ln, "  version "):
			out[name] = strings.Trim(strings.TrimSpace(strings.TrimPrefix(ln, "  version ")), `"`)
			name = ""
		}
	}
	return out
}

var tomlKV = regexp.MustCompile(`^(name|version)\s*=\s*"([^"]*)"`)

// parseTOMLPackages reads `[[package]]` tables with name and version (poetry.lock, Cargo.lock).
func parseTOMLPackages(b []byte) map[string]string {
	out := map[string]string{}
	var name, ver string
	flush := func() {
		if name != "" && ver != "" {
			out[pyNormIf(name)] = ver
		}
		name, ver = "", ""
	}
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "[[package]]" {
			flush()
		} else if m := tomlKV.FindStringSubmatch(ln); m != nil {
			if m[1] == "name" {
				name = m[2]
			} else {
				ver = m[2]
			}
		}
	}
	flush()
	return out
}

// pyNormIf leaves crate names alone; PyPI names are normalised by the caller's ecosystem.
func pyNormIf(s string) string { return s }

func parsePipfileLock(b []byte) map[string]string {
	var p struct {
		Default map[string]struct{ Version string } `json:"default"`
		Develop map[string]struct{ Version string } `json:"develop"`
	}
	out := map[string]string{}
	if json.Unmarshal(b, &p) != nil {
		return out
	}
	for _, m := range []map[string]struct{ Version string }{p.Develop, p.Default} {
		for n, v := range m {
			if ver := strings.TrimPrefix(v.Version, "=="); ver != "" {
				out[pyNorm(n)] = ver
			}
		}
	}
	return out
}

func parseGoSum(b []byte) map[string]string {
	out := map[string]string{}
	for _, ln := range strings.Split(string(b), "\n") {
		f := strings.Fields(ln)
		if len(f) >= 2 && strings.HasPrefix(f[1], "v") && !strings.HasSuffix(f[1], "/go.mod") {
			out[f[0]] = strings.TrimPrefix(f[1], "v")
		}
	}
	return out
}
