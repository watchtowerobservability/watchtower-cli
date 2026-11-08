package main

// Taint pass for `wtctl scan` (Go sources). The regex rules cannot tell whether a value came from
// the user; this pass can. Per package (directory) it parses every .go file with go/parser, then:
//  1. summarises each function: which parameter positions reach a sink, directly or through calls
//     to other functions of the package (fixpoint, a few rounds);
//  2. for each function that takes an *http.Request, treats the request as the source and reports
//     every sink it reaches, in the function itself or in helpers it passes derived values to.
//
// A constant reaching the same sink is not reported. Sinks: database/sql-style query calls (the
// SQL text argument only, so parameterised queries stay clean) and os/exec command construction.
// shortcut: name-based call resolution (methods match by name), straight-line flow without
// branches or aliasing through struct fields. Upgrade: go/types plus an SSA call graph. JavaScript
// and Python get the same pass in scan_taint_js.go / scan_taint_py.go with pure-Go parsers (no cgo).

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
)

type taintFile struct {
	path string // repo-relative, slash separated
	src  string
}

type taintRuleMeta struct{ id, name, severity string }

var taintRules = []taintRuleMeta{
	{"sast/taint-sql-injection", "Request input flows into a SQL string", "9.0"},
	{"sast/taint-command-injection", "Request input flows into a shell command", "9.8"},
}

type taintHit struct {
	rule string
	file string
	line int
}

type taintFn struct {
	decl *ast.FuncDecl
	file string
}

var sqlSinks = map[string]bool{"Query": true, "QueryRow": true, "Exec": true, "Prepare": true,
	"QueryContext": true, "QueryRowContext": true, "ExecContext": true, "PrepareContext": true}

// untainting calls: numeric conversion yields a value that cannot carry an injection.
var taintBreakers = map[string]bool{"Atoi": true, "ParseInt": true, "ParseUint": true,
	"ParseFloat": true, "ParseBool": true, "Itoa": true, "FormatInt": true}

func calleeName(c *ast.CallExpr) string {
	switch f := c.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}

// sinkOf reports the rule and the index of the first dangerous argument when c is a sink call.
func sinkOf(c *ast.CallExpr) (string, int, bool) {
	name := calleeName(c)
	if sel, ok := c.Fun.(*ast.SelectorExpr); ok {
		if id, ok := sel.X.(*ast.Ident); ok && id.Name == "exec" && (name == "Command" || name == "CommandContext") {
			if name == "CommandContext" {
				return "sast/taint-command-injection", 1, true
			}
			return "sast/taint-command-injection", 0, true
		}
		if sqlSinks[name] && len(c.Args) > 0 { // r.URL.Query() takes no SQL text
			if strings.HasSuffix(name, "Context") {
				return "sast/taint-sql-injection", 1, true
			}
			return "sast/taint-sql-injection", 0, true
		}
	}
	return "", 0, false
}

func tainted(e ast.Expr, set map[string]bool) bool {
	hit := false
	ast.Inspect(e, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if _, _, isSink := sinkOf(x); isSink || taintBreakers[calleeName(x)] {
				return false
			}
		case *ast.Ident:
			if set[x.Name] {
				hit = true
			}
		}
		return !hit
	})
	return hit
}

// analyze walks fn in source order with the given tainted names and returns the sinks reached.
func analyze(fn *taintFn, seeds []string, sums map[string]map[int][]taintHit, fset *token.FileSet) []taintHit {
	set := map[string]bool{}
	for _, s := range seeds {
		set[s] = true
	}
	var hits []taintHit
	at := func(rule string, p token.Pos) taintHit {
		return taintHit{rule, fn.file, fset.Position(p).Line}
	}
	ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			for i, l := range x.Lhs {
				id, ok := l.(*ast.Ident)
				if !ok {
					continue
				}
				rhs := x.Rhs[len(x.Rhs)-1]
				if len(x.Rhs) == len(x.Lhs) {
					rhs = x.Rhs[i]
				}
				if tainted(rhs, set) {
					set[id.Name] = true
				} else if x.Tok == token.DEFINE || len(x.Rhs) == len(x.Lhs) {
					delete(set, id.Name) // overwritten with a clean value
				}
			}
		case *ast.ValueSpec:
			for i, nm := range x.Names {
				if i < len(x.Values) && tainted(x.Values[i], set) {
					set[nm.Name] = true
				}
			}
		case *ast.CallExpr:
			if rule, from, ok := sinkOf(x); ok {
				for _, a := range x.Args[min(from, len(x.Args)):] {
					if tainted(a, set) {
						hits = append(hits, at(rule, x.Pos()))
						break
					}
					if rule == "sast/taint-sql-injection" {
						break // later arguments are bind values, safe by construction
					}
				}
				break
			}
			for i, a := range x.Args {
				if tainted(a, set) {
					hits = append(hits, sums[calleeName(x)][i]...)
				}
			}
		}
		return true
	})
	return hits
}

func appendUnique(dst, src []taintHit) []taintHit {
	for _, h := range src {
		dup := false
		for _, d := range dst {
			dup = dup || d == h
		}
		if !dup {
			dst = append(dst, h)
		}
	}
	return dst
}

func isHTTPRequest(t ast.Expr) bool {
	s, ok := t.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := s.X.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Request"
}

// taintUnit is one function for the language-independent solver: its name, parameter names (by
// position), the request-typed parameters that seed it, and a walker that returns the sinks
// reached from a set of tainted names. The JS and Python passes (scan_taint_js.go,
// scan_taint_py.go) build the same units.
type taintUnit struct {
	name   string
	file   string
	params []string
	req    []string
	run    func(seeds []string, sums map[string]map[int][]taintHit) []taintHit
}

// taintSolve summarises every unit (fixpoint over calls by name), then reports what the request
// parameters reach.
func taintSolve(units []taintUnit) []sarifResult {
	sums := map[string]map[int][]taintHit{}
	for round := 0; round < 4; round++ {
		changed := false
		for _, u := range units {
			if sums[u.name] == nil {
				sums[u.name] = map[int][]taintHit{}
			}
			for i, p := range u.params {
				if p == "" || u.name == "" { // destructured parameter, or anonymous callback
					continue
				}
				got := appendUnique(sums[u.name][i], u.run([]string{p}, sums))
				if len(got) != len(sums[u.name][i]) {
					sums[u.name][i], changed = got, true
				}
			}
		}
		if !changed {
			break
		}
	}
	var all []taintHit
	for _, u := range units {
		if len(u.req) > 0 {
			all = appendUnique(all, u.run(u.req, sums))
		}
	}
	out := make([]sarifResult, 0, len(all))
	for _, h := range all {
		msg := "Request input reaches this sink without sanitisation"
		out = append(out, sarifResult{
			RuleID: h.rule, Level: "error", Message: sarifMessage{Text: msg},
			Locations: []sarifLocation{{Physical: sarifPhysical{
				Artifact: sarifArtifact{URI: h.file}, Region: sarifRegion{StartLine: h.line}}}},
		})
	}
	return out
}

// taintScan analyses one package's files and returns SARIF results.
func taintScan(files []taintFile) []sarifResult {
	fset := token.NewFileSet()
	var units []taintUnit
	for _, f := range files {
		af, err := parser.ParseFile(fset, f.path, f.src, 0)
		if err != nil {
			continue
		}
		for _, d := range af.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			fn := &taintFn{decl: fd, file: f.path}
			u := taintUnit{name: fd.Name.Name, file: f.path}
			for _, p := range fd.Type.Params.List {
				for _, nm := range p.Names {
					u.params = append(u.params, nm.Name)
					if isHTTPRequest(p.Type) {
						u.req = append(u.req, nm.Name)
					}
				}
			}
			u.run = func(seeds []string, sums map[string]map[int][]taintHit) []taintHit {
				return analyze(fn, seeds, sums, fset)
			}
			units = append(units, u)
		}
	}
	return taintSolve(units)
}
