package main

// Taint pass for Python sources: the same analysis as scan_taint.go (Go), over the pure-Go gpython
// parser so the Windows/Linux release builds stay cgo-free. A parameter named request/req, or the
// global `request` (Flask), is the source; sinks are SQL text passed to execute-style methods and
// shell commands passed to os.system / os.popen / subprocess with shell=True.
// shortcut: gpython parses Python 3.4 grammar, so a file using f-strings, async or variable
// annotations fails to parse and is skipped (the regex rules still cover it); name-based call
// resolution and straight-line flow. Upgrade: a parser for current Python.

import (
	"github.com/go-python/gpython/ast"
	"github.com/go-python/gpython/parser"
	"github.com/go-python/gpython/py"
)

var pySQLSinks = map[string]bool{"execute": true, "executemany": true, "executescript": true, "raw": true}

var pyBreakers = map[string]bool{"int": true, "float": true, "bool": true, "len": true}

var pySubprocess = map[string]bool{"run": true, "call": true, "check_call": true, "check_output": true, "Popen": true}

func pyCallee(c *ast.Call) (name, base string) {
	switch f := c.Func.(type) {
	case *ast.Name:
		return string(f.Id), ""
	case *ast.Attribute:
		if b, ok := f.Value.(*ast.Name); ok {
			base = string(b.Id)
		}
		return string(f.Attr), base
	}
	return "", ""
}

func pySink(c *ast.Call) (string, bool) {
	name, base := pyCallee(c)
	_, isMember := c.Func.(*ast.Attribute)
	switch {
	case isMember && pySQLSinks[name]:
		return "sast/taint-sql-injection", true
	case base == "os" && (name == "system" || name == "popen"):
		return "sast/taint-command-injection", true
	case base == "subprocess" && pySubprocess[name]:
		for _, k := range c.Keywords {
			if nc, ok := k.Value.(*ast.NameConstant); ok && string(k.Arg) == "shell" && nc.Value == py.True {
				return "sast/taint-command-injection", true
			}
		}
	}
	return "", false
}

func pyTainted(e ast.Ast, set map[string]bool) bool {
	hit := false
	ast.Walk(e, func(n ast.Ast) bool {
		switch x := n.(type) {
		case *ast.Call:
			name, _ := pyCallee(x)
			if _, isSink := pySink(x); isSink || pyBreakers[name] {
				return false
			}
		case *ast.Name:
			hit = hit || set[string(x.Id)]
		}
		return !hit
	})
	return hit
}

func pyAnalyze(fd *ast.FunctionDef, path string, seeds []string, sums map[string]map[int][]taintHit) []taintHit {
	set := map[string]bool{}
	for _, s := range seeds {
		set[s] = true
	}
	// assign propagates taint from value to every plain name in target (tuples unpack).
	var assign func(target ast.Expr, value ast.Ast, clean bool)
	assign = func(target ast.Expr, value ast.Ast, clean bool) {
		switch t := target.(type) {
		case *ast.Name:
			if pyTainted(value, set) {
				set[string(t.Id)] = true
			} else if clean {
				delete(set, string(t.Id))
			}
		case *ast.Tuple:
			for _, e := range t.Elts {
				assign(e, value, clean)
			}
		case *ast.List:
			for _, e := range t.Elts {
				assign(e, value, clean)
			}
		}
	}
	var hits []taintHit
	// gpython leaves Call.Pos empty for trailer calls (a.b(...)), so report the enclosing statement's line.
	line := 0
	visit := func(n ast.Ast) bool {
		if _, ok := n.(ast.Stmt); ok && n.GetLineno() > 0 {
			line = n.GetLineno()
		}
		switch x := n.(type) {
		case *ast.Assign:
			for _, t := range x.Targets {
				assign(t, x.Value, true)
			}
		case *ast.AugAssign:
			assign(x.Target, x.Value, false)
		case *ast.For:
			assign(x.Target, x.Iter, false)
		case *ast.Call:
			if rule, ok := pySink(x); ok {
				if len(x.Args) > 0 && pyTainted(x.Args[0], set) { // later args are bind values
					hits = append(hits, taintHit{rule, path, line})
				}
				break
			}
			if name, _ := pyCallee(x); name != "" {
				for i, a := range x.Args {
					if pyTainted(a, set) {
						hits = append(hits, sums[name][i]...)
					}
				}
			}
		}
		return true
	}
	for _, s := range fd.Body {
		ast.Walk(s, visit)
	}
	return hits
}

// pyUnits parses one Python file and returns a taint unit per function (methods included).
func pyUnits(path, src string) []taintUnit {
	mod, err := parser.ParseString(src, py.ExecMode)
	if err != nil {
		return nil
	}
	var units []taintUnit
	ast.Walk(mod, func(n ast.Ast) bool {
		fd, ok := n.(*ast.FunctionDef)
		if !ok {
			return true
		}
		u := taintUnit{name: string(fd.Name), file: path, req: []string{"request"}}
		var args []*ast.Arg
		if fd.Args != nil {
			args = fd.Args.Args
		}
		for i, a := range args {
			p := string(a.Arg)
			if i == 0 && (p == "self" || p == "cls") {
				continue // keep positions aligned with call sites
			}
			u.params = append(u.params, p)
			if p == "req" {
				u.req = append(u.req, p)
			}
		}
		u.run = func(seeds []string, sums map[string]map[int][]taintHit) []taintHit {
			return pyAnalyze(fd, path, seeds, sums)
		}
		units = append(units, u)
		return true
	})
	return units
}

// taintScanPy analyses one directory's Python files together.
func taintScanPy(files []taintFile) []sarifResult {
	var units []taintUnit
	for _, f := range files {
		units = append(units, pyUnits(f.path, f.src)...)
	}
	return taintSolve(units)
}
