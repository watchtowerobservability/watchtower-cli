package main

// Taint pass for JavaScript sources: the same analysis as scan_taint.go (Go), over the pure-Go
// goja parser so the Windows/Linux release builds stay cgo-free. A function parameter named req or
// request is the source (Express/Koa/Fastify handlers); sinks are SQL text passed to query-style
// methods and shell commands passed to child_process exec.
// shortcut: name-based call resolution, straight-line flow, request recognised by parameter name
// (JS has no types), TypeScript not parsed. Upgrade: a TypeScript-capable parser.

import (
	"reflect"
	"strings"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/file"
	"github.com/dop251/goja/parser"
	"github.com/dop251/goja/token"
)

var jsSQLSinks = map[string]bool{"query": true, "execute": true, "prepare": true, "raw": true,
	"queryRaw": true, "$queryRawUnsafe": true}

var jsBreakers = map[string]bool{"parseInt": true, "parseFloat": true, "Number": true, "Boolean": true}

// jsWalk visits every node under v in source order; f returns false to skip a node's children.
// Value-typed Identifiers (property names in a.b) are not nodes here, so only reads are seen.
func jsWalk(v reflect.Value, f func(ast.Node) bool) {
	switch v.Kind() {
	case reflect.Interface:
		if !v.IsNil() {
			jsWalk(v.Elem(), f)
		}
	case reflect.Ptr:
		if v.IsNil() || !v.CanInterface() {
			return
		}
		if n, ok := v.Interface().(ast.Node); ok && !f(n) {
			return
		}
		jsWalk(v.Elem(), f)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).Name != "DeclarationList" { // hoisted copies of the body's bindings
				jsWalk(v.Field(i), f)
			}
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			jsWalk(v.Index(i), f)
		}
	}
}

func jsCallee(c *ast.CallExpression) (name, base string) {
	switch f := c.Callee.(type) {
	case *ast.Identifier:
		return f.Name.String(), ""
	case *ast.DotExpression:
		if b, ok := f.Left.(*ast.Identifier); ok {
			base = b.Name.String()
		}
		return f.Identifier.Name.String(), base
	}
	return "", ""
}

func jsSink(c *ast.CallExpression) (string, bool) {
	name, base := jsCallee(c)
	_, isMember := c.Callee.(*ast.DotExpression)
	switch {
	case isMember && jsSQLSinks[name]:
		return "sast/taint-sql-injection", true
	case (name == "exec" || name == "execSync") && (!isMember || base == "child_process" || base == "cp"):
		return "sast/taint-command-injection", true
	}
	return "", false
}

func jsTainted(e ast.Node, set map[string]bool) bool {
	hit := false
	jsWalk(reflect.ValueOf(e), func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpression:
			name, _ := jsCallee(x)
			if _, isSink := jsSink(x); isSink || jsBreakers[name] {
				return false
			}
		case *ast.Identifier:
			hit = hit || set[x.Name.String()]
		case *ast.PropertyShort:
			hit = hit || set[x.Name.Name.String()]
		}
		return !hit
	})
	return hit
}

func jsAnalyze(body ast.Node, path string, line func(file.Idx) int, seeds []string,
	sums map[string]map[int][]taintHit) []taintHit {
	set := map[string]bool{}
	for _, s := range seeds {
		set[s] = true
	}
	assign := func(t ast.Node, rhs ast.Node, clean bool) {
		if id, ok := t.(*ast.Identifier); ok && rhs != nil {
			if jsTainted(rhs, set) {
				set[id.Name.String()] = true
			} else if clean {
				delete(set, id.Name.String())
			}
		}
	}
	var hits []taintHit
	jsWalk(reflect.ValueOf(body), func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.Binding:
			if x.Initializer != nil {
				assign(x.Target, x.Initializer, true)
			}
		case *ast.AssignExpression:
			assign(x.Left, x.Right, x.Operator == token.ASSIGN)
		case *ast.CallExpression:
			if rule, ok := jsSink(x); ok {
				if len(x.ArgumentList) > 0 && jsTainted(x.ArgumentList[0], set) { // later args are bind values
					hits = append(hits, taintHit{rule, path, line(x.Idx0())})
				}
				break
			}
			if name, _ := jsCallee(x); name != "" {
				for i, a := range x.ArgumentList {
					if jsTainted(a, set) {
						hits = append(hits, sums[name][i]...)
					}
				}
			}
		}
		return true
	})
	return hits
}

// jsUnits parses one JavaScript file and returns a taint unit per function in it.
func jsUnits(path, src string) []taintUnit {
	prog, err := parser.ParseFile(nil, path, src, 0)
	if err != nil {
		return nil
	}
	line := func(i file.Idx) int { return 1 + strings.Count(src[:max(0, min(int(i)-1, len(src)))], "\n") }
	names := map[ast.Node]string{} // function literal -> the name it is bound to
	nameOf := func(target, lit ast.Node) {
		switch t := target.(type) {
		case *ast.Identifier:
			names[lit] = t.Name.String()
		case *ast.DotExpression:
			names[lit] = t.Identifier.Name.String()
		case *ast.StringLiteral:
			names[lit] = t.Value.String()
		}
	}
	var units []taintUnit
	add := func(name string, pl *ast.ParameterList, body ast.Node) {
		u := taintUnit{name: name, file: path}
		if pl != nil {
			for _, b := range pl.List {
				id, _ := b.Target.(*ast.Identifier)
				p := ""
				if id != nil {
					p = id.Name.String()
				}
				u.params = append(u.params, p)
				if p == "req" || p == "request" {
					u.req = append(u.req, p)
				}
			}
		}
		u.run = func(seeds []string, sums map[string]map[int][]taintHit) []taintHit {
			return jsAnalyze(body, path, line, seeds, sums)
		}
		units = append(units, u)
	}
	jsWalk(reflect.ValueOf(prog), func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.Binding:
			nameOf(x.Target, x.Initializer)
		case *ast.AssignExpression:
			nameOf(x.Left, x.Right)
		case *ast.PropertyKeyed:
			nameOf(x.Key, x.Value)
		case *ast.MethodDefinition:
			nameOf(x.Key, x.Body)
		case *ast.FunctionLiteral:
			name := names[x]
			if x.Name != nil {
				name = x.Name.Name.String()
			}
			add(name, x.ParameterList, x.Body)
		case *ast.ArrowFunctionLiteral:
			add(names[x], x.ParameterList, x.Body)
		}
		return true
	})
	return units
}

// taintScanJS analyses one directory's JavaScript files together, so helpers in sibling files
// resolve by name just like the Go pass.
func taintScanJS(files []taintFile) []sarifResult {
	var units []taintUnit
	for _, f := range files {
		units = append(units, jsUnits(f.path, f.src)...)
	}
	return taintSolve(units)
}
