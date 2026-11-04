// Package mibc compiles SMIv1/SMIv2 MIB modules into the agent's SNMP manifests and trap
// profiles (INF-014, INF-015, gap G-20), so a vendor MIB can be polled and its traps named
// without hand-written YAML. It is our own small parser: it reads the subset of the MIB
// grammar that names objects (OBJECT IDENTIFIER, OBJECT-TYPE, NOTIFICATION-TYPE, TRAP-TYPE and
// the other macro invocations that assign an OID), textual conventions and type assignments.
// MACRO bodies are skipped.
package mibc

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

type tok struct {
	s    string
	str  bool // a quoted string
	line int
}

// lex splits MIB text into tokens: identifiers (letters, digits, '-', '_'), numbers, quoted
// strings, "::=", "..", and single punctuation. "--" starts a comment that ends at the next
// "--" or at the end of the line.
func lex(src string) ([]tok, error) {
	var out []tok
	line := 1
	r := []rune(src)
	for i := 0; i < len(r); {
		c := r[i]
		switch {
		case c == '\n':
			line++
			i++
		case unicode.IsSpace(c):
			i++
		case c == '-' && i+1 < len(r) && r[i+1] == '-':
			i += 2
			for i < len(r) && r[i] != '\n' {
				if r[i] == '-' && i+1 < len(r) && r[i+1] == '-' {
					i += 2
					break
				}
				i++
			}
		case c == '"':
			j := i + 1
			start := line
			for j < len(r) && r[j] != '"' {
				if r[j] == '\n' {
					line++
				}
				j++
			}
			if j >= len(r) {
				return nil, fmt.Errorf("line %d: unterminated string", start)
			}
			out = append(out, tok{s: string(r[i+1 : j]), str: true, line: start})
			i = j + 1
		case c == '\'':
			// binary/hex literal such as '0F'H: one token
			j := i + 1
			for j < len(r) && r[j] != '\'' {
				j++
			}
			j = min(j+2, len(r))
			out = append(out, tok{s: string(r[i:j]), line: line})
			i = j
		case c == ':' && i+2 < len(r) && r[i+1] == ':' && r[i+2] == '=':
			out = append(out, tok{s: "::=", line: line})
			i += 3
		case c == '.' && i+1 < len(r) && r[i+1] == '.':
			out = append(out, tok{s: "..", line: line})
			i += 2
		case unicode.IsLetter(c) || unicode.IsDigit(c):
			j := i
			for j < len(r) && (unicode.IsLetter(r[j]) || unicode.IsDigit(r[j]) || r[j] == '-' || r[j] == '_') {
				if r[j] == '-' && j+1 < len(r) && r[j+1] == '-' {
					break
				}
				j++
			}
			out = append(out, tok{s: string(r[i:j]), line: line})
			i = j
		default:
			out = append(out, tok{s: string(c), line: line})
			i++
		}
	}
	return out, nil
}

// Object is one named node of a module.
type Object struct {
	Name, Module string
	Macro        string // OBJECT-TYPE, NOTIFICATION-TYPE, TRAP-TYPE, OBJECT IDENTIFIER, ...
	Parent       string // first component of the OID value
	Sub          []int  // the numeric components after Parent
	Syntax       string // base type name, e.g. Counter64, INTEGER, DisplayString
	SequenceOf   string // SYNTAX SEQUENCE OF <entry type>: this object is a table
	Enum         map[int]string
	Units        string
	Access       string
	Index        []string
	Augments     string
	Objects      []string // NOTIFICATION-TYPE OBJECTS, TRAP-TYPE VARIABLES
	Enterprise   string   // TRAP-TYPE ENTERPRISE
	Description  string
	Line         int
}

// TypeDef is a textual convention or a type assignment.
type TypeDef struct {
	Base string
	Enum map[int]string
}

// Module is one parsed MIB module.
type Module struct {
	Name    string
	Objects []*Object
	Types   map[string]TypeDef
}

var oidMacros = map[string]bool{
	"OBJECT-TYPE": true, "NOTIFICATION-TYPE": true, "MODULE-IDENTITY": true, "OBJECT-IDENTITY": true,
	"OBJECT-GROUP": true, "NOTIFICATION-GROUP": true, "MODULE-COMPLIANCE": true, "AGENT-CAPABILITIES": true,
	"TRAP-TYPE": true,
}

type parser struct {
	t []tok
	i int
}

func (p *parser) peek(n int) string {
	if p.i+n < len(p.t) {
		return p.t[p.i+n].s
	}
	return ""
}

// skipBalanced skips from an opening bracket to its partner.
func (p *parser) skipBalanced(open, closing string) {
	depth := 0
	for p.i < len(p.t) {
		s := p.t[p.i]
		p.i++
		if s.str {
			continue
		}
		switch s.s {
		case open:
			depth++
		case closing:
			depth--
			if depth <= 0 {
				return
			}
		}
	}
}

// names reads "{ a, b, IMPLIED c }" and returns the identifiers.
func (p *parser) names() []string {
	var out []string
	if p.peek(0) != "{" {
		return nil
	}
	p.i++
	for p.i < len(p.t) && p.peek(0) != "}" {
		s := p.t[p.i].s
		if s != "," && s != "IMPLIED" {
			out = append(out, s)
		}
		p.i++
	}
	p.i++
	return out
}

// enum reads "{ up(1), down(2) }".
func (p *parser) enum() map[int]string {
	out := map[int]string{}
	p.i++ // {
	for p.i < len(p.t) && p.peek(0) != "}" {
		if p.peek(1) == "(" {
			if n, err := strconv.Atoi(p.peek(2)); err == nil {
				out[n] = p.peek(0)
			}
			p.i += 4
			continue
		}
		p.i++
	}
	p.i++
	return out
}

// syntax reads a SYNTAX clause value into o or td.
func (p *parser) syntax() (base, seqOf string, enum map[int]string) {
	switch p.peek(0) {
	case "SEQUENCE":
		if p.peek(1) == "OF" {
			seqOf = p.peek(2)
			p.i += 3
			return "SEQUENCE", seqOf, nil
		}
		p.i++
		p.skipBalanced("{", "}")
		return "SEQUENCE", "", nil
	case "OCTET", "OBJECT":
		base = p.peek(0) + " " + p.peek(1)
		p.i += 2
	default:
		base = p.peek(0)
		p.i++
	}
	if p.peek(0) == "{" {
		enum = p.enum()
	}
	if p.peek(0) == "(" {
		p.skipBalanced("(", ")")
	}
	return base, "", enum
}

// oidValue reads "{ parent 1 2 }", "{ iso org(3) dod(6) 1 }" or "{ 1 3 6 1 }".
func (p *parser) oidValue() (string, []int, error) {
	if p.peek(0) != "{" {
		return "", nil, fmt.Errorf("line %d: expected an OID value", p.t[min(p.i, len(p.t)-1)].line)
	}
	p.i++
	parent := ""
	var sub []int
	for p.i < len(p.t) && p.peek(0) != "}" {
		s := p.peek(0)
		switch {
		case p.peek(1) == "(": // name(number)
			n, err := strconv.Atoi(p.peek(2))
			if err != nil {
				return "", nil, fmt.Errorf("line %d: bad OID component", p.t[p.i].line)
			}
			if parent == "" && len(sub) == 0 {
				// a leading name(number) also fixes the root number, e.g. iso(1)
				parent, sub = rootName(s, n)
			} else {
				sub = append(sub, n)
			}
			p.i += 4
		case isNumber(s):
			n, _ := strconv.Atoi(s)
			sub = append(sub, n)
			p.i++
		default:
			if parent != "" || len(sub) > 0 {
				return "", nil, fmt.Errorf("line %d: OID name %q after the first component", p.t[p.i].line, s)
			}
			parent = s
			p.i++
		}
	}
	p.i++
	if parent == "" {
		parent = "$root"
	}
	return parent, sub, nil
}

func rootName(name string, n int) (string, []int) {
	switch name {
	case "iso", "ccitt", "joint-iso-ccitt":
		return name, nil
	}
	return "$root", []int{n}
}

func isNumber(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

// Parse reads every module in src.
func Parse(src string) ([]*Module, error) {
	ts, err := lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{t: ts}
	var mods []*Module
	for p.i < len(p.t) {
		if p.peek(1) == "DEFINITIONS" {
			m, err := p.module()
			if err != nil {
				return nil, err
			}
			mods = append(mods, m)
			continue
		}
		p.i++
	}
	if len(mods) == 0 {
		return nil, errors.New("no MIB module (NAME DEFINITIONS ::= BEGIN) found")
	}
	return mods, nil
}

func (p *parser) module() (*Module, error) {
	m := &Module{Name: p.peek(0), Types: map[string]TypeDef{}}
	for p.i < len(p.t) && p.peek(0) != "BEGIN" {
		p.i++
	}
	p.i++
	for p.i < len(p.t) {
		switch {
		case p.peek(0) == "END":
			p.i++
			return m, nil
		case p.peek(0) == "IMPORTS":
			for p.i < len(p.t) && p.peek(0) != ";" {
				p.i++
			}
			p.i++
		case p.peek(1) == "MACRO":
			for p.i < len(p.t) && p.peek(0) != "END" {
				p.i++
			}
			p.i++
		case p.peek(1) == "OBJECT" && p.peek(2) == "IDENTIFIER" && p.peek(3) == "::=":
			o := &Object{Name: p.peek(0), Module: m.Name, Macro: "OBJECT IDENTIFIER", Line: p.t[p.i].line}
			p.i += 4
			var err error
			if o.Parent, o.Sub, err = p.oidValue(); err != nil {
				return nil, err
			}
			m.Objects = append(m.Objects, o)
		case oidMacros[p.peek(1)]:
			o, err := p.macro(m.Name)
			if err != nil {
				return nil, err
			}
			m.Objects = append(m.Objects, o)
		case p.peek(1) == "::=" && unicode.IsUpper([]rune(p.peek(0) + " ")[0]):
			name := p.peek(0)
			p.i += 2
			m.Types[name] = p.typeDef()
		default:
			p.i++
		}
	}
	return m, nil
}

// typeDef reads the right side of "Name ::= ...": a TEXTUAL-CONVENTION or a plain type.
func (p *parser) typeDef() TypeDef {
	if p.peek(0) == "TEXTUAL-CONVENTION" {
		p.i++
		for p.i < len(p.t) && p.peek(0) != "SYNTAX" {
			p.i++
		}
		p.i++
	}
	if p.peek(0) == "[" { // [APPLICATION n] IMPLICIT
		p.skipBalanced("[", "]")
		if p.peek(0) == "IMPLICIT" {
			p.i++
		}
	}
	base, _, enum := p.syntax()
	return TypeDef{Base: base, Enum: enum}
}

// macro reads "name MACRO clauses ::= value".
func (p *parser) macro(module string) (*Object, error) {
	o := &Object{Name: p.peek(0), Module: module, Macro: p.peek(1), Line: p.t[p.i].line}
	p.i += 2
	for p.i < len(p.t) && p.peek(0) != "::=" {
		switch p.peek(0) {
		case "SYNTAX":
			if o.Syntax != "" { // a MODULE-COMPLIANCE refinement; keep the first
				p.i++
				continue
			}
			p.i++
			o.Syntax, o.SequenceOf, o.Enum = p.syntax()
		case "UNITS":
			o.Units = p.peek(1)
			p.i += 2
		case "MAX-ACCESS", "ACCESS":
			o.Access = p.peek(1)
			p.i += 2
		case "INDEX":
			p.i++
			o.Index = p.names()
		case "AUGMENTS":
			p.i++
			if a := p.names(); len(a) > 0 {
				o.Augments = a[0]
			}
		case "OBJECTS", "VARIABLES":
			p.i++
			o.Objects = p.names()
		case "ENTERPRISE":
			o.Enterprise = p.peek(1)
			p.i += 2
		case "DESCRIPTION":
			if p.i+1 < len(p.t) && p.t[p.i+1].str {
				o.Description = strings.Join(strings.Fields(p.t[p.i+1].s), " ")
			}
			p.i += 2
		case "DEFVAL", "WRITE-SYNTAX":
			p.i++
			if p.peek(0) == "{" {
				p.skipBalanced("{", "}")
			}
		default:
			p.i++
		}
	}
	p.i++ // ::=
	if o.Macro == "TRAP-TYPE" {
		n, err := strconv.Atoi(p.peek(0))
		if err != nil {
			return nil, fmt.Errorf("line %d: TRAP-TYPE %s needs a number", o.Line, o.Name)
		}
		p.i++
		o.Parent, o.Sub = o.Enterprise, []int{0, n}
		return o, nil
	}
	var err error
	o.Parent, o.Sub, err = p.oidValue()
	return o, err
}
