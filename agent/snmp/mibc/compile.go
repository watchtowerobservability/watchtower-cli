package mibc

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/watchtowerobservability/watchtower-cli/agent/snmp"
)

const (
	maxTables     = 64
	maxItems      = 64
	maxScalars    = 128
	maxDescLen    = 200
	maxTypeChase  = 10
	maxOIDDepth   = 128
	maxTrapsOfMIB = 2000
)

// wellKnown are the roots most MIBs import from SNMPv2-SMI / RFC1155-SMI, so a vendor MIB
// compiles without those files.
var wellKnown = map[string]string{
	"iso": "1", "ccitt": "0", "joint-iso-ccitt": "2", "$root": "",
	"org": "1.3", "dod": "1.3.6", "internet": "1.3.6.1", "directory": "1.3.6.1.1", "mgmt": "1.3.6.1.2",
	"mib-2": "1.3.6.1.2.1", "system": "1.3.6.1.2.1.1", "interfaces": "1.3.6.1.2.1.2", "transmission": "1.3.6.1.2.1.10",
	"experimental": "1.3.6.1.3", "private": "1.3.6.1.4", "enterprises": "1.3.6.1.4.1", "security": "1.3.6.1.5",
	"snmpV2": "1.3.6.1.6", "snmpDomains": "1.3.6.1.6.1", "snmpProxys": "1.3.6.1.6.2", "snmpModules": "1.3.6.1.6.3",
	"zeroDotZero": "0.0",
}

// wellKnownTypes are common textual conventions, used when their defining MIB is not loaded.
var wellKnownTypes = map[string]TypeDef{
	"DisplayString": {Base: "OCTET STRING"}, "SnmpAdminString": {Base: "OCTET STRING"}, "PhysAddress": {Base: "OCTET STRING"},
	"MacAddress": {Base: "OCTET STRING"}, "DateAndTime": {Base: "OCTET STRING"}, "InetAddress": {Base: "OCTET STRING"},
	"TimeStamp": {Base: "TimeTicks"}, "TimeInterval": {Base: "INTEGER"}, "InterfaceIndex": {Base: "Integer32"},
	"InterfaceIndexOrZero": {Base: "Integer32"}, "CounterBasedGauge64": {Base: "Gauge32"},
	"ZeroBasedCounter32": {Base: "Counter32"}, "ZeroBasedCounter64": {Base: "Counter64"},
	"TruthValue":      {Base: "INTEGER", Enum: map[int]string{1: "true", 2: "false"}},
	"RowStatus":       {Base: "INTEGER", Enum: map[int]string{1: "active", 2: "notInService", 3: "notReady", 4: "createAndGo", 5: "createAndWait", 6: "destroy"}},
	"InetAddressType": {Base: "INTEGER", Enum: map[int]string{0: "unknown", 1: "ipv4", 2: "ipv6", 3: "ipv4z", 4: "ipv6z", 16: "dns"}},
}

var numericBase = map[string]string{
	"INTEGER": "gauge", "Integer32": "gauge", "Unsigned32": "gauge", "Gauge32": "gauge", "Gauge": "gauge",
	"TimeTicks": "gauge", "Counter32": "counter", "Counter": "counter", "Counter64": "counter",
}

// Compiler resolves names across every module added to it.
type Compiler struct {
	objs  map[string]*Object
	types map[string]TypeDef
	oids  map[string]string
	mods  map[string]*Module
}

// New returns an empty compiler.
func New() *Compiler {
	return &Compiler{objs: map[string]*Object{}, types: map[string]TypeDef{}, oids: map[string]string{}, mods: map[string]*Module{}}
}

// Add registers parsed modules. A later definition of a name replaces an earlier one.
func (c *Compiler) Add(mods ...*Module) {
	for _, m := range mods {
		c.mods[m.Name] = m
		for _, o := range m.Objects {
			c.objs[o.Name] = o
		}
		for k, v := range m.Types {
			c.types[k] = v
		}
	}
	clear(c.oids)
}

// AddFile parses and adds one MIB file.
func (c *Compiler) AddFile(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	mods, err := Parse(string(b))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.Add(mods...)
	names := make([]string, len(mods))
	for i, m := range mods {
		names[i] = m.Name
	}
	return names, nil
}

// OID resolves a name to its dotted OID.
func (c *Compiler) OID(name string) (string, error) {
	return c.resolve(name, 0)
}

func (c *Compiler) resolve(name string, depth int) (string, error) {
	if v, ok := c.oids[name]; ok {
		return v, nil
	}
	o, ok := c.objs[name]
	if !ok {
		if v, ok := wellKnown[name]; ok {
			return v, nil
		}
		return "", fmt.Errorf("%s is not defined (load the MIB that defines it)", name)
	}
	if depth > maxOIDDepth {
		return "", fmt.Errorf("%s: OID definition loops", name)
	}
	base, err := c.resolve(o.Parent, depth+1)
	if err != nil {
		return "", err
	}
	parts := []string{}
	if base != "" {
		parts = append(parts, base)
	}
	for _, n := range o.Sub {
		parts = append(parts, strconv.Itoa(n))
	}
	v := strings.Join(parts, ".")
	c.oids[name] = v
	return v, nil
}

// baseType follows textual conventions down to an SMI base type and the first enum seen.
func (c *Compiler) baseType(syntax string, enum map[int]string) (string, map[int]string) {
	for range maxTypeChase {
		if _, ok := numericBase[syntax]; ok || syntax == "" {
			return syntax, enum
		}
		td, ok := c.types[syntax]
		if !ok {
			td, ok = wellKnownTypes[syntax]
		}
		if !ok {
			return syntax, enum
		}
		if enum == nil {
			enum = td.Enum
		}
		syntax = td.Base
	}
	return syntax, enum
}

// snake turns "cpmCPUTotal5secRev" into "cpm_cpu_total5sec_rev".
func snake(s string) string {
	r := []rune(s)
	var b strings.Builder
	for i, c := range r {
		if c == '-' {
			b.WriteByte('_')
			continue
		}
		if unicode.IsUpper(c) && i > 0 {
			prev := r[i-1]
			nextLower := i+1 < len(r) && unicode.IsLower(r[i+1])
			if unicode.IsLower(prev) || unicode.IsDigit(prev) || unicode.IsUpper(prev) && nextLower {
				b.WriteByte('_')
			}
		}
		b.WriteRune(unicode.ToLower(c))
	}
	return b.String()
}

func metricPrefix(module string) string {
	return "snmp." + snake(strings.TrimSuffix(strings.TrimSuffix(module, "-MIB"), "-SMI"))
}

func accessible(o *Object) bool {
	switch o.Access {
	case "not-accessible", "accessible-for-notify":
		return false
	}
	return true
}

func isLabel(name, base string) bool {
	if base != "OCTET STRING" {
		return false
	}
	l := strings.ToLower(name)
	for _, s := range []string{"name", "descr", "description", "alias"} {
		if strings.HasSuffix(l, s) {
			return true
		}
	}
	return false
}

// item maps one object to a manifest item; ok is false for non-numeric or hidden objects.
func (c *Compiler) item(o *Object, prefix string) (snmp.Item, bool) {
	if o.Macro != "OBJECT-TYPE" || !accessible(o) || o.SequenceOf != "" {
		return snmp.Item{}, false
	}
	base, _ := c.baseType(o.Syntax, o.Enum)
	kind, ok := numericBase[base]
	if !ok {
		return snmp.Item{}, false
	}
	it := snmp.Item{Metric: prefix + "." + snake(o.Name), Unit: o.Units}
	if base == "TimeTicks" {
		it.Unit, it.Scale = "s", 0.01
	}
	if kind == "counter" {
		it.Kind = "counter"
		it.Metric += ".rate"
		it.Unit = orUnit(o.Units, "{count}") + "/s"
	}
	return it, true
}

func orUnit(u, def string) string {
	if u == "" {
		return def
	}
	return u
}

func (c *Compiler) children(parent string) []*Object {
	var out []*Object
	for _, o := range c.objs {
		if o.Parent == parent && len(o.Sub) == 1 {
			out = append(out, o)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Sub[0] < out[j].Sub[0] })
	return out
}

// Result is what one module compiles to.
type Result struct {
	Manifest snmp.Manifest
	Traps    snmp.TrapProfileFile
	Warnings []string
}

// Compile turns one added module into a manifest (its tables and numeric scalars) and a trap
// profile file (its NOTIFICATION-TYPE and TRAP-TYPE definitions).
func (c *Compiler) Compile(module string) (Result, error) {
	m, ok := c.mods[module]
	if !ok {
		return Result{}, fmt.Errorf("module %s was not added", module)
	}
	prefix := metricPrefix(m.Name)
	r := Result{Manifest: snmp.Manifest{Name: strings.ToLower(m.Name)}, Traps: snmp.TrapProfileFile{Vendor: strings.ToLower(m.Name)}}
	inTable := map[string]bool{}
	for _, o := range m.Objects {
		if o.Macro != "OBJECT-TYPE" || o.SequenceOf == "" {
			continue
		}
		t, err := c.table(o, prefix, inTable)
		if err != nil {
			r.Warnings = append(r.Warnings, err.Error())
			continue
		}
		if len(t.Items) > 0 && len(r.Manifest.Tables) < maxTables {
			r.Manifest.Tables = append(r.Manifest.Tables, t)
		}
	}
	for _, o := range m.Objects {
		if inTable[o.Name] || len(r.Manifest.Scalars) >= maxScalars {
			continue
		}
		it, ok := c.item(o, prefix)
		if !ok {
			continue
		}
		oid, err := c.OID(o.Name)
		if err != nil {
			r.Warnings = append(r.Warnings, err.Error())
			continue
		}
		it.OID = oid + ".0"
		r.Manifest.Scalars = append(r.Manifest.Scalars, it)
	}
	for _, o := range m.Objects {
		if o.Macro != "NOTIFICATION-TYPE" && o.Macro != "TRAP-TYPE" || len(r.Traps.Traps) >= maxTrapsOfMIB {
			continue
		}
		d, err := c.trap(o)
		if err != nil {
			r.Warnings = append(r.Warnings, err.Error())
			continue
		}
		r.Traps.Traps = append(r.Traps.Traps, d)
	}
	return r, nil
}

func (c *Compiler) table(o *Object, prefix string, inTable map[string]bool) (snmp.Table, error) {
	var entry *Object
	for _, ch := range c.children(o.Name) {
		if ch.Macro == "OBJECT-TYPE" {
			entry = ch
			break
		}
	}
	if entry == nil {
		return snmp.Table{}, fmt.Errorf("%s: table has no entry", o.Name)
	}
	oid, err := c.OID(entry.Name)
	if err != nil {
		return snmp.Table{}, err
	}
	inTable[o.Name], inTable[entry.Name] = true, true
	t := snmp.Table{Name: o.Name, OID: oid, Priority: 1}
	for _, col := range c.children(entry.Name) {
		inTable[col.Name] = true
		base, _ := c.baseType(col.Syntax, col.Enum)
		if t.LabelCol == "" && isLabel(col.Name, base) && accessible(col) {
			t.LabelCol, t.LabelAttr = strconv.Itoa(col.Sub[0]), prefix+"."+snake(col.Name)
			continue
		}
		it, ok := c.item(col, prefix)
		if !ok || len(t.Items) >= maxItems {
			continue
		}
		it.Col = strconv.Itoa(col.Sub[0])
		t.Items = append(t.Items, it)
	}
	if t.LabelAttr == "" {
		t.LabelAttr = prefix + ".index"
	}
	return t, nil
}

var (
	errorWords = []string{"fail", "down", "error", "critical", "alarm", "lost", "fault", "overtemp", "shutdown", "backward", "overload"}
	infoWords  = []string{"up", "ok", "clear", "restored", "established", "inserted", "normal", "resolved", "recover"}
)

// trapSeverity guesses from the name: failure words first, then recovery words, else WARN.
func trapSeverity(name string) string {
	l := strings.ToLower(name)
	for _, w := range errorWords {
		if strings.Contains(l, w) {
			return "ERROR"
		}
	}
	for _, w := range infoWords {
		if strings.Contains(l, w) {
			return "INFO"
		}
	}
	return "WARN"
}

func (c *Compiler) trap(o *Object) (snmp.TrapDef, error) {
	oid, err := c.OID(o.Name)
	if err != nil {
		return snmp.TrapDef{}, err
	}
	d := snmp.TrapDef{OID: oid, Name: o.Name, Severity: trapSeverity(o.Name)}
	if r := []rune(o.Description); len(r) > maxDescLen {
		d.Description = string(r[:maxDescLen])
	} else {
		d.Description = o.Description
	}
	for _, n := range o.Objects {
		voids, err := c.OID(n)
		if err != nil {
			continue // a varbind of an unloaded MIB keeps its number
		}
		v := snmp.TrapVarbind{OID: voids, Name: n}
		if vo := c.objs[n]; vo != nil {
			if _, enum := c.baseType(vo.Syntax, vo.Enum); len(enum) > 0 {
				v.Enum = map[string]string{}
				for k, l := range enum {
					v.Enum[strconv.Itoa(k)] = l
				}
			}
		}
		d.Varbinds = append(d.Varbinds, v)
	}
	return d, nil
}
