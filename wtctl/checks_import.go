package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// checksMain is `wtctl checks ...`.
func checksMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) > 0 && args[0] == "run" {
		if code := checksRun(ctx, args[1:], out, os.Stderr); code != exitPass {
			return exitCode(code)
		}
		return nil
	}
	if len(args) > 0 && args[0] == "watch" {
		return checksWatch(ctx, args[1:], out)
	}
	if len(args) != 2 || args[0] != "import-playwright" {
		return errors.New("usage: wtctl checks run|watch|import-playwright ...")
	}
	src, err := os.ReadFile(args[1])
	if err != nil {
		return err
	}
	mons, err := importPlaywright(args[1], string(src))
	if err != nil {
		return err
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if len(mons) == 1 { // one monitor per test(): an object for one, an array for several
		return enc.Encode(mons[0])
	}
	return enc.Encode(mons)
}

type pwMonitor struct {
	Name   string         `json:"name"`
	Kind   string         `json:"kind"`
	Config map[string]any `json:"config"`
}

const (
	jsStr  = "'(?:[^'\\\\]|\\\\.)*'|\"(?:[^\"\\\\]|\\\\.)*\"|`[^`$]*`"
	jsLoc  = `page\.(?:getByRole\(\s*(` + jsStr + `)\s*(?:,\s*\{\s*name:\s*(` + jsStr + `)\s*,?\s*\})?\s*\)|getByText\(\s*(` + jsStr + `)\s*\)|locator\(\s*(` + jsStr + `)\s*\))`
	jsRe   = `/((?:[^/\\\n]|\\.)+)/[a-z]*`
	oneArg = `\(\s*(` + jsStr + `)\s*\)`
)

var (
	reGoto    = regexp.MustCompile(`^page\.goto` + oneArg + `$`)
	reAct     = regexp.MustCompile(`^` + jsLoc + `\.(click|fill|press|selectOption)\(\s*(` + jsStr + `)?\s*\)$`)
	reLegacy  = regexp.MustCompile(`^page\.(click|fill|press|selectOption)\(\s*(` + jsStr + `)\s*(?:,\s*(` + jsStr + `))?\s*\)$`)
	reURL     = regexp.MustCompile(`^expect\(page\)\.toHaveURL\(\s*(?:(` + jsStr + `)|` + jsRe + `)\s*\)$`)
	reExpect  = regexp.MustCompile(`^expect\(` + jsLoc + `\)\.(toContainText|toBeVisible)\(\s*(` + jsStr + `)?\s*\)$`)
	reTitle   = regexp.MustCompile(`^test\(\s*(` + jsStr + `)`)
	reLastCal = regexp.MustCompile(`\.(\w+)\(`)
	reHead    = regexp.MustCompile(`^[A-Za-z_$][\w$.]*`)
)

// opener reports lines that open a block whose body holds steps: test.describe(...) and
// test.step(...) are flattened; test(...) starts a monitor.
func opener(l string) bool {
	return strings.HasPrefix(l, "test.describe(") || strings.HasPrefix(l, "test.step(")
}

// ignorable lines carry no action: block ends and comments.
func ignorable(l string) bool {
	for _, p := range []string{"}", "//", "/*", "*"} {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return false
}

// maxPlaywrightSteps is the step cap of a browser check.
const maxPlaywrightSteps = 50

// importPlaywright translates the Playwright subset into `browser` monitors, one per test()
// block. Everything it cannot translate (other calls, test.use/skip/only/beforeEach..., export
// lines) is an error naming file:line, and all of them are listed; nothing is dropped silently.
func importPlaywright(file, src string) ([]pwMonitor, error) {
	base := strings.TrimSuffix(strings.TrimSuffix(filepath.Base(file), ".ts"), ".spec")
	var (
		mons  []pwMonitor
		cur   *pwMonitor
		steps []map[string]any
		errs  []string
		from  int
	)
	fail := func(line int, format string, a ...any) {
		errs = append(errs, fmt.Sprintf("%s:%d: ", file, line)+fmt.Sprintf(format, a...))
	}
	flush := func() {
		switch {
		case cur == nil:
		case len(steps) == 0:
			fail(from, "test %q has no steps", cur.Name)
		case len(steps) > maxPlaywrightSteps:
			fail(from, "test %q has %d steps; a browser check has at most %d", cur.Name, len(steps), maxPlaywrightSteps)
		default:
			cur.Config = map[string]any{"steps": steps}
			mons = append(mons, *cur)
		}
		cur, steps = nil, nil
	}
	lines := strings.Split(src, "\n")
	for i := 0; i < len(lines); i++ {
		l := strings.TrimSpace(lines[i])
		bare := strings.TrimPrefix(l, "await ")
		if l == "" || ignorable(l) || opener(bare) {
			continue
		}
		if strings.HasPrefix(bare, "test(") {
			flush()
			from = i + 1
			name := fmt.Sprintf("%s-%d", base, len(mons)+1)
			if len(mons) == 0 && cur == nil {
				name = base
			}
			if m := reTitle.FindStringSubmatch(bare); m != nil {
				name = unquoteJS(m[1])
			}
			cur = &pwMonitor{Name: name, Kind: "browser"}
			continue
		}
		start := i + 1
		for depth(l) > 0 && i+1 < len(lines) { // a statement wrapped over several lines
			i++
			l += " " + strings.TrimSpace(lines[i])
		}
		bare = strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(l, "await ")), ";")
		switch {
		case strings.HasPrefix(bare, "import "):
		case strings.HasPrefix(bare, "export "):
			f := strings.Fields(bare)
			fail(start, "unsupported %s", strings.Join(f[:min(2, len(f))], " "))
		case strings.HasPrefix(bare, "test."):
			fail(start, "unsupported %s", reHead.FindString(bare))
		default:
			step, ok := translate(bare)
			switch {
			case !ok:
				fail(start, "unsupported %s", callName(bare))
			case cur == nil:
				fail(start, "a step outside any test()")
			default:
				steps = append(steps, step)
			}
		}
	}
	flush()
	if len(errs) > 0 {
		return nil, errors.New(strings.Join(errs, "\n"))
	}
	if len(mons) == 0 {
		return nil, fmt.Errorf("%s: no test() found", file)
	}
	return mons, nil
}

// depth is the number of parentheses and braces a statement leaves open, ignoring quoted text.
func depth(s string) int {
	n, quote := 0, byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"' || c == '`':
			quote = c
		case c == '(' || c == '{':
			n++
		case c == ')' || c == '}':
			n--
		}
	}
	return n
}

// callName is the call to blame: the first method that is not part of the supported subset, else
// the last method called, else the leading identifier.
func callName(l string) string {
	m := reLastCal.FindAllStringSubmatch(l, -1)
	for _, x := range m {
		if !supported[x[1]] {
			return x[1]
		}
	}
	if len(m) > 0 {
		return m[len(m)-1][1]
	}
	if h := reHead.FindString(l); h != "" {
		return h
	}
	return strings.Fields(l + " ?")[0]
}

var supported = map[string]bool{
	"goto": true, "click": true, "fill": true, "press": true, "selectOption": true, "getByRole": true,
	"getByText": true, "locator": true, "toHaveURL": true, "toContainText": true, "toBeVisible": true,
}

func unquoteJS(s string) string {
	s = s[1 : len(s)-1]
	r := strings.NewReplacer(`\'`, `'`, `\"`, `"`, `\\`, `\`, `\n`, "\n", "\\`", "`")
	return r.Replace(s)
}

// selector renders the locator groups of jsLoc (role, name, text, css) as a step selector.
func selector(role, name, text, css string) string {
	switch {
	case role != "":
		if name != "" {
			return fmt.Sprintf(`role=%s[name=%q]`, unquoteJS(role), unquoteJS(name))
		}
		return "role=" + unquoteJS(role)
	case text != "":
		return "text=" + unquoteJS(text)
	}
	return unquoteJS(css)
}

func translate(l string) (map[string]any, bool) {
	if m := reGoto.FindStringSubmatch(l); m != nil {
		return map[string]any{"action": "goto", "url": unquoteJS(m[1])}, true
	}
	if m := reAct.FindStringSubmatch(l); m != nil {
		return action(m[5], selector(m[1], m[2], m[3], m[4]), m[6])
	}
	if m := reLegacy.FindStringSubmatch(l); m != nil {
		return action(m[1], unquoteJS(m[2]), m[3])
	}
	if m := reURL.FindStringSubmatch(l); m != nil {
		if m[1] != "" {
			return map[string]any{"action": "assert_url", "value": unquoteJS(m[1]), "match": "equals"}, true
		}
		return map[string]any{"action": "assert_url", "value": m[2], "match": "regex"}, true
	}
	if m := reExpect.FindStringSubmatch(l); m != nil {
		sel := selector(m[1], m[2], m[3], m[4])
		if m[5] == "toBeVisible" && m[6] == "" {
			return map[string]any{"action": "assert_visible", "selector": sel}, true
		}
		if m[5] == "toContainText" && m[6] != "" {
			return map[string]any{"action": "assert_text", "selector": sel, "text": unquoteJS(m[6])}, true
		}
	}
	return nil, false
}

// action builds click, fill, press or selectOption; arg is the quoted argument, if any.
func action(verb, sel, arg string) (map[string]any, bool) {
	switch {
	case verb == "click" && arg == "":
		return map[string]any{"action": "click", "selector": sel}, true
	case verb == "fill" && arg != "":
		return map[string]any{"action": "fill", "selector": sel, "value": unquoteJS(arg)}, true
	case verb == "press" && arg != "":
		return map[string]any{"action": "press", "selector": sel, "key": unquoteJS(arg)}, true
	case verb == "selectOption" && arg != "":
		return map[string]any{"action": "select", "selector": sel, "value": unquoteJS(arg)}, true
	}
	return nil, false
}
