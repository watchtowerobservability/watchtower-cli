package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
)

const activityConfigUsage = `usage: wtctl activity config plan  --file activity.json --project <prj> --api <url> --key <key> [--detailed-exitcode] [--json] [--lenient]
       wtctl activity config apply --file activity.json --project <prj> --api <url> --key <key> [--json] [--no-validate]
       wtctl activity config get   --project <prj> --api <url> --key <key>

(-f is --file; the npm package installs this binary as both "wtctl" and "wt".)
plan prints one line per change, by section (schema, theme, policy, retention, account_group,
activity_rule, hook) and name, with the changed fields. With --detailed-exitcode (alias
--exit-code, as "wtctl plan") it exits 0 when the stored config equals the document and 2 on
drift; without it, drift exits 0 too. Either way an error exits 1, and so does a sample that
fails validation unless --lenient. CI must pass --detailed-exitcode to gate on drift.
--json prints exactly the server's plan document (what config.plan() returns in the SDK).
apply writes the document (it first validates the document's "samples" the way plan does,
unless --no-validate). Webhook secrets in the document ("secret": "${ENV_NAME}", "secrets":
["${NEW}", "${OLD}"]) are read from the environment here and sent as values; secret_ref names
are kept as names; a plan never prints a value. The key needs scope config:activity (or
schema:, theme: and rules:activity together) on the project, or the org apiKey.`

// configResult is the answer of PUT .../activity/config.
type configResult struct {
	Mode    string `json:"mode"`
	Applied bool   `json:"applied"`
	Changed bool   `json:"changed"`
	Changes []struct {
		Kind        string   `json:"kind"`
		Name        string   `json:"name"`
		Op          string   `json:"op"`
		Fields      []string `json:"fields"`
		ChangedKeys []string `json:"changed_keys"`
		KeyChanges  []struct {
			Key      string          `json:"key"`
			Previous json.RawMessage `json:"previous"`
			Next     json.RawMessage `json:"next"`
		} `json:"key_changes"`
	} `json:"changes"`
	Warnings []struct {
		Code    string `json:"code"`
		Path    string `json:"path"`
		Message string `json:"message"`
	} `json:"warnings"`
	Validation []struct {
		Action string `json:"action"`
		Result struct {
			OK              bool     `json:"ok"`
			Problem         string   `json:"problem"`
			Warnings        []string `json:"warnings"`
			MissingTemplate bool     `json:"missing_template"`
		} `json:"result"`
	} `json:"validation"`
	IssuedSecrets []struct {
		Kind          string `json:"kind"`
		Name          string `json:"name"`
		SigningSecret string `json:"signing_secret"`
	} `json:"issued_secrets"`
}

// kindRank is the order a plan lists what it changes: the order of the document's sections.
var kindRank = map[string]int{"schema": 0, "theme": 1, "policy": 2, "retention": 3, "account_group": 4, "activity_rule": 5, "hook": 6}

// sortStable puts the answer in one fixed order (changes by section then name, warnings by path,
// validation by action), so the same plan prints the same bytes on every run and a CI diff of two
// plans only shows real differences. It does not depend on the order the server answered in.
func (r *configResult) sortStable() {
	sort.SliceStable(r.Changes, func(i, j int) bool {
		a, b := r.Changes[i], r.Changes[j]
		if ra, rb := kindRank[a.Kind], kindRank[b.Kind]; ra != rb {
			return ra < rb
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Op < b.Op
	})
	for i := range r.Changes {
		sort.Strings(r.Changes[i].Fields)
		sort.Strings(r.Changes[i].ChangedKeys)
		kc := r.Changes[i].KeyChanges
		sort.SliceStable(kc, func(a, b int) bool { return kc[a].Key < kc[b].Key })
	}
	sort.SliceStable(r.Warnings, func(i, j int) bool {
		a, b := r.Warnings[i], r.Warnings[j]
		return a.Path < b.Path || a.Path == b.Path && a.Message < b.Message
	})
	sort.SliceStable(r.Validation, func(i, j int) bool { return r.Validation[i].Action < r.Validation[j].Action })
	for i := range r.Validation {
		sort.Strings(r.Validation[i].Result.Warnings)
	}
}

var envPlaceholder = regexp.MustCompile(`^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$`)

// resolveSecrets replaces every "${NAME}" secret of the document (rule channels and hooks:
// secret, secrets[]) with that environment variable. An unset or empty variable is an error
// that names the variable, never a value.
func resolveSecrets(doc map[string]any, env func(string) string) error {
	one := func(where string, v any) (any, error) {
		s, ok := v.(string)
		if !ok {
			return v, nil
		}
		m := envPlaceholder.FindStringSubmatch(s)
		if m == nil {
			return v, nil
		}
		val := env(m[1])
		if val == "" {
			return nil, fmt.Errorf("%s: environment variable %s is not set", where, m[1])
		}
		return val, nil
	}
	holder := func(where string, h map[string]any) error {
		if v, ok := h["secret"]; ok {
			r, err := one(where+".secret", v)
			if err != nil {
				return err
			}
			h["secret"] = r
		}
		if list, ok := h["secrets"].([]any); ok {
			for i, v := range list {
				r, err := one(fmt.Sprintf("%s.secrets[%d]", where, i), v)
				if err != nil {
					return err
				}
				list[i] = r
			}
		}
		return nil
	}
	if rules, ok := doc["activity_rules"].(map[string]any); ok {
		for name, r := range rules {
			rule, _ := r.(map[string]any)
			if ch, ok := rule["channel"].(map[string]any); ok {
				if err := holder("activity_rules."+name+".channel", ch); err != nil {
					return err
				}
			}
		}
	}
	if hooks, ok := doc["hooks"].(map[string]any); ok {
		for kind, h := range hooks {
			if hook, ok := h.(map[string]any); ok {
				if err := holder("hooks."+kind, hook); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func readConfigDoc(file string) (map[string]any, error) {
	var b []byte
	var err error
	if file == "-" {
		b, err = io.ReadAll(io.LimitReader(os.Stdin, 16<<20))
	} else {
		b, err = os.ReadFile(file)
	}
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return doc, nil
}

// showJSON renders a plan value: a missing or null one is "absent".
func showJSON(v json.RawMessage) string {
	if len(v) == 0 || string(v) == "null" {
		return "absent"
	}
	return string(v)
}

// printConfig writes the plan or apply result and returns how many validation problems it holds
// (a sample that would be refused, a schema warning, a missing display template).
func printConfig(out io.Writer, r configResult) (problems int) {
	sign := map[string]string{"create": "+", "update": "~", "delete": "-"}
	r.sortStable()
	for _, c := range r.Changes {
		f := ""
		if len(c.Fields) > 0 {
			f = " (" + strings.Join(c.Fields, ", ") + ")"
		}
		fmt.Fprintf(out, "%s %s %s%s\n", sign[c.Op], c.Kind, c.Name, f)
		detailed := map[string]bool{}
		for _, k := range c.KeyChanges {
			detailed[k.Key] = true
			fmt.Fprintf(out, "    %-6s %s: %s \u2192 %s\n", c.Kind, k.Key, showJSON(k.Previous), showJSON(k.Next))
		}
		for _, k := range c.ChangedKeys {
			if !detailed[k] {
				fmt.Fprintf(out, "    %-6s %s: changed\n", c.Kind, k)
			}
		}
	}
	for _, w := range r.Warnings {
		code := ""
		if w.Code != "" {
			code = " [" + w.Code + "]"
		}
		fmt.Fprintf(out, "warning%s: %s: %s\n", code, w.Path, w.Message)
	}
	for _, v := range r.Validation {
		switch {
		case !v.Result.OK:
			problems++
			fmt.Fprintf(out, "invalid sample %s: %s\n", v.Action, v.Result.Problem)
		default:
			for _, w := range v.Result.Warnings {
				problems++
				fmt.Fprintf(out, "sample %s: %s\n", v.Action, w)
			}
			if v.Result.MissingTemplate {
				problems++
				fmt.Fprintf(out, "sample %s: no display template for the action\n", v.Action)
			}
		}
	}
	if !r.Changed {
		fmt.Fprintln(out, "no changes")
	}
	return problems
}

func activityConfigMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || (args[0] != "plan" && args[0] != "apply" && args[0] != "get") {
		return errors.New(activityConfigUsage)
	}
	verb := args[0]
	var o activityOpts
	fs := flag.NewFlagSet("activity config "+verb, flag.ContinueOnError)
	o.bind(fs)
	file := fs.String("f", "", "config document (JSON); - reads stdin")
	fs.StringVar(file, "file", "", "alias of -f")
	detailed := fs.Bool("detailed-exitcode", false, "plan: exit 2 when the plan has changes")
	exitAlias := fs.Bool("exit-code", false, "alias of --detailed-exitcode")
	asJSON := fs.Bool("json", false, "plan, apply: print the server's answer as JSON")
	lenient := fs.Bool("lenient", false, "plan: do not fail on sample warnings or missing templates")
	noValidate := fs.Bool("no-validate", false, "apply: do not validate the document's samples first")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if err := o.check(); err != nil {
		return err
	}
	u := o.base() + "/config"
	if verb == "get" {
		var v any
		if err := call(ctx, http.MethodGet, u, o.key, nil, &v); err != nil {
			return err
		}
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "%s\n", b)
		return err
	}
	if *file == "" {
		return errors.New("--file <activity.json> is required")
	}
	doc, err := readConfigDoc(*file)
	if err != nil {
		return err
	}
	if err := resolveSecrets(doc, os.Getenv); err != nil {
		return err
	}
	return runConfig(ctx, verb, u, o.key, doc, configFlags{lenient: *lenient, noValidate: *noValidate, detailed: *detailed || *exitAlias, asJSON: *asJSON}, out)
}

type configFlags struct{ lenient, noValidate, detailed, asJSON bool }

// emit prints the server's answer: the document itself with --json, else the sorted text.
func emit(out io.Writer, raw json.RawMessage, r configResult, f configFlags) int {
	if !f.asJSON {
		return printConfig(out, r)
	}
	var b bytes.Buffer
	if json.Indent(&b, raw, "", "  ") != nil {
		b.Reset()
		b.Write(raw)
	}
	fmt.Fprintf(out, "%s\n", b.Bytes())
	return printConfigProblems(io.Discard, r)
}

// runConfig plans or applies doc at the config URL u. Exit codes (as `wtctl plan`): plan 0
// equal, 1 error or a failed sample, 2 drift only with --detailed-exitcode (else 0); apply 0
// written, 1 error or a failed sample.
func runConfig(ctx context.Context, verb, u, key string, doc map[string]any, f configFlags, out io.Writer) error {
	_, hasSamples := doc["samples"]
	plan := func(validate bool) (json.RawMessage, configResult, error) {
		q := u + "?mode=plan"
		if validate && hasSamples {
			q += "&validate=samples"
		}
		var raw json.RawMessage
		var r configResult
		if err := call(ctx, http.MethodPut, q, key, doc, &raw); err != nil {
			return nil, r, err
		}
		return raw, r, json.Unmarshal(raw, &r)
	}
	if verb == "plan" {
		raw, r, err := plan(true)
		if err != nil {
			return err
		}
		problems := emit(out, raw, r, f)
		if problems > 0 && !f.lenient {
			return fmt.Errorf("%d validation problem(s) in the samples", problems)
		}
		if r.Changed && f.detailed {
			return exitCode(2)
		}
		return nil
	}
	if hasSamples && !f.noValidate {
		_, r, err := plan(true)
		if err != nil {
			return err
		}
		if n := printConfigProblems(out, r); n > 0 {
			return fmt.Errorf("%d validation problem(s) in the samples; nothing was applied", n)
		}
	}
	var raw json.RawMessage
	var r configResult
	if err := call(ctx, http.MethodPut, u, key, doc, &raw); err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return err
	}
	emit(out, raw, r, f)
	if f.asJSON {
		return nil // the signing secrets are in the document itself
	}
	for _, s := range r.IssuedSecrets {
		fmt.Fprintf(out, "signing secret of %s %s (shown once; store it, then reference it as ${ENV}): %s\n", s.Kind, s.Name, s.SigningSecret)
	}
	return nil
}

// printConfigProblems prints only the validation findings of a pre-apply check.
func printConfigProblems(out io.Writer, r configResult) int {
	r.Changes, r.Warnings, r.Changed = nil, nil, true // no change lines, no "no changes"
	return printConfig(out, r)
}
