package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

const activityUsage = `usage: wtctl activity tail --project <prj> --api <url> --key <key> [--interval 2s]
       wtctl activity verify <export.ndjson[.gz]> [--project prj_...] [--checkpoint verify.json --keys <url|file>]
       wtctl activity import --from workos-csv|retraced-ndjson|mapping.yaml <file> --project <prj> --key <wti_...> --api <url> [--dry-run]
       wtctl activity types --project <prj> --lang ts|go|py --api <url> --key <key>
       wtctl activity copy-config --from <prj> --to <prj> --api <url> --key <org API key> [--dry-run]
       wtctl activity templates [--import soc2|iso27001|hipaa|pci|ai_act --project <prj> --api <url> --key <key>]
       wtctl activity get <event id> --project <prj> --api <url> --key <key>
       wtctl activity batch <batch id> --api <url> --key <wti_...>` + "\n" + activityMonitorUsage + "\n" + activityWitnessUsage

// activityMain dispatches `wtctl activity ...` (B-5, B-6, B-8, B-9).
func activityMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(activityUsage)
	}
	switch args[0] {
	case "tail":
		return activityTailMain(ctx, args[1:], out)
	case "verify":
		return activityVerifyMain(ctx, args[1:], out)
	case "import":
		return activityImportMain(ctx, args[1:], out)
	case "types":
		return activityTypesMain(ctx, args[1:], out)
	case "copy-config":
		return activityCopyMain(ctx, args[1:], out)
	case "templates":
		return activityTemplatesMain(ctx, args[1:], out)
	case "get", "batch":
		return activityGetMain(ctx, args[0], args[1:], out)
	case "monitor":
		return activityMonitorMain(ctx, args[1:], out)
	case "witness":
		return activityWitnessMain(ctx, args[1:], out)
	}
	return errors.New(activityUsage)
}

type activityOpts struct{ api, key, project string }

func (o *activityOpts) bind(fs *flag.FlagSet) {
	fs.StringVar(&o.api, "api", os.Getenv("WT_API_URL"), "API base URL; default $WT_API_URL")
	fs.StringVar(&o.key, "key", os.Getenv("WT_API_KEY"), "API key; default $WT_API_KEY")
	fs.StringVar(&o.project, "project", "", "project id")
}

func (o *activityOpts) check() error {
	if o.api == "" || o.key == "" || o.project == "" {
		return errors.New("--api, --key and --project are required")
	}
	return nil
}

func (o *activityOpts) base() string {
	return strings.TrimRight(o.api, "/") + "/v1/projects/" + url.PathEscape(o.project) + "/activity"
}

type tailEvent struct {
	ID         string         `json:"id"`
	AccountID  string         `json:"account_id"`
	Action     string         `json:"action"`
	OccurredAt string         `json:"occurred_at"`
	Actor      map[string]any `json:"actor"`
	Target     map[string]any `json:"target"`
	Outcome    string         `json:"outcome"`
	Warnings   []any          `json:"warnings"`
}

// activityTailMain polls the dashboard list (newest first) and prints events not seen before,
// oldest first, with any validation warnings the API attaches.
func activityTailMain(ctx context.Context, args []string, out io.Writer) error {
	var o activityOpts
	fs := flag.NewFlagSet("activity tail", flag.ContinueOnError)
	o.bind(fs)
	interval := fs.Duration("interval", 2*time.Second, "poll interval")
	backfill := fs.Bool("backfill", false, "also print the events already present")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := o.check(); err != nil {
		return err
	}
	fetch := func() ([]tailEvent, error) {
		var page struct {
			Data []tailEvent `json:"data"`
		}
		err := call(ctx, http.MethodGet, o.base()+"/events?limit=100", o.key, nil, &page)
		return page.Data, err
	}
	return tailLoop(ctx, fetch, *interval, *backfill, 0, out)
}

// activityGetMain prints one event (`GET .../activity/events/{id}`) or the state of an async
// ingest batch (`GET /v1/activity/batches/{id}`) as indented JSON.
func activityGetMain(ctx context.Context, what string, args []string, out io.Writer) error {
	var o activityOpts
	fs := flag.NewFlagSet("activity "+what, flag.ContinueOnError)
	o.bind(fs)
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errors.New(activityUsage)
	}
	id := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	u := strings.TrimRight(o.api, "/") + "/v1/activity/batches/" + url.PathEscape(id)
	if what == "get" {
		if err := o.check(); err != nil {
			return err
		}
		u = o.base() + "/events/" + url.PathEscape(id)
	} else if o.api == "" || o.key == "" {
		return errors.New("--api and --key are required")
	}
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

// tailLoop runs maxPolls polls (0 = until ctx ends).
func tailLoop(ctx context.Context, fetch func() ([]tailEvent, error), every time.Duration, backfill bool, maxPolls int, out io.Writer) error {
	seen := map[string]bool{}
	for n := 0; maxPolls == 0 || n < maxPolls; n++ {
		evs, err := fetch()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			fmt.Fprintln(os.Stderr, "tail:", err) // transient: keep polling
		}
		for i := len(evs) - 1; i >= 0; i-- {
			e := evs[i]
			if seen[e.ID] {
				continue
			}
			seen[e.ID] = true
			if n == 0 && !backfill {
				continue
			}
			fmt.Fprintf(out, "%s  %-12s %-28s actor=%v target=%v %s\n", e.OccurredAt, e.AccountID, e.Action, e.Actor["id"], e.Target["id"], e.Outcome)
			for _, w := range e.Warnings {
				fmt.Fprintf(out, "    warning: %v\n", w)
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(every):
		}
	}
	return nil
}

type schemaDef struct {
	Action         string         `json:"action"`
	Version        int            `json:"version"`
	Description    string         `json:"description"`
	MetadataSchema map[string]any `json:"metadata_schema"`
}

// activityTypesMain prints typed per-action metadata definitions from the project's schemas.
func activityTypesMain(ctx context.Context, args []string, out io.Writer) error {
	var o activityOpts
	fs := flag.NewFlagSet("activity types", flag.ContinueOnError)
	o.bind(fs)
	lang := fs.String("lang", "ts", "ts, go or py")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := o.check(); err != nil {
		return err
	}
	if *lang != "ts" && *lang != "go" && *lang != "py" {
		return errors.New("--lang must be ts, go or py")
	}
	defs, err := pages[schemaDef](ctx, o.key, o.base()+"/schemas")
	if err != nil {
		return err
	}
	sort.Slice(defs, func(i, j int) bool { return defs[i].Action < defs[j].Action })
	_, err = io.WriteString(out, renderTypes(defs, *lang))
	return err
}

func pascal(s string) string {
	var b strings.Builder
	up := true
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9':
			if up && r >= 'a' && r <= 'z' {
				r -= 32
			}
			b.WriteRune(r)
			up = false
		default:
			up = true
		}
	}
	return b.String()
}

// propType maps a JSON Schema property to a type in lang.
func propType(p map[string]any, lang string) string {
	if en, ok := p["enum"].([]any); ok && len(en) > 0 && lang != "go" {
		parts := make([]string, len(en))
		for i, v := range en {
			parts[i] = fmt.Sprintf("%q", fmt.Sprint(v))
			if _, isStr := v.(string); !isStr && lang == "ts" {
				parts[i] = fmt.Sprint(v)
			}
		}
		if lang == "py" {
			return "Literal[" + strings.Join(parts, ", ") + "]"
		}
		return strings.Join(parts, " | ")
	}
	t, _ := p["type"].(string)
	m := map[string][3]string{ // ts, go, py
		"string": {"string", "string", "str"}, "integer": {"number", "int64", "int"}, "number": {"number", "float64", "float"},
		"boolean": {"boolean", "bool", "bool"}, "object": {"Record<string, unknown>", "map[string]any", "dict[str, Any]"},
		"array": {"unknown[]", "[]any", "list[Any]"},
	}
	idx := map[string]int{"ts": 0, "go": 1, "py": 2}[lang]
	if v, ok := m[t]; ok {
		return v[idx]
	}
	return [3]string{"unknown", "any", "Any"}[idx]
}

func renderTypes(defs []schemaDef, lang string) string {
	var b strings.Builder
	switch lang {
	case "ts":
		b.WriteString("// Generated by `wtctl activity types`; do not edit.\n")
	case "go":
		b.WriteString("// Code generated by `wtctl activity types`; DO NOT EDIT.\npackage activity\n")
	case "py":
		b.WriteString("# Generated by `wtctl activity types`; do not edit.\nfrom typing import Any, Literal, NotRequired, TypedDict\n")
	}
	for _, d := range defs {
		name := pascal(d.Action) + "Metadata"
		props, _ := d.MetadataSchema["properties"].(map[string]any)
		req := map[string]bool{}
		if r, ok := d.MetadataSchema["required"].([]any); ok {
			for _, x := range r {
				req[fmt.Sprint(x)] = true
			}
		}
		names := make([]string, 0, len(props))
		for k := range props {
			names = append(names, k)
		}
		sort.Strings(names)
		doc := d.Description
		if doc == "" {
			doc = "Metadata of " + d.Action
		}
		cm := map[string]string{"ts": "//", "go": "//", "py": "#"}[lang]
		fmt.Fprintf(&b, "\n%s %s (action %q, schema v%d)\n", cm, strings.ReplaceAll(doc, "\n", " "), d.Action, d.Version)
		switch lang {
		case "ts":
			fmt.Fprintf(&b, "export interface %s {\n", name)
			for _, k := range names {
				opt := "?"
				if req[k] {
					opt = ""
				}
				fmt.Fprintf(&b, "  %q%s: %s;\n", k, opt, propType(pm(props[k]), lang))
			}
			b.WriteString("}\n")
		case "go":
			fmt.Fprintf(&b, "type %s struct {\n", name)
			for _, k := range names {
				tag, ty := k, propType(pm(props[k]), lang)
				if !req[k] {
					tag, ty = k+",omitempty", "*"+ty
				}
				fmt.Fprintf(&b, "\t%s %s `json:%q`\n", pascal(k), ty, tag)
			}
			b.WriteString("}\n")
		case "py":
			fmt.Fprintf(&b, "class %s(TypedDict):\n", name)
			for _, k := range names {
				ty := propType(pm(props[k]), lang)
				if !req[k] {
					ty = "NotRequired[" + ty + "]"
				}
				fmt.Fprintf(&b, "    %s: %s\n", k, ty)
			}
			if len(names) == 0 {
				b.WriteString("    pass\n")
			}
		}
	}
	if lang == "ts" {
		b.WriteString("\nexport interface ActionMetadata {\n")
		for _, d := range defs {
			fmt.Fprintf(&b, "  %q: %sMetadata;\n", d.Action, pascal(d.Action))
		}
		b.WriteString("}\n")
	}
	return b.String()
}

func pm(v any) map[string]any { m, _ := v.(map[string]any); return m }
