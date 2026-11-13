package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// One project per environment (staging, production): copy-config moves the activity setup from
// one to the other. It copies the newest version of every action schema, the redaction rules,
// the theme draft (not published: review it and publish in the target) and the alert rules with
// an email channel (a rule whose name the target already has is skipped, so a rerun adds no
// duplicates). Slack and webhook rules are listed and skipped, because their URLs are
// secrets the API never returns; recreate them in the target. Streams are not copied for the
// same reason (write-only credentials).
type copyOpts struct {
	api, key, from, to string
	dryRun             bool
}

func activityCopyMain(ctx context.Context, args []string, out io.Writer) error {
	var o copyOpts
	fs := flag.NewFlagSet("activity copy-config", flag.ContinueOnError)
	fs.StringVar(&o.api, "api", apiEnv(), "API base URL; default $WT_API_URL")
	fs.StringVar(&o.key, "key", os.Getenv("WT_API_KEY"), "org API key with access to both projects; default $WT_API_KEY")
	fs.StringVar(&o.from, "from", "", "source project id")
	fs.StringVar(&o.to, "to", "", "target project id")
	fs.BoolVar(&o.dryRun, "dry-run", false, "print what would be copied")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if o.api == "" || o.key == "" || o.from == "" || o.to == "" {
		return errors.New("--api, --key, --from and --to are required")
	}
	if o.from == o.to {
		return errors.New("--from and --to must differ")
	}
	return copyConfig(ctx, o, out)
}

func (o copyOpts) base(prj string) string {
	return strings.TrimRight(o.api, "/") + "/v1/projects/" + url.PathEscape(prj) + "/activity"
}

// put sends the write unless this is a dry run.
func (o copyOpts) put(ctx context.Context, method, u string, body any, out io.Writer, what string) error {
	fmt.Fprintf(out, "%s %s\n", map[bool]string{true: "would copy", false: "copy"}[o.dryRun], what)
	if o.dryRun {
		return nil
	}
	return call(ctx, method, u, o.key, body, nil)
}

// pages follows next_cursor of a `{data, next_cursor}` list.
func pages[T any](ctx context.Context, key, u string) ([]T, error) {
	var all []T
	cursor := ""
	for {
		var p struct {
			Data       []T     `json:"data"`
			NextCursor *string `json:"next_cursor"`
		}
		q := u + "?limit=100"
		if cursor != "" {
			q += "&cursor=" + url.QueryEscape(cursor)
		}
		if err := call(ctx, http.MethodGet, q, key, nil, &p); err != nil {
			return nil, err
		}
		all = append(all, p.Data...)
		if p.NextCursor == nil || *p.NextCursor == "" {
			return all, nil
		}
		cursor = *p.NextCursor
	}
}

func copyConfig(ctx context.Context, o copyOpts, out io.Writer) error {
	src, dst := o.base(o.from), o.base(o.to)
	type schema struct {
		Action         string   `json:"action"`
		TargetTypes    []string `json:"target_types"`
		MetadataSchema any      `json:"metadata_schema"`
		Mode           string   `json:"mode"`
		Description    *string  `json:"description,omitempty"`
	}
	schemas, err := pages[schema](ctx, o.key, src+"/schemas")
	if err != nil {
		return err
	}
	for _, s := range schemas {
		body := map[string]any{"metadata_schema": s.MetadataSchema, "target_types": s.TargetTypes, "mode": s.Mode, "description": s.Description}
		if err := o.put(ctx, http.MethodPut, dst+"/schemas/"+url.PathEscape(s.Action), body, out, "schema "+s.Action); err != nil {
			return err
		}
	}
	var red struct {
		Rules []any `json:"rules"`
	}
	if err := call(ctx, http.MethodGet, src+"/redaction", o.key, nil, &red); err != nil {
		return err
	}
	if red.Rules == nil {
		red.Rules = []any{}
	}
	if err := o.put(ctx, http.MethodPut, dst+"/redaction", map[string]any{"rules": red.Rules}, out, fmt.Sprintf("redaction (%d rules)", len(red.Rules))); err != nil {
		return err
	}
	var theme struct {
		Theme map[string]any `json:"theme"`
		Draft map[string]any `json:"draft"`
	}
	if err := call(ctx, http.MethodGet, src+"/theme", o.key, nil, &theme); err != nil {
		return err
	}
	draft := theme.Draft
	if len(draft) == 0 {
		draft = theme.Theme
	}
	if len(draft) > 0 {
		if err := o.put(ctx, http.MethodPut, dst+"/theme", map[string]any{"draft": draft}, out, "theme draft (publish it in the target)"); err != nil {
			return err
		}
	}
	return copyRules(ctx, o, src, dst, out)
}

func copyRules(ctx context.Context, o copyOpts, src, dst string, out io.Writer) error {
	type rule struct {
		Name      string         `json:"name"`
		AccountID *string        `json:"account_id"`
		Match     any            `json:"match"`
		Channel   map[string]any `json:"channel"`
	}
	rules, err := pages[rule](ctx, o.key, src+"/rules")
	if err != nil {
		return err
	}
	have, err := pages[rule](ctx, o.key, dst+"/rules")
	if err != nil {
		return err
	}
	exists := map[string]bool{}
	for _, r := range have {
		exists[r.Name] = true
	}
	for _, r := range rules {
		if exists[r.Name] {
			fmt.Fprintf(out, "skip rule %q: the target has a rule of that name\n", r.Name)
			continue
		}
		if r.Channel["kind"] != "email" {
			fmt.Fprintf(out, "skip rule %q: its %v URL is a secret; recreate it in the target\n", r.Name, r.Channel["kind"])
			continue
		}
		body := map[string]any{"name": r.Name, "match": r.Match, "channel": map[string]any{"kind": "email", "to": r.Channel["to"]}}
		if r.AccountID != nil {
			body["account_id"] = *r.AccountID
		}
		if err := o.put(ctx, http.MethodPost, dst+"/rules", body, out, "rule "+r.Name); err != nil {
			return err
		}
	}
	return nil
}
