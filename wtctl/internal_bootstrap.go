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
	"path/filepath"
	"sort"
	"strings"

	"github.com/watchtowerobservability/watchtower-cli/internal/ascode"
)

const internalUsage = "usage: wtctl internal bootstrap --api <url> --key <key> [--dashboards infra/dashboards/internal] [--alerts infra/alerts/internal] [--secret-out file] [--dry-run]"

// internalServices get one ingestion credential each in the internal project.
var internalServices = []string{"api", "worker", "edge", "alerts", "janitor", "gateway", "notifier", "uptime", "archiver", "fleet"}

type internalOpts struct {
	api, key, dashboards, alerts, secretOut string
	dryRun                                  bool
}

func internalMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) < 1 || args[0] != "bootstrap" {
		return errors.New(internalUsage)
	}
	var o internalOpts
	fs := flag.NewFlagSet("internal bootstrap", flag.ContinueOnError)
	fs.StringVar(&o.api, "api", os.Getenv("WT_API"), "API base URL")
	fs.StringVar(&o.key, "key", os.Getenv("WT_API_KEY"), "API key")
	fs.StringVar(&o.dashboards, "dashboards", "infra/dashboards/internal", "dashboard JSON directory")
	fs.StringVar(&o.alerts, "alerts", "infra/alerts/internal", "alert rule manifest directory")
	fs.StringVar(&o.secretOut, "secret-out", "", "write new credential tokens to this Kubernetes Secret manifest (mode 0600)")
	fs.BoolVar(&o.dryRun, "dry-run", false, "plan the dashboards and rules, write nothing")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if o.api == "" || o.key == "" {
		return errors.New("--api and --key are required")
	}
	return internalBootstrap(ctx, o, out)
}

type page struct {
	Data []map[string]any `json:"data"`
	Next *string          `json:"next_cursor"`
}

// listAll follows cursors.
func listAll(ctx context.Context, o internalOpts, path string) ([]map[string]any, error) {
	var all []map[string]any
	cursor := ""
	for {
		u := o.api + path + "?limit=200"
		if cursor != "" {
			u += "&cursor=" + url.QueryEscape(cursor)
		}
		var p page
		if err := call(ctx, http.MethodGet, u, o.key, nil, &p); err != nil {
			return nil, err
		}
		all = append(all, p.Data...)
		if p.Next == nil || *p.Next == "" {
			return all, nil
		}
		cursor = *p.Next
	}
}

func findBy(items []map[string]any, field, want string) string {
	for _, it := range items {
		if s, _ := it[field].(string); s == want {
			id, _ := it["id"].(string)
			return id
		}
	}
	return ""
}

// ensure creates the resource unless one with the same field value exists; returns its id and
// the create response when it was created (nil when it already existed).
func ensure(ctx context.Context, o internalOpts, listPath, createPath, field, want string, body map[string]any) (id string, made map[string]any, err error) {
	items, err := listAll(ctx, o, listPath)
	if err != nil {
		return "", nil, err
	}
	if id := findBy(items, field, want); id != "" {
		return id, nil, nil
	}
	if err := call(ctx, http.MethodPost, o.api+createPath, o.key, body, &made); err != nil {
		return "", nil, err
	}
	id, _ = made["id"].(string)
	return id, made, nil
}

func internalBootstrap(ctx context.Context, o internalOpts, out io.Writer) error {
	o.api = strings.TrimRight(o.api, "/")
	org, _, err := ensure(ctx, o, "/v1/orgs", "/v1/orgs", "slug", "watchtower-system",
		map[string]any{"slug": "watchtower-system", "name": "Watchtower system"})
	if err != nil {
		return fmt.Errorf("org: %w", err)
	}
	prj, _, err := ensure(ctx, o, "/v1/orgs/"+org+"/projects", "/v1/orgs/"+org+"/projects", "slug", "internal",
		map[string]any{"slug": "internal", "name": "Internal"})
	if err != nil {
		return fmt.Errorf("project: %w", err)
	}
	envs, err := listAll(ctx, o, "/v1/projects/"+prj+"/environments")
	if err != nil || len(envs) == 0 {
		return fmt.Errorf("environment: %v", err)
	}
	env, _ := envs[0]["id"].(string)
	tokens := map[string]string{}
	for _, svc := range internalServices {
		name := "wt-" + svc
		_, made, err := ensure(ctx, o, "/v1/projects/"+prj+"/credentials", "/v1/projects/"+prj+"/credentials", "name", name,
			map[string]any{"name": name, "env_id": env, "scopes": []string{"ingest:traces", "ingest:logs", "ingest:metrics"}})
		if err != nil {
			return fmt.Errorf("credential %s: %w", name, err)
		}
		if made != nil {
			fmt.Fprintf(out, "credential %s created\n", name)
			tokens[name], _ = made["token"].(string)
		}
	}
	if err := writeSecret(o.secretOut, tokens); err != nil {
		return err
	}
	docs, err := internalDocs(o)
	if err != nil {
		return err
	}
	c, err := ascode.New(o.api, o.key, prj, guardedClient(0))
	if err != nil {
		return err
	}
	plan, err := c.Plan(ctx, docs, false)
	if err != nil {
		return err
	}
	done, err := c.Apply(ctx, plan, o.dryRun, io.Discard)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "project %s: %d change(s)\n", prj, ascode.Count(done))
	return nil
}

// internalDocs turns the dashboard JSON files into Dashboard manifests and loads the alert rule
// manifests.
func internalDocs(o internalOpts) ([]ascode.Doc, error) {
	files, err := filepath.Glob(filepath.Join(o.dashboards, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	var docs []ascode.Doc
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var spec map[string]any
		if err := json.Unmarshal(b, &spec); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		title := "Internal / " + strings.TrimSuffix(filepath.Base(f), ".json")
		docs = append(docs, ascode.Doc{
			APIVersion: "watchtower.dev/v1", Kind: "Dashboard", Metadata: ascode.Metadata{Name: title},
			Spec: map[string]any{"description": "Shipped internal dashboard", "spec": spec},
		})
	}
	if o.alerts != "" {
		rules, err := ascode.LoadDocs(o.alerts)
		if err != nil {
			return nil, err
		}
		docs = append(docs, rules...)
	}
	return docs, nil
}

// writeSecret writes the once-shown tokens as a Kubernetes Secret manifest; nothing when no
// token is new or no path is given (tokens are never printed).
func writeSecret(path string, tokens map[string]string) error {
	if path == "" || len(tokens) == 0 {
		return nil
	}
	names := make([]string, 0, len(tokens))
	for n := range tokens {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("apiVersion: v1\nkind: Secret\nmetadata:\n  name: watchtower-self-keys\ntype: Opaque\nstringData:\n")
	for _, n := range names {
		fmt.Fprintf(&b, "  %s: %q\n", n, tokens[n])
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}
