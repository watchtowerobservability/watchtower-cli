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
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/watchtowerobservability/watchtower-cli/internal/ascode"
)

// detectStack names what a project directory uses, from its manifests (cheap string checks).
func detectStack(dir string) []string {
	read := func(name string) string { b, _ := os.ReadFile(filepath.Join(dir, name)); return string(b) }
	var found []string
	if pkg := read("package.json"); pkg != "" {
		for _, d := range []string{"next", "@nestjs/core", "express", "bullmq", "pg", "postgres", "ioredis"} {
			if strings.Contains(pkg, `"`+d+`"`) {
				found = append(found, d)
			}
		}
		found = append(found, "node")
	}
	if read("go.mod") != "" {
		found = append(found, "go")
	}
	if read("requirements.txt") != "" || read("pyproject.toml") != "" {
		found = append(found, "python")
	}
	for _, f := range []string{"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"} {
		if c := read(f); c != "" {
			found = append(found, "docker-compose")
			for _, img := range []string{"postgres", "redis", "kafka", "clickhouse"} {
				if regexp.MustCompile(`image:\s*\S*` + img).MatchString(c) {
					found = append(found, img+"-container")
				}
			}
			break
		}
	}
	sort.Strings(found)
	return found
}

const initKeyHelp = `Keys (create them in the app, or re-run with --create-keys):
  WT_INGEST_KEY      wti_...  ingest key: services and the OTel exporter send telemetry with it
  WT_PUBLISHABLE_KEY wtp_...  publishable key: browser SDK / RUM only, safe in client code
  WT_API_KEY         wta_...  service account for wtctl in CI; scopes ci:write, events:write, monitors:write
Also: WT_API_URL, WT_PROJECT (prj_...)`

// initMain is `wtctl init`: write a starter watchtower.yaml for the detected stack and say which
// key goes where. Keys are created only with --create-keys.
func initMain(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	dir := fs.String("dir", ".", "project directory")
	force := fs.Bool("force", false, "overwrite an existing watchtower.yaml")
	createKeys := fs.Bool("create-keys", false, "create (or reuse) the wtctl-ci service account and mint a key for it; the token is printed once, never saved")
	api := fs.String("api", apiEnv(), "API base URL; default $WT_API_URL")
	key := fs.String("key", os.Getenv("WT_API_KEY"), "org admin key for --create-keys; default $WT_API_KEY")
	project := fs.String("project", os.Getenv("WT_PROJECT"), "project id for --create-keys; default $WT_PROJECT")
	if err := fs.Parse(args); err != nil {
		return err
	}
	stack := detectStack(*dir)
	path := filepath.Join(*dir, "watchtower.yaml")
	if _, err := os.Stat(path); err == nil && !*force {
		return errors.New(path + " exists; use --force to overwrite")
	}
	if err := os.WriteFile(path, []byte(starterYAML(stack)), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "detected: %s\nwrote %s\n%s\n", strings.Join(stack, ", "), path, initKeyHelp)
	envPath := filepath.Join(*dir, ".env.example") // names only, never values; an existing file is left alone
	if f, err := os.OpenFile(envPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644); err == nil {
		_, _ = f.WriteString("WT_API_URL=\nWT_PROJECT=\nWT_INGEST_KEY=\nWT_PUBLISHABLE_KEY=\nWT_API_KEY=\n")
		_ = f.Close()
		fmt.Fprintf(out, "wrote %s (variable names only)\n", envPath)
	}
	if *createKeys {
		return createCIKey(ctx, *api, *key, *project, out)
	}
	return nil
}

func starterYAML(stack []string) string {
	has := func(s string) bool {
		for _, x := range stack {
			if x == s {
				return true
			}
		}
		return false
	}
	var b strings.Builder
	b.WriteString("# Starter watchtower.yaml. Check with `wtctl plan`, then `wtctl apply`.\n")
	b.WriteString("# Secrets are ${ENV} references only; they are read when you run apply.\n")
	b.WriteString("environments:\n  - name: production\n\nmonitors:\n")
	b.WriteString("  - name: app-health\n    env: production\n    kind: http\n    interval_s: 300\n    config: { url: https://example.com/health }\n")
	if has("pg") || has("postgres") || has("postgres-container") {
		b.WriteString("  - name: postgres-tcp\n    env: production\n    kind: tcp\n    interval_s: 300\n    config: { host: db.example.com, port: 5432 }\n")
	}
	if has("ioredis") || has("redis-container") || has("bullmq") {
		b.WriteString("  - name: redis-tcp\n    env: production\n    kind: tcp\n    interval_s: 300\n    config: { host: redis.example.com, port: 6379 }\n")
	}
	b.WriteString("\nslos:\n  - name: availability\n    env: production\n    objective: 0.995\n    window_days: 30\n    sli: { availability: { monitor: app-health } }\n")
	if has("next") || has("express") || has("@nestjs/core") || has("go") || has("python") {
		b.WriteString("\nservices:\n  - name: web\n")
	}
	return b.String()
}

const ciAccount = "wtctl-ci"

// createCIKey reuses the service account wtctl-ci (role engineer) or creates it, then mints a
// key for the project with the scopes wtctl needs in CI. A key's token is shown once by the API,
// so every run mints a new key; the token goes to out only.
func createCIKey(ctx context.Context, api, key, project string, out io.Writer) error {
	c, err := ascode.New(api, key, project, guardedClient(0))
	if err != nil {
		return fmt.Errorf("--create-keys: %w (needs --api/$WT_API_URL, --key/$WT_API_KEY, --project/$WT_PROJECT)", err)
	}
	const accounts = "/v1/orgs/{org}/service-accounts"
	var id string
	for cursor := ""; id == ""; {
		var page struct {
			Data []struct{ ID, Name string } `json:"data"`
			Next *string                     `json:"next_cursor"`
		}
		q := "?limit=200"
		if cursor != "" {
			q += "&cursor=" + url.QueryEscape(cursor)
		}
		if err := c.Do(ctx, http.MethodGet, accounts+q, nil, nil, &page); err != nil {
			return fmt.Errorf("list service accounts: %w", err)
		}
		for _, a := range page.Data {
			if a.Name == ciAccount {
				id = a.ID
			}
		}
		if page.Next == nil || *page.Next == "" {
			break
		}
		cursor = *page.Next
	}
	if id == "" {
		var a struct{ ID string }
		body := map[string]any{"name": ciAccount, "role": "engineer", "projects": []string{project}}
		if err := c.Do(ctx, http.MethodPost, accounts, nil, body, &a); err != nil {
			return fmt.Errorf("create service account: %w", err)
		}
		id = a.ID
	}
	var k struct{ Token string }
	body := map[string]any{"name": ciAccount, "scopes": []string{"ci:write", "events:write", "monitors:write"}, "expires_in_days": 365, "project_id": project}
	if err := c.Do(ctx, http.MethodPost, accounts+"/"+url.PathEscape(id)+"/keys", nil, body, &k); err != nil {
		return fmt.Errorf("create key (an existing %s account must allow project %s): %w", ciAccount, project, err)
	}
	fmt.Fprintf(out, "\nservice account %s (%s), key valid 365 days:\nWT_API_KEY=%s\nStore it now: this token is shown once and was not saved anywhere.\n", ciAccount, id, k.Token)
	return nil
}
