package main

import (
	"bufio"
	"bytes"
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
	"time"
)

const provisionUsage = `usage: wtctl provision --project <slug> [--name <display>] [--org <org id>] [--env production] [--origins https://a,https://b] [--out ./watchtower.env] [--rotate] [--json] [--api <url>] [--key <key>]`

type provisioner struct {
	api, key string
	hc       *http.Client
}

// do calls the API and turns an RFC 9457 problem body into a readable error.
func (p *provisioner) do(ctx context.Context, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.api+path, rdr)
	if err != nil {
		return err
	}
	if p.key != "" {
		req.Header.Set("Authorization", "Bearer "+p.key)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		var pr struct{ Code, Title, Detail string }
		_ = json.Unmarshal(b, &pr)
		msg := strings.TrimSpace(pr.Code + " " + pr.Detail)
		if msg == "" {
			msg = pr.Title
		}
		if msg == "" {
			msg = strings.TrimSpace(string(b[:min(len(b), 200)]))
		}
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, msg)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

type provRow struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// list reads every page of a cursor-paginated route.
func (p *provisioner) list(ctx context.Context, path string) ([]provRow, error) {
	var all []provRow
	cursor := ""
	for {
		var pg struct {
			Data []provRow `json:"data"`
			Next *string   `json:"next_cursor"`
		}
		q := path + "?limit=100"
		if cursor != "" {
			q += "&cursor=" + url.QueryEscape(cursor)
		}
		if err := p.do(ctx, "GET", q, nil, &pg); err != nil {
			return nil, err
		}
		all = append(all, pg.Data...)
		if pg.Next == nil || *pg.Next == "" {
			return all, nil
		}
		cursor = *pg.Next
	}
}

// findOrCreate returns the id of the row `match` selects, else creates one.
func (p *provisioner) findOrCreate(ctx context.Context, path string, match func(provRow) bool, body any) (string, bool, error) {
	rows, err := p.list(ctx, path)
	if err != nil {
		return "", false, err
	}
	for _, r := range rows {
		if match(r) {
			return r.ID, false, nil
		}
	}
	var r provRow
	if err := p.do(ctx, "POST", path, body, &r); err != nil {
		return "", false, err
	}
	return r.ID, true, nil
}

type provOpts struct {
	slug, name, org, env, out string
	origins                   []string
	rotate                    bool
}

// provisionRun does the work and returns the final env map plus which keys were written or reused.
func (p *provisioner) run(ctx context.Context, o provOpts) (env map[string]string, written, reused []string, ids map[string]string, err error) {
	env, err = readEnvFile(o.out)
	if err != nil {
		return
	}
	ids = map[string]string{}
	var cfg struct {
		Ingest string `json:"ingest_url"`
		Edge   string `json:"edge_url"`
	}
	if err = p.do(ctx, "GET", "/v1/platforms/config", nil, &cfg); err != nil {
		return
	}
	if cfg.Ingest == "" || cfg.Edge == "" {
		err = errors.New("this install does not advertise its ingest and edge URLs at /v1/platforms/config")
		return
	}
	org := o.org
	if org == "" {
		var orgs []provRow
		if orgs, err = p.list(ctx, "/v1/orgs"); err != nil {
			return
		}
		if len(orgs) != 1 {
			err = fmt.Errorf("the key sees %d orgs; pass --org <org id>", len(orgs))
			return
		}
		org = orgs[0].ID
	}
	name := o.name
	if name == "" {
		name = o.slug
	}
	prj, _, err := p.findOrCreate(ctx, "/v1/orgs/"+org+"/projects", func(r provRow) bool { return r.Slug == o.slug }, map[string]string{"slug": o.slug, "name": name})
	if err != nil {
		return
	}
	pp := "/v1/projects/" + prj
	envID, _, err := p.findOrCreate(ctx, pp+"/environments", func(r provRow) bool { return r.Name == o.env }, map[string]string{"name": o.env})
	if err != nil {
		return
	}
	ids["org"], ids["project"], ids["environment"] = org, prj, envID
	envKey := "WT_ENV_" + strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' {
			return r - 32
		}
		if r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return '_'
	}, o.env)
	set := func(k, v string) {
		if env[k] == "" || env[k] != v {
			written = append(written, k)
		} else {
			reused = append(reused, k)
		}
		env[k] = v
	}
	set("WT_ORG_ID", org)
	set("WT_PROJECT_ID", prj)
	set(envKey, envID)
	set("WT_OTLP_ENDPOINT", cfg.Ingest)
	set("WT_EDGE_URL", cfg.Edge)
	label := "wtctl provision " + o.slug
	// mint runs only for a secret the file lacks, or with --rotate.
	mint := func(k string, f func() (string, error)) error {
		if env[k] != "" && !o.rotate {
			reused = append(reused, k)
			return nil
		}
		v, e := f()
		if e != nil {
			return e
		}
		env[k], written = v, append(written, k)
		return nil
	}
	if err = mint("WT_INGEST_KEY", func() (string, error) {
		var r struct{ Token string }
		e := p.do(ctx, "POST", pp+"/credentials", map[string]any{"name": label, "env_id": envID,
			"scopes": []string{"ingest:traces", "ingest:logs", "ingest:metrics", "ingest:errors"}}, &r)
		return r.Token, e
	}); err != nil {
		return
	}
	// engineer is the lowest role with ManageReleases (releases, deployments, artifact upload).
	if err = mint("WT_CI_API_KEY", func() (string, error) {
		var r struct{ Token string }
		e := p.do(ctx, "POST", "/v1/orgs/"+org+"/api-keys", map[string]any{"name": label, "role": "engineer", "project_id": prj}, &r)
		return r.Token, e
	}); err != nil {
		return
	}
	if len(o.origins) > 0 {
		if err = mint("WT_RUM_KEY", func() (string, error) {
			var r struct{ Key string }
			e := p.do(ctx, "POST", pp+"/rum/keys", map[string]any{"name": label, "env_id": envID, "origins": o.origins}, &r)
			return r.Key, e
		}); err != nil {
			return
		}
		set("WT_RUM_ENDPOINT", cfg.Edge)
		set("WT_RUM_SCRIPT_URL", strings.TrimRight(cfg.Edge, "/")+"/sdk/v0/wt.min.js")
		set("WT_RUM_ORIGINS", strings.Join(o.origins, ","))
	}
	sort.Strings(written)
	sort.Strings(reused)
	return
}

func readEnvFile(path string) (map[string]string, error) {
	m := map[string]string{}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "="); ok && !strings.HasPrefix(k, "#") {
			m[k] = v
		}
	}
	return m, sc.Err()
}

// writeEnvFile writes a temp file created 0600 and renames it over the target, so the secrets are never readable by others.
func writeEnvFile(path string, env map[string]string) error {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("# Watchtower settings written by `wtctl provision`. This file holds SECRETS (WT_INGEST_KEY, WT_CI_API_KEY): never commit it.\n")
	for _, k := range keys {
		b.WriteString(k + "=" + env[k] + "\n")
	}
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp")
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(b.String()); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// provisionMain is `wtctl provision`: set a product up on Watchtower and write its env file.
func provisionMain(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("provision", flag.ContinueOnError)
	api := fs.String("api", apiEnv(), "API base URL")
	key := fs.String("key", os.Getenv("WT_API_KEY"), "API key (org_admin or project_admin); prefer $WT_API_KEY")
	o := provOpts{}
	fs.StringVar(&o.slug, "project", "", "project slug (created when missing)")
	fs.StringVar(&o.name, "name", "", "project display name (default: the slug)")
	fs.StringVar(&o.org, "org", "", "org id (default: the key's only org)")
	fs.StringVar(&o.env, "env", "production", "environment name")
	origins := fs.String("origins", "", "comma-separated browser origins; mints a RUM publishable key")
	fs.StringVar(&o.out, "out", "./watchtower.env", "env file to write")
	fs.BoolVar(&o.rotate, "rotate", false, "mint fresh secrets instead of reusing the file's")
	asJSON := fs.Bool("json", false, "print ids and key names as JSON (no secret values)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if o.slug == "" || *api == "" || *key == "" {
		return errors.New(provisionUsage)
	}
	for _, s := range strings.Split(*origins, ",") {
		if s = strings.TrimSpace(s); s != "" {
			o.origins = append(o.origins, s)
		}
	}
	p := &provisioner{api: strings.TrimRight(*api, "/"), key: *key, hc: guardedClient(30 * time.Second)}
	env, written, reused, ids, err := p.run(ctx, o)
	if err != nil {
		return err
	}
	if err := writeEnvFile(o.out, env); err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(out).Encode(map[string]any{"file": o.out, "ids": ids, "written": written, "reused": reused})
	}
	fmt.Fprintf(out, "wrote %s (mode 0600; holds secrets)\n  written: %s\n  reused:  %s\n", o.out, strings.Join(written, " "), strings.Join(reused, " "))
	return nil
}
