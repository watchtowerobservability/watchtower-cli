package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// envMain is `wtctl env`: the resolved connection settings and where each came from. The key is
// shown as its prefix only.
func envMain(_ context.Context, _ []string, out io.Writer) error {
	for _, r := range resolveEnv() {
		fmt.Fprintf(out, "%-8s %-40s %s\n", r.name, r.value, r.source)
	}
	return nil
}

type envRow struct{ name, value, source string }

func resolveEnv() []envRow {
	src := func(vars ...string) (string, string) {
		for _, v := range vars {
			if x := os.Getenv(v); x != "" {
				if ctxFilled[v] {
					return x, "context " + ctxName
				}
				return x, "$" + v
			}
		}
		return "", "unset (set " + vars[0] + ", pass --api/--key/--project to a command, or run wtctl login)"
	}
	api, as := src("WT_API", "WT_API_URL")
	prj, ps := src("WT_PROJECT")
	key, ks := src("WT_API_KEY")
	return []envRow{{"api", api, as}, {"project", prj, ps}, {"key", keyPrefix(key), ks}}
}

// keyPrefix is the part of a key that names its kind (wtk_ab12...), never the secret.
func keyPrefix(k string) string {
	if k == "" {
		return ""
	}
	if i := strings.Index(k, "_"); i >= 0 && i+5 <= len(k) {
		return k[:i+5] + "..."
	}
	return k[:min(4, len(k))] + "..."
}

// keyKinds is docs/product/admin/keys-and-scopes.md in one line per kind.
var keyKinds = map[string]string{
	"wtu_": "personal access token: acts as you; query:*, admin:* and ci:write scopes narrow it",
	"wtk_": "org API key: a role in the org or one project (read_only keys only GET)",
	"wta_": "service account key: query:*, admin:*, ci:write and ingest:* scopes",
	"wti_": "ingest key: ingest:* (+ agent:fleet, probes:read). Sends telemetry; it cannot call /v1 API routes",
	"wtp_": "publishable key: ingest:rum for the browser SDK only",
}

type doctor struct {
	out  io.Writer
	http *http.Client
	bad  int
}

func (d *doctor) line(ok bool, what, fix string) {
	mark := "ok  "
	if !ok {
		mark = "FAIL"
		d.bad++
	}
	fmt.Fprintf(d.out, "[%s] %s\n", mark, what)
	if !ok && fix != "" {
		fmt.Fprintf(d.out, "       fix: %s\n", fix)
	}
}

func (d *doctor) get(ctx context.Context, url, key string) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := d.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return resp, b, nil
}

// doctorMain is `wtctl doctor`: is the API reachable, does the key work and what can it do, do the
// ingest and edge hosts answer, is the clock right. Every failure prints the concrete fix.
func doctorMain(ctx context.Context, _ []string, out io.Writer) error {
	d := &doctor{out: out, http: guardedClient(10 * time.Second)}
	api := strings.TrimRight(firstEnv("WT_API", "WT_API_URL"), "/")
	key, prj := os.Getenv("WT_API_KEY"), os.Getenv("WT_PROJECT")
	if api == "" {
		d.line(false, "no API URL", "export WT_API=https://<your-console-host> (see `wtctl env`; hosted: https://watchtowerops.net) or run `wtctl login --api <url> --key <key> --project <prj>`")
		return doctorResult(d)
	}
	resp, _, err := d.get(ctx, api+"/healthz", "")
	if err != nil || resp.StatusCode != http.StatusOK {
		d.line(false, "API "+api+" is not reachable: "+errOrStatus(err, resp), "check the URL is the console/API host (not ingest. or edge.), your network and proxy settings")
		return doctorResult(d)
	}
	d.line(true, "API "+api+" answers /healthz", "")
	if t, err := http.ParseTime(resp.Header.Get("Date")); err == nil {
		skew := time.Since(t).Round(time.Second)
		d.line(skew < 2*time.Minute && skew > -2*time.Minute, fmt.Sprintf("clock skew against the API: %s", skew), "sync this machine's clock (NTP); signed requests and token expiry break past a few minutes of skew")
	}
	if key == "" {
		d.line(false, "no API key", "export WT_API_KEY=<key>; create one under Settings > API keys (wtk_/wta_) or POST /v1/me/tokens (wtu_)")
	} else {
		d.keyChecks(ctx, api, key, prj)
	}
	d.hosts(ctx, api)
	return doctorResult(d)
}

func (d *doctor) keyChecks(ctx context.Context, api, key, prj string) {
	kind := "unknown kind (expected wtk_, wta_, wtu_, wti_ or wtp_)"
	if len(key) >= 4 && keyKinds[key[:4]] != "" {
		kind = keyKinds[key[:4]]
	}
	if !d.introspect(ctx, api, key) {
		fmt.Fprintf(d.out, "       key %s: %s (guessed from the prefix; this server has no GET /v1/auth/key)\n", keyPrefix(key), kind)
	}
	if strings.HasPrefix(key, "wti_") || strings.HasPrefix(key, "wtp_") {
		d.line(false, "this key only sends telemetry and cannot call the API", "for wtctl use an org API key (wtk_) or a service account key (wta_) with admin:read/admin:write; keep the ingest key for SDKs and the agent")
		return
	}
	resp, _, err := d.get(ctx, api+"/v1/orgs", key)
	switch {
	case err != nil:
		d.line(false, "key check failed: "+err.Error(), "")
	case resp.StatusCode == http.StatusUnauthorized:
		d.line(false, "the API rejects this key (401)", "the key is wrong, revoked or expired: create a new one and export WT_API_KEY")
	default:
		d.line(resp.StatusCode == http.StatusOK, fmt.Sprintf("key authenticates (GET /v1/orgs -> %d)", resp.StatusCode), "the key authenticates but lacks read access: give it admin:read or a role on the org")
	}
	if prj == "" {
		d.line(false, "no project set", "export WT_PROJECT=<project id> (Settings > Project)")
		return
	}
	for _, p := range []struct{ path, needs string }{{"environments", "project read (admin:read or a role)"}, {"credentials", "admin:read"}} {
		resp, _, err := d.get(ctx, api+"/v1/projects/"+prj+"/"+p.path, key)
		switch {
		case err != nil:
			d.line(false, "GET "+p.path+": "+err.Error(), "")
		case resp.StatusCode == http.StatusNotFound:
			d.line(false, "GET /v1/projects/"+prj+"/"+p.path+" -> 404", "the project id is wrong or this key cannot see the project (inaccessible projects answer 404, not 403)")
		default:
			d.line(resp.StatusCode == http.StatusOK, fmt.Sprintf("GET %s -> %d (needs %s)", p.path, resp.StatusCode, p.needs), "grant the scope or a role that includes it")
		}
	}
	d.receipt(ctx, api, key, prj)
}

// introspect prints what the server says the key is (GET /v1/auth/key: scopes or role, project
// binding, expiry). It reports false when the route is absent (an older server), so the caller falls
// back to the prefix guess.
func (d *doctor) introspect(ctx context.Context, api, key string) bool {
	resp, b, err := d.get(ctx, api+"/v1/auth/key", key)
	if err != nil || resp.StatusCode != http.StatusOK {
		return false
	}
	var k struct {
		Kind      string   `json:"kind"`
		Name      string   `json:"name"`
		Prefix    string   `json:"prefix"`
		Role      string   `json:"role"`
		Scopes    []string `json:"scopes"`
		Projects  []string `json:"projects"`
		ProjectID string   `json:"project_id"`
		ReadOnly  bool     `json:"read_only"`
		Expires   string   `json:"expires_at"`
	}
	if json.Unmarshal(b, &k) != nil {
		return false
	}
	fmt.Fprintf(d.out, "       key %s (%s) %q\n", k.Prefix, k.Kind, k.Name)
	switch {
	case k.Scopes != nil:
		fmt.Fprintf(d.out, "       scopes: %s\n", strings.Join(k.Scopes, ", "))
	case k.Role != "":
		fmt.Fprintf(d.out, "       role: %s (read_only=%t)\n", k.Role, k.ReadOnly)
	default:
		fmt.Fprintln(d.out, "       scopes: not narrowed (acts with its owner's full role)")
	}
	if k.ProjectID != "" {
		fmt.Fprintf(d.out, "       bound to project %s\n", k.ProjectID)
	} else if k.Projects != nil {
		fmt.Fprintf(d.out, "       limited to projects %s\n", strings.Join(k.Projects, ", "))
	}
	if k.Expires != "" {
		fmt.Fprintf(d.out, "       expires %s\n", k.Expires)
	}
	return true
}

// receipt prints what reached storage in the last hour (GET /v1/projects/{prj}/ingest/data-receipt).
func (d *doctor) receipt(ctx context.Context, api, key, prj string) {
	resp, b, err := d.get(ctx, api+"/v1/projects/"+prj+"/ingest/data-receipt?range=1h", key)
	if err != nil || resp.StatusCode != http.StatusOK {
		return // the access checks above already explain a refusal
	}
	var r struct {
		Data []struct {
			Signal   string `json:"signal"`
			Received uint64 `json:"received"`
			Rejected uint64 `json:"rejected_samples"`
		} `json:"data"`
	}
	if json.Unmarshal(b, &r) != nil {
		return
	}
	for _, s := range r.Data {
		fmt.Fprintf(d.out, "       last hour: %-8s stored %d, rejected samples %d\n", s.Signal, s.Received, s.Rejected)
	}
}

// hosts checks the ingest and edge hosts the API advertises at GET /v1/platforms/config.
func (d *doctor) hosts(ctx context.Context, api string) {
	_, b, err := d.get(ctx, api+"/v1/platforms/config", "")
	var cfg struct {
		Ingest string `json:"ingest_url"`
		Edge   string `json:"edge_url"`
	}
	if err != nil || json.Unmarshal(b, &cfg) != nil {
		d.line(false, "could not read /v1/platforms/config, so ingest and edge were not checked", "check the API host is the console host")
		return
	}
	for _, h := range []struct{ name, url, use string }{{"ingest (gateway)", cfg.Ingest, "OTLP from SDKs and the agent endpoint"}, {"edge", cfg.Edge, "agent fleet_endpoint, browser SDK, CI webhooks"}} {
		if h.url == "" {
			d.line(false, h.name+" URL is not advertised by this install", "set WT_INGEST_URL / WT_EDGE_URL on the API (self-hosted)")
			continue
		}
		resp, _, err := d.get(ctx, strings.TrimRight(h.url, "/")+"/healthz", "")
		d.line(err == nil && resp.StatusCode == http.StatusOK, fmt.Sprintf("%s %s answers /healthz (%s)", h.name, h.url, h.use), "check DNS/firewall for "+h.url+": "+errOrStatus(err, resp))
	}
}

func firstEnv(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}

func errOrStatus(err error, r *http.Response) string {
	if err != nil {
		return err.Error()
	}
	return r.Status
}

func doctorResult(d *doctor) error {
	if d.bad > 0 {
		return exitCode(1)
	}
	fmt.Fprintln(d.out, "all checks passed")
	return nil
}
