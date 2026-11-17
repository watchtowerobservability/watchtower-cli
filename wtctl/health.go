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
	"strings"
	"time"
)

// healthMain is `wtctl health`: the doctor checks plus the project's state (telemetry arriving,
// integration sources, monitors). Exit 1 when a check at or above --fail-on exists.
func healthMain(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("health", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print {\"checks\":[...],\"ok\":bool}")
	failOn := fs.String("fail-on", "error", "exit 1 on a check at this level or worse: error, warning or never")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch *failOn {
	case "error", "warning", "never":
	default:
		return fmt.Errorf("--fail-on must be error, warning or never, not %q", *failOn)
	}
	return runDiagnostics(ctx, out, *asJSON, *failOn, true)
}

// projectState adds the checks that need WT_PROJECT: first event, integration health, monitors.
func (d *doctor) projectState(ctx context.Context, api, key, prj string) {
	base := api + "/v1/projects/" + url.PathEscape(prj)
	var fe struct {
		Received bool   `json:"received"`
		Signal   string `json:"signal"`
		At       string `json:"at"`
	}
	if d.getJSON(ctx, base+"/onboarding/first-event", key, &fe, "telemetry.received") {
		if fe.Received {
			d.add("telemetry.received", "ok", fmt.Sprintf("telemetry received (%s, %s)", fe.Signal, fe.At), "")
		} else {
			d.add("telemetry.received", "error", "no telemetry has reached this project yet", "point an SDK or the agent at the ingest host with an ingest key (wti_); `wtctl send-test` sends one event")
		}
	}
	var ih struct {
		Data []struct {
			Kind      string `json:"kind"`
			Name      string `json:"name"`
			Status    string `json:"status"`
			LastError string `json:"last_error"`
		} `json:"data"`
	}
	if d.getJSON(ctx, base+"/integration-health", key, &ih, "integration.sources") {
		for _, h := range ih.Data {
			id := "integration." + h.Kind + "." + h.Name
			switch h.Status {
			case "error":
				d.add(id, "error", fmt.Sprintf("%s %s failed: %s", h.Kind, h.Name, h.LastError), "fix the credentials or destination in Settings > Integrations, then re-run it")
			case "pending":
				d.add(id, "warning", fmt.Sprintf("%s %s has never run", h.Kind, h.Name), "wait for its first scheduled run or trigger one in Settings > Integrations")
			default:
				d.add(id, "ok", fmt.Sprintf("%s %s is healthy", h.Kind, h.Name), "")
			}
		}
	}
	cursor := ""
	for page := 0; page < 20; page++ { // shortcut: 20 pages of 100 monitors, raise if a project has more
		var ms struct {
			Data []struct {
				ID     string `json:"id"`
				Name   string `json:"name"`
				Status string `json:"status"`
			} `json:"data"`
			Next string `json:"next_cursor"`
		}
		q := "/monitors?limit=100"
		if cursor != "" { // an empty cursor is a 422
			q += "&cursor=" + url.QueryEscape(cursor)
		}
		if !d.getJSON(ctx, base+q, key, &ms, "monitors.list") {
			return
		}
		for _, m := range ms.Data {
			switch m.Status { // "paused" (disabled) monitors are not checked
			case "down":
				d.add("monitor."+m.ID, "error", fmt.Sprintf("monitor %s is down", m.Name), "open the monitor's latest result in the console to see why it fails")
			case "up":
				d.add("monitor."+m.ID, "ok", fmt.Sprintf("monitor %s is up", m.Name), "")
			}
		}
		if ms.Next == "" {
			return
		}
		cursor = ms.Next
	}
}

// getJSON GETs and decodes; on a transport error or non-200 it records an error check and says false.
func (d *doctor) getJSON(ctx context.Context, u, key string, into any, id string) bool {
	resp, b, err := d.get(ctx, u, key)
	switch {
	case err != nil:
		d.add(id, "error", "GET "+u+": "+err.Error(), "")
	case resp.StatusCode != http.StatusOK:
		d.add(id, "error", fmt.Sprintf("GET %s -> %d", u, resp.StatusCode), "the key needs read access to the project (admin:read or a role)")
	case json.Unmarshal(b, into) != nil:
		d.add(id, "error", "GET "+u+" returned a body wtctl cannot read", "upgrade wtctl")
	default:
		return true
	}
	return false
}

// whoamiMain is `wtctl whoami`: what GET /v1/auth/key says the credential is. The key itself is
// never printed, only its server-reported prefix.
func whoamiMain(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("whoami", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the key's description as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	api, key := strings.TrimRight(firstEnv("WT_API", "WT_API_URL"), "/"), os.Getenv("WT_API_KEY")
	if api == "" || key == "" {
		return errors.New("set WT_API and WT_API_KEY (see `wtctl env`, or run `wtctl login`)")
	}
	d := &doctor{out: io.Discard, http: guardedClient(10 * time.Second)}
	resp, b, err := d.get(ctx, api+"/v1/auth/key", key)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("GET /v1/auth/key answered %d: the key is wrong, revoked or expired, or this server is too old to describe keys", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET /v1/auth/key answered %d", resp.StatusCode)
	}
	var k struct {
		Kind      string   `json:"kind"`
		Prefix    string   `json:"prefix"`
		Name      string   `json:"name"`
		OrgID     string   `json:"org_id"`
		ProjectID string   `json:"project_id"`
		Projects  []string `json:"projects"`
		Scopes    []string `json:"scopes"`
		Role      string   `json:"role"`
		Expires   string   `json:"expires_at"`
	}
	if err := json.Unmarshal(b, &k); err != nil {
		return fmt.Errorf("unreadable /v1/auth/key answer: %w", err)
	}
	if *asJSON {
		return json.NewEncoder(out).Encode(k)
	}
	access := "role " + k.Role
	if k.Role == "" {
		access = "scopes " + strings.Join(k.Scopes, ", ")
		if k.Scopes == nil {
			access = "scopes not narrowed"
		}
	}
	fmt.Fprintf(out, "kind     %s\nkey      %s\naccess   %s\norg      %s\nproject  %s\nexpires  %s\n",
		k.Kind, k.Prefix, access, dash(k.OrgID), dash(firstNonEmpty(k.ProjectID, strings.Join(k.Projects, ", "))), dash(k.Expires))
	return nil
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
