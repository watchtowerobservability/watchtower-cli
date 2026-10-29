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
)

const fleetUsage = `usage: wtctl fleet <command> --api <url> --key <key> --project <id>
  configs                                   list configs
  push <config-id> <file> [--note TEXT]     add a version (validated against the component catalog)
  rollout <config-id> --version N [--canary PCT] [--bake SECONDS] [--max-unhealthy PCT]
                                  [--os OS] [--env ENV] [--zone ZONE] [--label k=v ...]
  rollouts                                  list rollouts, newest first
  agents                                    list agents with config, health and last seen
  flare <agent-id>                          request a diagnostics bundle
  restart <agent-id>                        request an agent restart`

type labelFlag map[string]string

func (l labelFlag) String() string { return fmt.Sprint(map[string]string(l)) }
func (l labelFlag) Set(s string) error {
	k, v, ok := strings.Cut(s, "=")
	if !ok || k == "" {
		return errors.New("label must be key=value")
	}
	l[k] = v
	return nil
}

// fleetMain is `wtctl fleet ...`, a thin client of the /v1/projects/{p}/fleet API.
func fleetMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) < 1 {
		return errors.New(fleetUsage)
	}
	cmd := args[0]
	// Positional arguments precede the flags.
	var pos []string
	rest := args[1:]
	for len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		pos, rest = append(pos, rest[0]), rest[1:]
	}
	fs := flag.NewFlagSet("fleet "+cmd, flag.ContinueOnError)
	api := fs.String("api", "", "API base URL")
	key := fs.String("key", os.Getenv("WT_API_KEY"), "API key; default $WT_API_KEY")
	project := fs.String("project", "", "project id")
	note := fs.String("note", "", "version note")
	version := fs.Int("version", 0, "config version to roll out")
	canary := fs.Int("canary", 0, "canary percent (1-99); 0 = all at once")
	bake := fs.Int("bake", 300, "canary bake time in seconds")
	unhealthy := fs.Int("max-unhealthy", 10, "percent of canaries allowed unhealthy")
	osName := fs.String("os", "", "select agents by os")
	envName := fs.String("env", "", "select agents by environment")
	zone := fs.String("zone", "", "select agents by zone")
	labels := labelFlag{}
	fs.Var(labels, "label", "select agents by label key=value (repeatable)")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if *api == "" || *key == "" || *project == "" {
		return errors.New("--api, --key and --project are required")
	}
	base := strings.TrimRight(*api, "/") + "/v1/projects/" + url.PathEscape(*project) + "/fleet"
	do := func(method, path string, body any) error {
		var res any
		if err := call(ctx, method, base+path, *key, body, &res); err != nil {
			return err
		}
		if res == nil {
			return nil
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}
	need := func(n int) error {
		if len(pos) != n {
			return errors.New(fleetUsage)
		}
		return nil
	}
	switch cmd {
	case "configs":
		return do(http.MethodGet, "/configs", nil)
	case "rollouts":
		return do(http.MethodGet, "/rollouts", nil)
	case "agents":
		return do(http.MethodGet, "/agents", nil)
	case "push":
		if err := need(2); err != nil {
			return err
		}
		b, err := os.ReadFile(pos[1])
		if err != nil {
			return err
		}
		return do(http.MethodPost, "/configs/"+url.PathEscape(pos[0])+"/versions", map[string]any{"body": string(b), "note": *note})
	case "rollout":
		if err := need(1); err != nil {
			return err
		}
		if *version < 1 {
			return errors.New("--version is required")
		}
		sel := map[string]any{}
		for k, v := range map[string]string{"os": *osName, "env": *envName, "zone": *zone} {
			if v != "" {
				sel[k] = v
			}
		}
		if len(labels) > 0 {
			sel["labels"] = map[string]string(labels)
		}
		req := map[string]any{"config_id": pos[0], "version": *version, "selector": sel, "strategy": "all"}
		if *canary > 0 {
			req["strategy"], req["canary_pct"], req["bake_s"], req["max_unhealthy_pct"] = "canary", *canary, *bake, *unhealthy
		}
		return do(http.MethodPost, "/rollouts", req)
	case "flare", "restart":
		if err := need(1); err != nil {
			return err
		}
		return do(http.MethodPost, "/agents/"+url.PathEscape(pos[0])+"/"+cmd, nil)
	}
	return errors.New(fleetUsage)
}
