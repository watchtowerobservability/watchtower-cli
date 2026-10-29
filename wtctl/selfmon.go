package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// selfmonDashboard is a copy of crates/wt-dashboards/src/templates/platform.json (go:embed cannot
// leave the module); keep the two identical.
//
//go:embed selfmon_platform.json
var selfmonDashboard []byte

const selfmonUsage = "usage: wtctl self-monitor init --project <platform-project-id> --api <url> --key <key>"

// selfmonRule is one alert rule body (RuleSpec) for the platform project.
func selfmonRule(name, promql, op string, threshold float64, forS int, sev string) map[string]any {
	return map[string]any{
		"name": name, "kind": "promql", "query": map[string]any{"promql": promql},
		"condition": map[string]any{"threshold": map[string]any{"op": op, "value": threshold}},
		"for_s":     forS, "severity": sev, "every_s": 60, "window_s": 300,
	}
}

func selfmonRules() []map[string]any {
	return []map[string]any{
		selfmonRule("Consumer lag over 60s", "max(wt_consumer_lag_seconds)", "gt", 60, 300, "high"),
		selfmonRule("ClickHouse insert errors", "increase(wt_ch_insert_errors_total[5m])", "gt", 0, 300, "high"),
		selfmonRule("Gateway 5xx rate over 1%", "100 * sum(rate(wt_gateway_responses_total{class=\"5xx\"}[5m])) / sum(rate(wt_gateway_responses_total[5m]))", "gt", 1, 0, "critical"),
		selfmonRule("Alert evaluation lag over 120s", "max(wt_alert_eval_lag_seconds)", "gt", 120, 0, "high"),
		selfmonRule("Outbox age over 5m", "max(wt_outbox_age_seconds)", "gt", 300, 0, "warning"),
	}
}

// selfMonitorMain is `wtctl self-monitor init`: the "Platform health" dashboard and five rules.
func selfMonitorMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) < 1 || args[0] != "init" {
		return errors.New(selfmonUsage)
	}
	var o rulesOpts
	fs := o.flags("self-monitor init")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if o.api == "" || o.key == "" || o.project == "" {
		return errors.New("--api, --key and --project are required")
	}
	return selfMonitorInit(ctx, o.api, o.key, o.project, out)
}

func selfMonitorInit(ctx context.Context, api, key, project string, out io.Writer) error {
	var spec any
	if err := json.Unmarshal(selfmonDashboard, &spec); err != nil {
		return err
	}
	base := strings.TrimRight(api, "/") + "/v1/projects/" + url.PathEscape(project)
	var d map[string]any
	if err := call(ctx, http.MethodPost, base+"/dashboards", key, map[string]any{"title": "Platform health", "spec": spec}, &d); err != nil {
		return fmt.Errorf("dashboard: %w", err)
	}
	fmt.Fprintf(out, "dashboard %v\n", d["id"])
	for _, r := range selfmonRules() {
		if err := call(ctx, http.MethodPost, base+"/alert-rules", key, r, nil); err != nil {
			return fmt.Errorf("rule %v: %w", r["name"], err)
		}
		fmt.Fprintf(out, "rule %v\n", r["name"])
	}
	return nil
}
