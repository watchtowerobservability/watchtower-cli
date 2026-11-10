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
		"name": name, "kind": "metric", "query": map[string]any{"promql": promql},
		"condition": map[string]any{"threshold": map[string]any{"op": op, "value": threshold}},
		"for_s":     forS, "severity": sev, "every_s": 60, "window_s": 300,
	}
}

// selfmonRules query metrics the services really expose. The worker's come from the agent's
// prometheus module scraping :8889. Every series exists at 0 from startup, so no data means monitoring
// is blind and each rule fires. A memory error outside a per-query limit fires at once (for_s 0): one failed merge or
// insert is already a signal, and increase() falls back to 0 five minutes later.
// shortcut: no rule for alert evaluation lag, no service exposes it yet; add it with the metric.
func selfmonRules() []map[string]any {
	rules := []map[string]any{
		selfmonRule("Worker lag over 1000 messages", "max(wt_worker_lag)", "gt", 1000, 300, "high"),
		selfmonRule("ClickHouse insert errors", "increase(wt_ch_insert_errors_total[5m])", "gt", 0, 300, "high"),
		selfmonRule("ClickHouse memory limit errors", `sum(increase({__name__="clickhouse.errors","error.type"="MEMORY_LIMIT_EXCEEDED"}[5m])) - sum(increase({__name__="clickhouse.errors","error.type"="QUERY_MEMORY_LIMIT_EXCEEDED"}[5m]))`, "gt", 0, 0, "high"),
		selfmonRule("Gateway produce errors", "sum(increase(wt_gateway_produce_errors_total[5m]))", "gt", 0, 300, "high"),
		selfmonRule("Host disk under 10 GB free", `min({__name__="system.filesystem.usage",state="free",mountpoint="/etc/hosts"})`, "lt", 10e9, 300, "high"),
		selfmonRule("Gateway throttling platform ingest", "sum(increase(wt_gateway_throttled_total[5m]))", "gt", 0, 300, "high"),
		selfmonRule("Notifier page queued over 5 minutes", "max(wt_notifier_oldest_due_seconds)", "gt", 300, 0, "high"),
		selfmonRule("Gateway refusing repeated bad keys", "sum(increase(wt_gateway_auth_fail_limited_total[5m]))", "gt", 0, 0, "warning"),
		selfmonRule("Agent dropping records", "sum(increase(wt_agent_export_records_dropped_total[5m]))", "gt", 0, 300, "warning"),
	}
	for _, r := range rules {
		r["no_data"] = "alerting"
	}
	return rules
}

// selfMonitorMain is `wtctl self-monitor init`: the "Platform health" dashboard and its rules.
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
