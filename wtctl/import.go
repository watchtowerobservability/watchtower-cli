package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
)

const importUsage = "usage: wtctl import datadog|grafana|newrelic|splunk|promrules|chronosphere|sentry|honeycomb|dynatrace|kibana\n" +
	"       wtctl import helicone --file <export.jsonl> [--endpoint <gateway>] [--key <ingestion key>] [--dry-run]\n" +
	"       wtctl import pagerduty|opsgenie|victorops|splunk-on-call|grafana-oncall|datadog --live ...  (live pull; see below)\n" +
	"           [--alerts <file>] [--dashboards <file>] [--alertmanager <file>] [--monitors <file>] [--pipelines <file>] [--alert-rules <file>]\n" +
	"           [--apply] [--report <prefix>]  (export files are uploaded and mapped on the server; dry run unless --apply; see docs/product/migration)\n" +
	"       (also --api <url> --key <wt key> --project <id>, defaulting to $WT_API, $WT_API_KEY, $WT_PROJECT)"

// importSources are the export-file importers the server runs; the API-pull importers
// (import_live.go) are server-side jobs too, with the vendor key sealed on the server.
var importSources = []string{"datadog", "grafana", "newrelic", "splunk", "promrules", "chronosphere", "sentry", "honeycomb", "dynatrace", "kibana"}

// importMain is `wtctl import <source> --alerts ... --dashboards ...`: it uploads the export
// files, waits for the server-side job and prints its plan and skip report.
func importMain(ctx context.Context, args []string, out io.Writer) error {
	if isLiveImport(args) {
		return importLive(ctx, args, out)
	}
	if len(args) > 0 && args[0] == "helicone" {
		return importHelicone(ctx, args[1:], out)
	}
	if len(args) < 1 || !slices.Contains(importSources, args[0]) {
		return errors.New(importUsage)
	}
	which := args[0]
	fs := flag.NewFlagSet("import "+which, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var api, key, project, report string
	var apply bool
	files := map[string]*string{}
	for _, role := range []string{"alerts", "dashboards", "alertmanager", "monitors", "pipelines", "alert_rules"} {
		files[role] = new(string)
	}
	fs.StringVar(&api, "api", os.Getenv("WT_API"), "")
	fs.StringVar(&key, "key", os.Getenv("WT_API_KEY"), "")
	fs.StringVar(&project, "project", os.Getenv("WT_PROJECT"), "")
	fs.StringVar(&report, "report", "import-report", "")
	fs.BoolVar(&apply, "apply", false, "")
	for _, role := range []string{"alerts", "dashboards", "alertmanager", "monitors", "pipelines"} {
		fs.StringVar(files[role], role, "", "")
	}
	fs.StringVar(files["alert_rules"], "alert-rules", "", "")
	if err := fs.Parse(args[1:]); err != nil {
		return fmt.Errorf("%w\n%s", err, importUsage)
	}
	if api == "" || key == "" || project == "" {
		return errors.New("--api, --key and --project are required (or $WT_API, $WT_API_KEY, $WT_PROJECT)")
	}
	picked := map[string]string{}
	for role, p := range files {
		if *p != "" {
			picked[role] = *p
		}
	}
	if len(picked) == 0 {
		return errors.New("give at least one export file (--alerts, --dashboards, ...)\n" + importUsage)
	}
	v, err := uploadImport(ctx, api, key, project, which, apply, nil, picked)
	fmt.Fprint(out, v.Result.Output)
	if err != nil {
		return err
	}
	return writeImportReport(report, v)
}
