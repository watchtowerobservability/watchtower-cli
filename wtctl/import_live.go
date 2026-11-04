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

// liveSources pull from the vendor's API. The CLI reads the vendor key from the named environment
// variable and sends it to the Watchtower API, which seals it; the pull runs server-side.
// splunk-on-call is VictorOps under its new name; datadog with --api-key-env is the live pull.
var liveSources = []string{"pagerduty", "opsgenie", "victorops", "splunk-on-call", "grafana-oncall", "zenduty"}

const liveUsage = "usage: wtctl import pagerduty|opsgenie|victorops|splunk-on-call|grafana-oncall|zenduty|datadog --live\n" +
	"           --api-key-env <VAR> [--app-key-env <VAR>] [--api-id-env <VAR>] [--region us|eu] [--site datadoghq.com]\n" +
	"           [--url <oncall https url>] [--scope policy=<id>,schedule=<id>,user=<email> | monitors,dashboards,pipelines]\n" +
	"           [--apply] [--report <prefix>]  (the key is sealed on the server and never returned)"

// isLiveImport reports whether args select a live pull: a live-only source, or datadog --live.
func isLiveImport(args []string) bool {
	return len(args) > 0 && (slices.Contains(liveSources, args[0]) || (args[0] == "datadog" && slices.Contains(args[1:], "--live")))
}

func importLive(ctx context.Context, args []string, out io.Writer) error {
	which := args[0]
	fs := flag.NewFlagSet("import "+which, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var api, key, project, report, keyEnv, appEnv, idEnv, region, site, url, scope string
	var apply, live bool
	fs.StringVar(&api, "api", os.Getenv("WT_API"), "")
	fs.StringVar(&key, "key", os.Getenv("WT_API_KEY"), "")
	fs.StringVar(&project, "project", os.Getenv("WT_PROJECT"), "")
	fs.StringVar(&report, "report", "import-report", "")
	fs.StringVar(&keyEnv, "api-key-env", "", "")
	fs.StringVar(&appEnv, "app-key-env", "", "")
	fs.StringVar(&idEnv, "api-id-env", "", "")
	fs.StringVar(&region, "region", "", "")
	fs.StringVar(&site, "site", "", "")
	fs.StringVar(&url, "url", "", "")
	fs.StringVar(&scope, "scope", "", "")
	fs.BoolVar(&apply, "apply", false, "")
	fs.BoolVar(&live, "live", false, "")
	if err := fs.Parse(args[1:]); err != nil {
		return fmt.Errorf("%w\n%s", err, liveUsage)
	}
	if api == "" || key == "" || project == "" {
		return errors.New("--api, --key and --project are required (or $WT_API, $WT_API_KEY, $WT_PROJECT)")
	}
	env := func(name string) (string, error) {
		if name == "" {
			return "", nil
		}
		v := os.Getenv(name)
		if v == "" {
			return "", fmt.Errorf("environment variable %s is empty", name)
		}
		return v, nil
	}
	vkey, err := env(keyEnv)
	if err != nil || vkey == "" {
		return errors.Join(err, errors.New(liveUsage))
	}
	fields := map[string]string{"api_key": vkey, "region": region, "site": site, "url": url, "scope": scope}
	if fields["app_key"], err = env(appEnv); err != nil {
		return err
	}
	if fields["api_id"], err = env(idEnv); err != nil {
		return err
	}
	source := which
	switch which {
	case "splunk-on-call":
		source = "victorops"
	case "datadog":
		source = "datadog-live"
	}
	v, err := uploadImport(ctx, api, key, project, source, apply, fields, nil)
	fmt.Fprint(out, v.Result.Output)
	if err != nil {
		return err
	}
	return writeImportReport(report, v)
}
