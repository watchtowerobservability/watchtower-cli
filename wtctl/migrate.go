package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

const migrateUsage = "usage: wtctl migrate datadog [--api-key-env DD_API_KEY] [--app-key-env DD_APP_KEY] [--site datadoghq.com] [--apply] [--report <prefix>]\n" +
	"           [--scope monitors,slos,downtimes,dashboards,notebooks,pipelines,synthetics,indexes,catalog,schedule:<id>,policy:<id>]\n" +
	"           (pulls the account live with a read-only API and application key, then prints what did not map and the share migrated per kind; dry run unless --apply)\n" +
	"       wtctl migrate terraform-datadog <terraform-show.json> [--apply] [--report <prefix>]  (datadog_* resources of a `terraform show -json` state or plan)\n" +
	"       (also --api <url> --key <wt key> --project <id>, defaulting to $WT_API, $WT_API_KEY, $WT_PROJECT)"

// migrateMain is `wtctl migrate datadog|terraform-datadog`; `wtctl import datadog` stays as the file-based form.
func migrateMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(migrateUsage)
	}
	switch args[0] {
	case "datadog":
		rest := args[1:]
		for flagName, env := range map[string]string{"--api-key-env": "DD_API_KEY", "--app-key-env": "DD_APP_KEY"} {
			if !hasFlag(rest, flagName) {
				rest = append(rest, flagName, env)
			}
		}
		return importLiveRun(ctx, append([]string{"datadog", "--live"}, rest...), out, true)
	case "terraform-datadog":
		return migrateTerraform(ctx, args[1:], out)
	}
	return errors.New(migrateUsage)
}

func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name || strings.HasPrefix(a, name+"=") {
			return true
		}
	}
	return false
}

// migrateTerraform uploads the state or plan JSON; the server maps the datadog_* resources through the same
// mappers as the API pull and applies them with --apply.
func migrateTerraform(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("migrate terraform-datadog", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var api, key, project, report string
	var apply bool
	fs.StringVar(&api, "api", os.Getenv("WT_API"), "")
	fs.StringVar(&key, "key", os.Getenv("WT_API_KEY"), "")
	fs.StringVar(&project, "project", os.Getenv("WT_PROJECT"), "")
	fs.StringVar(&report, "report", "import-report", "")
	fs.BoolVar(&apply, "apply", false, "")
	// the state file comes first; flags may follow it
	file := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		file, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w\n%s", err, migrateUsage)
	}
	if file == "" && fs.NArg() == 1 {
		file = fs.Arg(0)
	}
	if file == "" || api == "" || key == "" || project == "" {
		return errors.New("a state file, --api, --key and --project are required (or $WT_API, $WT_API_KEY, $WT_PROJECT)\n" + migrateUsage)
	}
	v, err := uploadImport(ctx, api, key, project, "datadog", apply, nil, map[string]string{"terraform": file})
	fmt.Fprint(out, v.Result.Output)
	fmt.Fprint(out, "\n", v.Result.Markdown)
	if err != nil {
		return err
	}
	return writeImportReport(report, v)
}
