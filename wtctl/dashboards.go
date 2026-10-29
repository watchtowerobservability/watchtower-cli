package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/watchtowerobservability/watchtower-cli/internal/ascode"
)

const dashboardsUsage = "usage: wtctl dashboards export [<id|title>] --project <id> [--format manifest|yaml|json] [--out file] [--api <url>] [--key <key>]\n" +
	"       wtctl dashboards import <file> --project <id> [--format grafana|yaml|json] [--folder <id>] [--dry-run]\n" +
	"       wtctl dashboards diff -f <dir|file> --project <id>\n" +
	"       wtctl dashboards apply -f <dir|file> --project <id> [--dry-run]"

// dashboardsMain is `wtctl dashboards export|import|diff|apply`: dashboards as code, plus Grafana import.
func dashboardsMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) < 1 {
		return errors.New(dashboardsUsage)
	}
	switch args[0] {
	case "export":
		return dashboardsExport(ctx, args[1:], out)
	case "import":
		return dashboardsImport(ctx, args[1:], out)
	case "diff", "apply":
		if err := onlyDashboards(args[1:]); err != nil {
			return err
		}
		if args[0] == "diff" {
			return diffMain(ctx, args[1:], out)
		}
		return applyMain(ctx, args[1:], out)
	}
	return errors.New(dashboardsUsage)
}

// onlyDashboards refuses a manifest set that holds anything but Dashboards: `dashboards apply`
// must never touch other kinds, even with --prune.
func onlyDashboards(args []string) error {
	for i, a := range args {
		if (a == "-f" || a == "--f") && i+1 < len(args) {
			docs, err := ascode.LoadDocs(args[i+1])
			if err != nil {
				return err
			}
			for _, d := range docs {
				if d.Kind != "Dashboard" {
					return fmt.Errorf("%s/%s: wtctl dashboards handles kind Dashboard only (use wtctl apply)", d.Kind, d.Metadata.Name)
				}
			}
		}
	}
	return nil
}

func dashboardsExport(ctx context.Context, args []string, out io.Writer) error {
	var o asCodeOpts
	fs := o.flags("dashboards export")
	var format, outFile string
	fs.StringVar(&format, "format", "manifest", "manifest (for wtctl apply), yaml or json (the API export document)")
	fs.StringVar(&outFile, "out", "", "write here instead of stdout")
	sel, rest := "", args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sel, rest = args[0], args[1:]
	}
	c, err := o.client(fs, rest)
	if err != nil {
		return err
	}
	k := ascode.ByKind("Dashboard")
	items, err := c.List(ctx, k)
	if err != nil {
		return err
	}
	var names []string
	for n, it := range items {
		if sel == "" || n == sel || it.Ref == sel {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return fmt.Errorf("no dashboard matches %q", sel)
	}
	var b []byte
	switch format {
	case "manifest":
		docs := make([]ascode.Doc, 0, len(names))
		for _, n := range names {
			docs = append(docs, ascode.ExportDoc(k, n, items[n].Body))
		}
		b, err = ascode.Marshal(docs)
	case "yaml", "json":
		if len(names) != 1 {
			return errors.New("--format yaml|json exports one dashboard; name it by id or title")
		}
		var doc map[string]any
		if err = c.Do(ctx, "GET", "dashboards/"+items[names[0]].Ref+"/export", nil, nil, &doc); err != nil {
			return err
		}
		if format == "json" {
			b, err = json.MarshalIndent(doc, "", "  ")
			b = append(b, '\n')
		} else {
			b, err = yaml.Marshal(doc) // map keys come out sorted: stable
		}
	default:
		return fmt.Errorf("unknown --format %q", format)
	}
	if err != nil {
		return err
	}
	if outFile != "" {
		return os.WriteFile(outFile, b, 0o644)
	}
	_, err = out.Write(b)
	return err
}

// importFormat picks the document format: the flag, else the extension, else Grafana when the
// JSON has a schemaVersion.
func importFormat(flagVal, path string, body []byte) string {
	if flagVal != "" {
		return flagVal
	}
	if e := strings.ToLower(filepath.Ext(path)); e == ".yaml" || e == ".yml" {
		return "yaml"
	}
	var probe struct {
		SchemaVersion *int `json:"schemaVersion"`
	}
	if json.Unmarshal(body, &probe) == nil && probe.SchemaVersion != nil {
		return "grafana"
	}
	return "json"
}

func dashboardsImport(ctx context.Context, args []string, out io.Writer) error {
	if len(args) < 1 || strings.HasPrefix(args[0], "-") {
		return errors.New(dashboardsUsage)
	}
	file, rest := args[0], args[1:]
	var o asCodeOpts
	fs := o.flags("dashboards import")
	var format, folder string
	var dry bool
	fs.StringVar(&format, "format", "", "grafana, yaml or json (default: from the file)")
	fs.StringVar(&folder, "folder", "", "folder id for the new dashboard")
	fs.BoolVar(&dry, "dry-run", false, "convert and validate, save nothing")
	c, err := o.client(fs, rest)
	if err != nil {
		return err
	}
	body, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	req := map[string]any{"format": importFormat(format, file, body), "body": string(body), "dry_run": dry}
	if folder != "" {
		req["folder_id"] = folder
	}
	var res struct {
		Dashboard map[string]any `json:"dashboard"`
		Warnings  []struct {
			Path    string `json:"path"`
			Message string `json:"message"`
		} `json:"warnings"`
	}
	if err := c.Do(ctx, "POST", "dashboards/imports", nil, req, &res); err != nil {
		return err
	}
	for _, w := range res.Warnings {
		fmt.Fprintf(out, "warning: %s: %s\n", w.Path, w.Message)
	}
	title, _ := res.Dashboard["title"].(string)
	if dry {
		fmt.Fprintf(out, "dry run: would create %q (%d warning(s))\n", title, len(res.Warnings))
		return nil
	}
	id, _ := res.Dashboard["id"].(string)
	fmt.Fprintf(out, "created %q (%s)\n", title, id)
	return nil
}
