package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
)

const monitorsUsage = `usage: wtctl monitors list [--status active|retired|paused] [--service <name>] [--limit 100] [--project <id|slug|org/slug>]
       wtctl monitors prune --service <name> [--dry-run] [--project <id|slug|org/slug>]   (retire the auto-created cron monitors of <name> whose job no longer exists)`

// monitorsMain is `wtctl monitors`: list monitors (also the retired ones the SDK's cron integration
// leaves behind) and prune the auto-created ones of a service by hand.
func monitorsMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(monitorsUsage)
	}
	fs := flag.NewFlagSet("monitors "+args[0], flag.ContinueOnError)
	api := fs.String("api", apiEnv(), "API base URL; default $WT_API_URL")
	key := fs.String("key", os.Getenv("WT_API_KEY"), "API key; default $WT_API_KEY")
	project := fs.String("project", os.Getenv("WT_PROJECT"), "project id, slug or org/slug; default $WT_PROJECT")
	service := fs.String("service", "", "the service (WT_SERVICE) the monitors belong to")
	status := fs.String("status", "", "list: only monitors in this state (retired lists what prune or the worker start retired)")
	limit := fs.Int("limit", 100, "list: page size")
	dry := fs.Bool("dry-run", false, "prune: say what would be retired and change nothing")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *api == "" || *key == "" || *project == "" {
		return errors.New("--api, --key and --project are required (or $WT_API_URL, $WT_API_KEY, $WT_PROJECT)")
	}
	base := strings.TrimRight(*api, "/") + "/v1/projects/" + url.PathEscape(projectRef(*project)) + "/monitors"
	switch args[0] {
	case "list":
		q := url.Values{"limit": {fmt.Sprint(*limit)}}
		if *status != "" {
			q.Set("status", *status)
		}
		if *service != "" {
			q.Set("service", *service)
		}
		var page struct {
			Data []struct {
				ID      string `json:"id"`
				Name    string `json:"name"`
				Kind    string `json:"kind"`
				Status  string `json:"status"`
				Service string `json:"service"`
			} `json:"data"`
			NextCursor *string `json:"next_cursor"`
		}
		if err := call(ctx, "GET", base+"?"+q.Encode(), *key, nil, &page); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		for _, m := range page.Data {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", m.ID, m.Name, m.Kind, m.Status, m.Service)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		if page.NextCursor != nil && *page.NextCursor != "" {
			fmt.Fprintf(out, "more: next cursor %s (raise --limit)\n", *page.NextCursor)
		}
		return nil
	case "prune":
		if *service == "" {
			return errors.New("monitors prune needs --service <name>")
		}
		var res struct {
			Retired []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"retired"`
			DryRun bool `json:"dry_run"`
		}
		if err := call(ctx, "POST", base+"/prune", *key, map[string]any{"service": *service, "dry_run": *dry}, &res); err != nil {
			return err
		}
		verb := "retired"
		if res.DryRun || *dry {
			verb = "would retire"
		}
		for _, m := range res.Retired {
			fmt.Fprintf(out, "%s %s (%s)\n", verb, m.Name, m.ID)
		}
		fmt.Fprintf(out, "%s %d monitor(s) of service %s\n", verb, len(res.Retired), *service)
		return nil
	}
	return errors.New(monitorsUsage)
}
