package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// grafanaPage is the page size of Grafana's search API.
const grafanaPage = 500

// grafanaClient reads dashboards from a Grafana instance over its HTTP API.
type grafanaClient struct {
	base, token string
	http        *http.Client
}

func (g grafanaClient) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(g.base, "/")+path, nil)
	if err != nil {
		return err
	}
	if g.token != "" {
		req.Header.Set("Authorization", "Bearer "+g.token)
	}
	res, err := g.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("grafana %s: %s", path, res.Status)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 64<<20)).Decode(out)
}

// uids lists every dashboard of the instance, page by page.
func (g grafanaClient) uids(ctx context.Context) ([]string, error) {
	var all []string
	for page := 1; ; page++ {
		var hits []struct {
			UID string `json:"uid"`
		}
		q := url.Values{"type": {"dash-db"}, "limit": {fmt.Sprint(grafanaPage)}, "page": {fmt.Sprint(page)}}
		if err := g.get(ctx, "/api/search?"+q.Encode(), &hits); err != nil {
			return nil, err
		}
		for _, h := range hits {
			all = append(all, h.UID)
		}
		if len(hits) < grafanaPage {
			return all, nil
		}
	}
}

// dashboardsImportGrafana pulls a whole Grafana instance through the same import route as a file;
// one dashboard failing is reported and the run goes on.
func dashboardsImportGrafana(ctx context.Context, args []string, out io.Writer) error {
	var o asCodeOpts
	fs := o.flags("dashboards import-grafana")
	var base, folder string
	var dry bool
	fs.StringVar(&base, "grafana-url", "", "base URL of the Grafana instance")
	fs.StringVar(&folder, "folder", "", "folder id for the new dashboards")
	fs.BoolVar(&dry, "dry-run", false, "convert and validate, save nothing")
	c, err := o.client(fs, args)
	if err != nil {
		return err
	}
	if base == "" {
		return errors.New(dashboardsUsage)
	}
	g := grafanaClient{base: base, token: os.Getenv("GRAFANA_TOKEN"), http: &http.Client{Timeout: time.Minute}}
	uids, err := g.uids(ctx)
	if err != nil {
		return err
	}
	failed := 0
	for _, uid := range uids {
		var doc struct {
			Dashboard json.RawMessage `json:"dashboard"`
		}
		err := g.get(ctx, "/api/dashboards/uid/"+url.PathEscape(uid), &doc)
		var res struct {
			Dashboard struct {
				Title string `json:"title"`
			} `json:"dashboard"`
			Warnings []struct {
				Path    string `json:"path"`
				Message string `json:"message"`
			} `json:"warnings"`
		}
		if err == nil {
			req := map[string]any{"format": "grafana", "body": string(doc.Dashboard), "dry_run": dry}
			if folder != "" {
				req["folder_id"] = folder
			}
			err = c.Do(ctx, "POST", "dashboards/imports", nil, req, &res)
		}
		if err != nil {
			failed++
			fmt.Fprintf(out, "failed %s: %v\n", uid, err)
			continue
		}
		fmt.Fprintf(out, "imported %q (%d warning(s))\n", res.Dashboard.Title, len(res.Warnings))
		for _, w := range res.Warnings {
			fmt.Fprintf(out, "  warning: %s: %s\n", w.Path, w.Message)
		}
	}
	fmt.Fprintf(out, "%d dashboards, %d failed\n", len(uids), failed)
	if failed > 0 {
		return fmt.Errorf("%d dashboards failed", failed)
	}
	return nil
}
