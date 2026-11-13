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
	"regexp"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-cli/internal/ascode"
)

const shadowUsage = "usage: wtctl shadow datadog --monitors <file|api> --events <file|api> [--from <rfc3339>] [--to <rfc3339>] [--tolerance 10m] [--out shadow-report] [--upload]\n" +
	"           [--api-key-env DD_API_KEY --app-key-env DD_APP_KEY --site datadoghq.com]  (for `api`)\n" +
	"           (also --api <url> --key <wt key> --project <id>, defaulting to $WT_API_URL, $WT_API_KEY, $WT_PROJECT)"

var ddSiteOK = regexp.MustCompile(`^[a-z0-9.-]+\.[a-z]{2,}$`)

// shadowMain is `wtctl shadow datadog`: after dual-shipping to Datadog and Watchtower for a while, it says
// how many Datadog monitors fired at the same times as their imported Watchtower rule would have.
func shadowMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) < 1 || args[0] != "datadog" {
		return errors.New(shadowUsage)
	}
	fs := flag.NewFlagSet("shadow datadog", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var api, key, project, monitors, events, fromS, toS, outPrefix, keyEnv, appEnv, site string
	tol := fs.Duration("tolerance", 10*time.Minute, "")
	upload := fs.Bool("upload", false, "")
	fs.StringVar(&api, "api", apiEnv(), "")
	fs.StringVar(&key, "key", os.Getenv("WT_API_KEY"), "")
	fs.StringVar(&project, "project", os.Getenv("WT_PROJECT"), "")
	fs.StringVar(&monitors, "monitors", "", "")
	fs.StringVar(&events, "events", "", "")
	fs.StringVar(&fromS, "from", "", "")
	fs.StringVar(&toS, "to", "", "")
	fs.StringVar(&outPrefix, "out", "shadow-report", "")
	fs.StringVar(&keyEnv, "api-key-env", "DD_API_KEY", "")
	fs.StringVar(&appEnv, "app-key-env", "DD_APP_KEY", "")
	fs.StringVar(&site, "site", "datadoghq.com", "")
	if err := fs.Parse(args[1:]); err != nil {
		return fmt.Errorf("%w\n%s", err, shadowUsage)
	}
	if api == "" || key == "" || project == "" || monitors == "" || events == "" {
		return errors.New("--api, --key, --project, --monitors and --events are required\n" + shadowUsage)
	}
	to, from := time.Now().UTC().Truncate(time.Second), time.Time{}
	var err error
	if toS != "" {
		if to, err = time.Parse(time.RFC3339, toS); err != nil {
			return fmt.Errorf("--to: %w", err)
		}
	}
	from = to.Add(-14 * 24 * time.Hour)
	if fromS != "" {
		if from, err = time.Parse(time.RFC3339, fromS); err != nil {
			return fmt.Errorf("--from: %w", err)
		}
	}
	if !from.Before(to) || to.Sub(from) > 30*24*time.Hour {
		return errors.New("--from must be before --to, at most 30 days apart (the backtest limit); compare a longer shadow period in windows")
	}
	dd := &ddReader{hc: guardedClient(60 * time.Second), site: site}
	if monitors == "api" || events == "api" {
		if !ddSiteOK.MatchString(site) {
			return errors.New("--site is a Datadog site such as datadoghq.com or datadoghq.eu")
		}
		if dd.apiKey, dd.appKey = os.Getenv(keyEnv), os.Getenv(appEnv); dd.apiKey == "" || dd.appKey == "" {
			return fmt.Errorf("environment variables %s and %s must hold the Datadog keys", keyEnv, appEnv)
		}
	}
	var mons []ddMonitorRef
	if err := dd.load(ctx, monitors, "/api/v1/monitor", &mons); err != nil {
		return fmt.Errorf("monitors: %w", err)
	}
	evs, err := dd.events(ctx, events, from.Unix(), to.Unix())
	if err != nil {
		return fmt.Errorf("events: %w", err)
	}
	c, err := ascode.New(api, key, project, guardedClient(0))
	if err != nil {
		return err
	}
	rules, err := c.List(ctx, ascode.ByKind("AlertRule"))
	if err != nil {
		return fmt.Errorf("list alert rules: %w", err)
	}
	byMon := map[string][]ddEvent{}
	for _, e := range evs {
		byMon[e.MonitorID.String()] = append(byMon[e.MonitorID.String()], e)
	}
	var rows []shadowRow
	for _, m := range mons {
		id := m.ID.String()
		row := shadowRow{Monitor: m.Name, ID: id}
		it, ok := rules[m.Name]
		if !ok {
			it, ok = rules[m.Name+" ("+id+")"] // the importer's name for a duplicate
		}
		if !ok {
			row.Note = "no imported rule named " + m.Name + "; run wtctl import datadog first"
			rows = append(rows, row)
			continue
		}
		row.Rule = it.Name
		trs, note, err := backtestRule(ctx, c, it.Ref, from, to)
		if err != nil {
			return fmt.Errorf("backtest %s: %w", it.Name, err)
		}
		if note != "" {
			row.Note = note
			rows = append(rows, row)
			continue
		}
		wt, err := wtFirings(trs, from.Unix(), to.Unix())
		if err != nil {
			return err
		}
		rows = append(rows, compareFirings(row, ddFirings(byMon[id], from.Unix(), to.Unix()), wt, int64(tol.Seconds())))
	}
	rep := buildShadowReport(rows, from.Unix(), to.Unix(), int64(tol.Seconds()))
	rep.write(out)
	var md strings.Builder
	rep.write(&md)
	if err := os.WriteFile(outPrefix+".md", []byte(md.String()), 0o644); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	if err := os.WriteFile(outPrefix+".json", b, 0o644); err != nil {
		return err
	}
	if *upload { // the console's Datadog shadow screen reads the latest upload per window length
		if err := c.Do(ctx, http.MethodPost, "shadow/datadog", nil, rep.upload(), nil); err != nil {
			return fmt.Errorf("upload: %w", err)
		}
		fmt.Fprintln(out, "uploaded: the console's Datadog shadow screen shows this result")
	}
	return nil
}

// backtestRule replays a saved rule; a rule that cannot be replayed (composite, managed, quota) or whose
// replay was cut short comes back as a note instead of transitions.
func backtestRule(ctx context.Context, c *ascode.Client, id string, from, to time.Time) ([]shadowTransition, string, error) {
	var res struct {
		Transitions []shadowTransition `json:"transitions"`
		Incomplete  bool               `json:"incomplete"`
		ID          string             `json:"id"`
		Status      string             `json:"status"`
		Error       string             `json:"error"`
		Result      *struct {
			Transitions []shadowTransition `json:"transitions"`
			Incomplete  bool               `json:"incomplete"`
		} `json:"result"`
	}
	body := map[string]any{"rule_id": id, "from": from.Format(time.RFC3339), "to": to.Format(time.RFC3339)}
	if err := c.Do(ctx, http.MethodPost, "alert-rules:backtest", nil, body, &res); err != nil {
		if strings.Contains(err.Error(), "422") || strings.Contains(err.Error(), "429") {
			return nil, "the rule cannot be replayed: " + firstLine(err.Error()), nil
		}
		return nil, "", err
	}
	// a long replay is a job: poll it (every 2 s, at most 10 minutes)
	jobID := res.ID
	for i := 0; jobID != "" && res.Status == "in_progress"; i++ {
		if i > 300 {
			return nil, "the replay job did not finish in 10 minutes", nil
		}
		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		case <-time.After(2 * time.Second):
		}
		if err := c.Do(ctx, http.MethodGet, "alert-rules/backtest-jobs/"+url.PathEscape(jobID), nil, nil, &res); err != nil {
			return nil, "", err
		}
	}
	if res.Status == "failure" {
		return nil, "the replay failed: " + res.Error, nil
	}
	if res.Result != nil {
		res.Transitions, res.Incomplete = res.Result.Transitions, res.Result.Incomplete
	}
	if res.Incomplete {
		return nil, "the replay hit its deadline before the end of the period", nil
	}
	return res.Transitions, "", nil
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// ddReader reads Datadog inputs from a file or, for the word `api`, from the account with the user's own keys
// (read from the environment, sent only as request headers).
type ddReader struct {
	hc             *http.Client
	site           string
	apiKey, appKey string
}

func (d *ddReader) get(ctx context.Context, path string, q url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api."+d.site+path+"?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("DD-API-KEY", d.apiKey)
	req.Header.Set("DD-APPLICATION-KEY", d.appKey)
	resp, err := d.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("datadog %s: %s", path, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(out)
}

func (d *ddReader) load(ctx context.Context, src, path string, out any) error {
	if src == "api" {
		return d.get(ctx, path, url.Values{}, out)
	}
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// events reads monitor alert events: a file holds the array (or {"events": [...]}); `api` pages through
// GET /api/v1/events (1000 a page, at most 50 pages) and keeps the events that carry a monitor id.
func (d *ddReader) events(ctx context.Context, src string, from, to int64) ([]ddEvent, error) {
	var all []ddEvent
	if src != "api" {
		var w struct {
			Events []ddEvent `json:"events"`
		}
		b, err := os.ReadFile(src)
		if err != nil {
			return nil, err
		}
		if json.Unmarshal(b, &w) == nil && w.Events != nil {
			return w.Events, nil
		}
		return all, json.Unmarshal(b, &all)
	}
	for page := 0; page < 50; page++ {
		var res struct {
			Events []ddEvent `json:"events"`
		}
		q := url.Values{"start": {fmt.Sprint(from)}, "end": {fmt.Sprint(to)}, "unaggregated": {"true"}, "page": {fmt.Sprint(page)}}
		if err := d.get(ctx, "/api/v1/events", q, &res); err != nil {
			return nil, err
		}
		for _, e := range res.Events {
			if e.MonitorID.String() != "" {
				all = append(all, e)
			}
		}
		if len(res.Events) < 1000 {
			break
		}
	}
	return all, nil
}
