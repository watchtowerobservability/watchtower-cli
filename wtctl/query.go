package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

// Telemetry from the terminal (PLT-021): `wtctl query logs|traces|metrics` over the query API and
// `wtctl logs tail [--follow]` over the logs/tail SSE stream, as a table or JSON lines.

const queryUsage = `usage: wtctl query logs [--text t] [--services a,b] [--severities error,warn] [--since 1h] [--limit 100] [-o table|json]
       wtctl query traces '<TraceQL>' [--since 1h] [--limit 20] [-o table|json]
       wtctl query metrics '<PromQL>' [--since 1h] [--step 60s] [-o table|json]
       wtctl logs tail [--follow] [--text t] [--services a,b] [--severities error] [-o table|json]
       (--api --key --project, $WT_API $WT_API_KEY $WT_PROJECT, or a context from wtctl login)`

type queryOpts struct {
	api, key, project, output, text, services, severities string

	since time.Duration

	limit int
}

func (o *queryOpts) flags(fs *flag.FlagSet, limit int) {
	fs.StringVar(&o.api, "api", os.Getenv("WT_API"), "API base URL; default $WT_API")
	fs.StringVar(&o.key, "key", os.Getenv("WT_API_KEY"), "API key; default $WT_API_KEY")
	fs.StringVar(&o.project, "project", os.Getenv("WT_PROJECT"), "project id; default $WT_PROJECT")
	fs.StringVar(&o.output, "o", "table", "table or json (one JSON object per line)")
	fs.StringVar(&o.text, "text", "", "terms that must all occur in the log body")
	fs.StringVar(&o.services, "services", "", "comma-separated service names")
	fs.StringVar(&o.severities, "severities", "", "comma-separated severities")
	fs.DurationVar(&o.since, "since", time.Hour, "how far back")
	fs.IntVar(&o.limit, "limit", limit, "rows")
}

func (o *queryOpts) base() (string, error) {
	if o.api == "" || o.key == "" || o.project == "" {
		return "", errors.New("--api, --key and --project are required (or $WT_API, $WT_API_KEY, $WT_PROJECT, or wtctl login)")
	}
	if o.output != "table" && o.output != "json" {
		return "", errors.New("-o must be table or json")
	}
	return strings.TrimRight(o.api, "/") + "/v1/projects/" + url.PathEscape(o.project), nil
}

func queryMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(queryUsage)
	}
	var o queryOpts
	fs := flag.NewFlagSet("query "+args[0], flag.ContinueOnError)
	step := fs.Duration("step", time.Minute, "metrics resolution")
	limit := 100
	if args[0] == "traces" {
		limit = 20
	}
	o.flags(fs, limit)
	pos, err := parseInterleaved(fs, args[1:])
	if err != nil {
		return err
	}
	base, err := o.base()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	from := now.Add(-o.since).Format(time.RFC3339)
	switch args[0] {
	case "logs":
		q := url.Values{"from": {from}, "limit": {strconv.Itoa(o.limit)}}
		setIf(q, "text", o.text)
		setIf(q, "services", o.services)
		setIf(q, "severities", o.severities)
		var r struct {
			Data []map[string]any `json:"data"`
		}
		if err := call(ctx, http.MethodGet, base+"/logs/search?"+q.Encode(), o.key, nil, &r); err != nil {
			return err
		}
		return printLogs(out, o.output, r.Data)
	case "traces":
		if len(pos) != 1 {
			return errors.New(queryUsage)
		}
		var r struct {
			Traces []map[string]any `json:"traces"`
		}
		body := map[string]any{"q": pos[0], "from": from, "limit": o.limit}
		if err := call(ctx, http.MethodPost, base+"/query/traces", o.key, body, &r); err != nil {
			return err
		}
		return printRows(out, o.output, r.Traces, []string{"trace_id", "matched_span_count"})
	case "metrics":
		if len(pos) != 1 {
			return errors.New(queryUsage)
		}
		q := url.Values{"query": {pos[0]}, "start": {from}, "end": {now.Format(time.RFC3339)}, "step": {strconv.Itoa(int(step.Seconds()))}}
		var r struct {
			Data struct {
				Result []struct {
					Metric map[string]string `json:"metric"`
					Values [][2]any          `json:"values"`
				} `json:"result"`
			} `json:"data"`
		}
		if err := call(ctx, http.MethodGet, base+"/prometheus/api/v1/query_range?"+q.Encode(), o.key, nil, &r); err != nil {
			return err
		}
		rows := make([]map[string]any, 0)
		for _, s := range r.Data.Result {
			for _, v := range s.Values {
				ts, _ := v[0].(float64)
				rows = append(rows, map[string]any{"series": seriesName(s.Metric), "time": time.Unix(int64(ts), 0).UTC().Format(time.RFC3339), "value": v[1]})
			}
		}
		return printRows(out, o.output, rows, []string{"series", "time", "value"})
	}
	return errors.New(queryUsage)
}

func setIf(q url.Values, k, v string) {
	if v != "" {
		q.Set(k, v)
	}
}

// seriesName prints labels Prometheus-style: name{a="b",...}.
func seriesName(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		if k != "__name__" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s=%q", k, m[k])
	}
	return m["__name__"] + "{" + strings.Join(parts, ",") + "}"
}

func printLogs(out io.Writer, format string, rows []map[string]any) error {
	for _, r := range rows {
		if ns, ok := r["ts_ns"].(float64); ok {
			r["time"] = time.Unix(0, int64(ns)).UTC().Format(time.RFC3339Nano)
		}
	}
	return printRows(out, format, rows, []string{"time", "service", "severity_text", "body"})
}

// printRows writes JSON lines, or a table of cols (cells cut at 200 characters, no newlines).
func printRows(out io.Writer, format string, rows []map[string]any, cols []string) error {
	if format == "json" {
		enc := json.NewEncoder(out)
		for _, r := range rows {
			if err := enc.Encode(r); err != nil {
				return err
			}
		}
		return nil
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, strings.ToUpper(strings.Join(cols, "\t")))
	for _, r := range rows {
		cells := make([]string, len(cols))
		for i, c := range cols {
			s := strings.NewReplacer("\n", " ", "\t", " ").Replace(fmt.Sprint(valueOr(r[c])))
			if len(s) > 200 {
				s = s[:200] + "…"
			}
			cells[i] = s
		}
		fmt.Fprintln(tw, strings.Join(cells, "\t"))
	}
	return tw.Flush()
}

func valueOr(v any) any {
	if v == nil {
		return ""
	}
	return v
}

func logsMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "tail" {
		return errors.New(queryUsage)
	}
	var o queryOpts
	fs := flag.NewFlagSet("logs tail", flag.ContinueOnError)
	follow := fs.Bool("follow", false, "stream new logs until interrupted")
	fs.BoolVar(follow, "f", false, "short for --follow")
	o.flags(fs, 50)
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	base, err := o.base()
	if err != nil {
		return err
	}
	if !*follow {
		return queryMain(ctx, []string{"logs", "--limit", strconv.Itoa(o.limit), "--since", o.since.String(), "-o", o.output,
			"--text", o.text, "--services", o.services, "--severities", o.severities,
			"--api", o.api, "--key", o.key, "--project", o.project}, out)
	}
	q := url.Values{}
	setIf(q, "text", o.text)
	setIf(q, "services", o.services)
	setIf(q, "severities", o.severities)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/logs/tail?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+o.key)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := guardedClient(0).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("logs tail: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return followSSE(resp.Body, o.output, out)
}

// followSSE prints each `log` event as it arrives; `end` and `error` events stop the stream.
func followSSE(body io.Reader, format string, out io.Writer) error {
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	event, data := "", ""
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			data += strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " ")
		case line == "":
			switch event {
			case "log":
				var r map[string]any
				if err := json.Unmarshal([]byte(data), &r); err == nil {
					if format == "json" {
						fmt.Fprintln(out, data)
					} else if err := printLogLine(out, r); err != nil {
						return err
					}
				}
			case "end":
				return nil
			case "error":
				return errors.New("logs tail: " + data)
			}
			event, data = "", ""
		}
	}
	return sc.Err()
}

func printLogLine(out io.Writer, r map[string]any) error {
	ts := ""
	if ns, ok := r["ts_ns"].(float64); ok {
		ts = time.Unix(0, int64(ns)).UTC().Format(time.RFC3339Nano)
	}
	_, err := fmt.Fprintf(out, "%s %s [%v] %v\n", ts, valueOr(r["service"]), valueOr(r["severity_text"]), valueOr(r["body"]))
	return err
}
