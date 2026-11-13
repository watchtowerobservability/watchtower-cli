package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Span search and annotation from the terminal (SDK-006, Phoenix `px` parity):
// `wtctl spans search` filters spans by name, kind, status, service, duration and any KQL
// condition through the pipe search API; `wtctl spans annotate` stores a human score on a span
// (`POST /llm/scores`, shown with the trace and in the LLM views).

const spansUsage = `usage: wtctl spans search [--name n] [--kind server|client|internal|producer|consumer] [--status ok|error|unset]
                         [--services a,b] [--min-duration 500ms] [--where '<KQL>'] [--since 1h] [--limit 50] [-o table|json]
       wtctl spans annotate <trace_id> <span_id> --name <score name> --value <number|true|false|label> [--comment text]
       (--api --key --project, $WT_API_URL $WT_API_KEY $WT_PROJECT, or a context from wtctl login)`

var spanKinds = map[string]int{"internal": 1, "server": 2, "client": 3, "producer": 4, "consumer": 5}
var spanStatuses = map[string]int{"unset": 0, "ok": 1, "error": 2}

func kqlString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

type spanFilter struct {
	name, kind, status, services, where string
	minDuration                         time.Duration
	limit                               int
}

// pipeQuery builds `spans | where ... | sort -start_ns | limit n`.
func (f spanFilter) pipeQuery() (string, error) {
	var conds []string
	if f.name != "" {
		conds = append(conds, "name == "+kqlString(f.name))
	}
	if f.kind != "" {
		k, ok := spanKinds[strings.ToLower(f.kind)]
		if !ok {
			return "", errors.New("--kind must be one of internal, server, client, producer, consumer")
		}
		conds = append(conds, "kind == "+strconv.Itoa(k))
	}
	if f.status != "" {
		s, ok := spanStatuses[strings.ToLower(f.status)]
		if !ok {
			return "", errors.New("--status must be ok, error or unset")
		}
		conds = append(conds, "status_code == "+strconv.Itoa(s))
	}
	if f.services != "" {
		var or []string
		for _, s := range strings.Split(f.services, ",") {
			if s = strings.TrimSpace(s); s != "" {
				or = append(or, "service == "+kqlString(s))
			}
		}
		if len(or) > 0 {
			conds = append(conds, "("+strings.Join(or, " or ")+")")
		}
	}
	if f.minDuration > 0 {
		conds = append(conds, "duration_ns >= "+strconv.FormatInt(f.minDuration.Nanoseconds(), 10))
	}
	if w := strings.TrimSpace(f.where); w != "" {
		conds = append(conds, "("+w+")")
	}
	if f.limit < 1 || f.limit > 10000 {
		return "", errors.New("--limit must be 1 to 10000")
	}
	q := "spans"
	if len(conds) > 0 {
		q += " | where " + strings.Join(conds, " and ")
	}
	return q + " | sort -start_ns | limit " + strconv.Itoa(f.limit), nil
}

func spansMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(spansUsage)
	}
	switch args[0] {
	case "search":
		return spansSearch(ctx, args[1:], out)
	case "annotate":
		return spansAnnotate(ctx, args[1:], out)
	}
	return errors.New(spansUsage)
}

func spansSearch(ctx context.Context, args []string, out io.Writer) error {
	var o queryOpts
	var f spanFilter
	fs := flag.NewFlagSet("spans search", flag.ContinueOnError)
	o.flags(fs, 50)
	fs.StringVar(&f.name, "name", "", "span name")
	fs.StringVar(&f.kind, "kind", "", "span kind")
	fs.StringVar(&f.status, "status", "", "span status")
	fs.StringVar(&f.where, "where", "", "extra KQL condition, e.g. attrs.http.route == \"/cart\"")
	fs.DurationVar(&f.minDuration, "min-duration", 0, "only spans at least this long")
	if _, err := parseInterleaved(fs, args); err != nil {
		return err
	}
	f.services, f.limit = o.services, o.limit
	base, err := o.base()
	if err != nil {
		return err
	}
	q, err := f.pipeQuery()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	body := map[string]any{"language": "pipe", "q": q, "from": now.Add(-o.since).Format(time.RFC3339), "to": now.Format(time.RFC3339)}
	var r struct {
		Columns []string `json:"columns"`
		Data    [][]any  `json:"data"`
	}
	if err := call(ctx, http.MethodPost, base+"/query/search", o.key, body, &r); err != nil {
		return err
	}
	rows := make([]map[string]any, 0, len(r.Data))
	for _, d := range r.Data {
		row := map[string]any{}
		for i, c := range r.Columns {
			if i < len(d) {
				row[c] = d[i]
			}
		}
		rows = append(rows, row)
	}
	return printRows(out, o.output, rows, []string{"start", "service", "name", "duration_ns", "status_code", "trace_id", "span_id"})
}

// scoreValue reads a number, a boolean or else a category label, as the scores API takes them.
func scoreValue(s string) any {
	if s == "true" || s == "false" {
		return s == "true"
	}
	if n, err := strconv.ParseFloat(s, 64); err == nil {
		return n
	}
	return s
}

func spansAnnotate(ctx context.Context, args []string, out io.Writer) error {
	var o queryOpts
	fs := flag.NewFlagSet("spans annotate", flag.ContinueOnError)
	o.flags(fs, 1)
	name := fs.String("name", "", "score name, e.g. correctness")
	value := fs.String("value", "", "number, true/false or a short label")
	comment := fs.String("comment", "", "explanation")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 2 || *name == "" || *value == "" {
		return errors.New(spansUsage)
	}
	base, err := o.base()
	if err != nil {
		return err
	}
	body := map[string]any{"trace_id": pos[0], "span_id": pos[1], "name": *name, "value": scoreValue(*value), "source": "human"}
	if *comment != "" {
		body["comment"] = *comment
	}
	var r map[string]any
	if err := call(ctx, http.MethodPost, base+"/llm/scores", o.key, body, &r); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "annotated %s/%s: %s = %s\n", pos[0], pos[1], *name, *value)
	return err
}
