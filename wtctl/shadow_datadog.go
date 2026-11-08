package main

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Datadog shadow mode (D1): Datadog and Watchtower both receive the data for a while; this compares when each
// monitor fired in Datadog with when its imported Watchtower rule would have fired over the same data (the
// rule backtest). Pure logic here; shadow_cmd.go fetches the inputs.

// interval is a firing period in unix seconds, [start, end).
type interval struct{ Start, End int64 }

// ddEvent is the part of a Datadog monitor alert event (GET /api/v1/events) the comparison reads.
// shortcut: the shape follows the documented events API (monitor_id, alert_type, "[Triggered on {group}]"
// titles) and was not run against a live account; the user can also pass an export file.
type ddEvent struct {
	DateHappened int64       `json:"date_happened"`
	AlertType    string      `json:"alert_type"`
	Title        string      `json:"title"`
	MonitorID    json.Number `json:"monitor_id"`
}

// ddMonitorRef names a Datadog monitor.
type ddMonitorRef struct {
	ID   json.Number `json:"id"`
	Name string      `json:"name"`
}

var ddGroupRe = regexp.MustCompile(`\{([^}]*)\}`)

// ddFirings turns a monitor's events into the periods it was alerting: per group (host, service, ...) it
// opens on an error or warning event and closes on a success one; the periods of all groups are merged. A
// period still open at `to` ends there. "No Data" events are not firings.
func ddFirings(events []ddEvent, from, to int64) []interval {
	sort.SliceStable(events, func(i, j int) bool { return events[i].DateHappened < events[j].DateHappened })
	open := map[string]int64{}
	var out []interval
	for _, e := range events {
		if strings.Contains(strings.ToLower(e.Title), "no data") {
			continue
		}
		g := ""
		if m := ddGroupRe.FindStringSubmatch(e.Title); m != nil {
			g = m[1]
		}
		switch e.AlertType {
		case "error", "warning":
			if _, on := open[g]; !on {
				open[g] = e.DateHappened
			}
		case "success":
			if s, on := open[g]; on {
				out = append(out, interval{s, e.DateHappened})
				delete(open, g)
			}
		}
	}
	for _, s := range open {
		out = append(out, interval{s, to})
	}
	return mergeIntervals(clip(out, from, to))
}

// wtFirings turns a backtest's state transitions into firing periods: from `firing` to the next state that
// is not firing (recovering counts as ended: the condition cleared).
func wtFirings(trs []shadowTransition, from, to int64) ([]interval, error) {
	var out []interval
	start := int64(-1)
	for _, t := range trs {
		at, err := time.Parse(time.RFC3339, t.At)
		if err != nil {
			return nil, fmt.Errorf("backtest transition time %q: %w", t.At, err)
		}
		switch {
		case t.State == "firing" && start < 0:
			start = at.Unix()
		case t.State != "firing" && start >= 0:
			out = append(out, interval{start, at.Unix()})
			start = -1
		}
	}
	if start >= 0 {
		out = append(out, interval{start, to})
	}
	return mergeIntervals(clip(out, from, to)), nil
}

type shadowTransition struct {
	At    string `json:"at"`
	State string `json:"state"`
}

func clip(in []interval, from, to int64) []interval {
	var out []interval
	for _, v := range in {
		v.Start, v.End = max(v.Start, from), min(v.End, to)
		if v.End > v.Start {
			out = append(out, v)
		}
	}
	return out
}

func mergeIntervals(in []interval) []interval {
	sort.Slice(in, func(i, j int) bool { return in[i].Start < in[j].Start })
	var out []interval
	for _, v := range in {
		if n := len(out); n > 0 && v.Start <= out[n-1].End {
			out[n-1].End = max(out[n-1].End, v.End)
			continue
		}
		out = append(out, v)
	}
	return out
}

// unmatched returns the periods of a that no period of b overlaps once b is widened by tol seconds each side.
func unmatched(a, b []interval, tol int64) []interval {
	var out []interval
	for _, x := range a {
		hit := false
		for _, y := range b {
			if x.Start < y.End+tol && y.Start-tol < x.End {
				hit = true
				break
			}
		}
		if !hit {
			out = append(out, x)
		}
	}
	return out
}

// shadowRow is one monitor's comparison.
type shadowRow struct {
	Monitor string     `json:"monitor"`
	ID      string     `json:"datadog_id"`
	Rule    string     `json:"rule,omitempty"`
	DD      int        `json:"datadog_firings"`
	WT      int        `json:"watchtower_firings"`
	Missed  []interval `json:"missed,omitempty"` // Datadog fired, Watchtower did not
	Extra   []interval `json:"extra,omitempty"`  // Watchtower fired, Datadog did not
	Note    string     `json:"note,omitempty"`   // why there is no comparison
}

func (r shadowRow) same() bool { return r.Note == "" && len(r.Missed) == 0 && len(r.Extra) == 0 }

// shadowReport is the divergence report.
type shadowReport struct {
	From, To     string
	WindowDays   int
	ToleranceS   int64
	Rows         []shadowRow
	Compared     int // monitors with a comparison
	Same         int
	QuietInBoth  int // of Same: neither fired in the period
	NotCompared  int // no imported rule, or the rule cannot be replayed
	Differ       []shadowRow
	NotComparedR []shadowRow
}

// buildShadowReport sorts the rows into those that agree, differ and could not be compared.
func buildShadowReport(rows []shadowRow, from, to int64, tolS int64) shadowReport {
	r := shadowReport{From: time.Unix(from, 0).UTC().Format(time.RFC3339), To: time.Unix(to, 0).UTC().Format(time.RFC3339), ToleranceS: tolS, Rows: rows,
		WindowDays: min(30, max(1, int((to-from+43200)/86400)))}
	for _, row := range rows {
		switch {
		case row.Note != "":
			r.NotComparedR = append(r.NotComparedR, row)
			r.NotCompared++
		case row.same():
			r.Compared++
			r.Same++
			if row.DD == 0 && row.WT == 0 {
				r.QuietInBoth++
			}
		default:
			r.Compared++
			r.Differ = append(r.Differ, row)
		}
	}
	return r
}

// compareFirings fills a row from the two firing lists.
func compareFirings(row shadowRow, dd, wt []interval, tolS int64) shadowRow {
	row.DD, row.WT = len(dd), len(wt)
	row.Missed, row.Extra = unmatched(dd, wt, tolS), unmatched(wt, dd, tolS)
	return row
}

func fmtSpan(v interval) string {
	f := func(s int64) string { return time.Unix(s, 0).UTC().Format("2006-01-02 15:04") }
	return f(v.Start) + " to " + f(v.End)
}

// write renders the report as Markdown: the headline first, then the monitors that differ.
func (r shadowReport) write(w io.Writer) {
	total := r.Compared + r.NotCompared
	fmt.Fprintf(w, "# Datadog shadow report\n\n%s to %s (a firing matches when it starts within %d minutes)\n\n", r.From, r.To, r.ToleranceS/60)
	fmt.Fprintf(w, "**%d of %d monitors fired at the same times as Datadog**", r.Same, total)
	if n := len(r.Differ) + r.NotCompared; n > 0 {
		fmt.Fprintf(w, "; here are the %d that differ", n)
	}
	fmt.Fprintf(w, ".\n\n- Agree: %d (%d of them fired in neither)\n- Differ: %d\n- Not compared: %d\n", r.Same, r.QuietInBoth, len(r.Differ), r.NotCompared)
	if len(r.Differ) > 0 {
		fmt.Fprint(w, "\n## Monitors that differ\n\n| Monitor | Datadog | Watchtower | Datadog only | Watchtower only |\n|---|---|---|---|---|\n")
		for _, d := range r.Differ {
			fmt.Fprintf(w, "| %s | %d | %d | %s | %s |\n", mdCell(d.Monitor), d.DD, d.WT, spans(d.Missed), spans(d.Extra))
		}
	}
	if len(r.NotComparedR) > 0 {
		fmt.Fprint(w, "\n## Not compared\n\n| Monitor | Why |\n|---|---|\n")
		for _, d := range r.NotComparedR {
			fmt.Fprintf(w, "| %s | %s |\n", mdCell(d.Monitor), mdCell(d.Note))
		}
	}
}

func mdCell(s string) string { return strings.ReplaceAll(s, "|", "/") }

func spans(in []interval) string {
	if len(in) == 0 {
		return "-"
	}
	var parts []string
	for i, v := range in {
		if i == 5 {
			parts = append(parts, fmt.Sprintf("and %d more", len(in)-5))
			break
		}
		parts = append(parts, fmtSpan(v))
	}
	return strings.Join(parts, "; ")
}

// upload is the body of POST /v1/projects/{prj}/shadow/datadog, the shape the console screen reads.
func (r shadowReport) upload() map[string]any {
	data := make([]map[string]any, 0, len(r.Rows))
	for _, row := range r.Rows {
		status, note := "match", row.Note
		switch {
		case row.Note != "":
			status = "no_data"
		case !row.same():
			status = "differs"
			note = fmt.Sprintf("%d Datadog-only and %d Watchtower-only firings", len(row.Missed), len(row.Extra))
		}
		m := map[string]any{
			"monitor_id": row.ID, "name": row.Monitor, "datadog_fires": row.DD, "watchtower_fires": row.WT,
			"matched_fires": max(0, row.DD-len(row.Missed)), "status": status,
		}
		if note != "" {
			m["note"] = note
		}
		data = append(data, m)
	}
	return map[string]any{"window_days": r.WindowDays, "data": data}
}
