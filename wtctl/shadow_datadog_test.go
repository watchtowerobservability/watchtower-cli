package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const (
	t0 = int64(1767225600) // 2026-01-01T00:00:00Z
	hr = int64(3600)
)

func ts(s int64) string { return time.Unix(s, 0).UTC().Format(time.RFC3339) }

func evs(t *testing.T, raw string) []ddEvent {
	t.Helper()
	var out []ddEvent
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDDFiringsPerGroupMergedAndOpenEnded(t *testing.T) {
	e := evs(t, `[
	 {"date_happened": 1767229200, "alert_type": "error",   "title": "[Triggered on {host:a}] CPU", "monitor_id": 1},
	 {"date_happened": 1767230000, "alert_type": "warning", "title": "[Triggered on {host:b}] CPU", "monitor_id": 1},
	 {"date_happened": 1767232800, "alert_type": "success", "title": "[Recovered on {host:a}] CPU", "monitor_id": 1},
	 {"date_happened": 1767234000, "alert_type": "success", "title": "[Recovered on {host:b}] CPU", "monitor_id": 1},
	 {"date_happened": 1767300000, "alert_type": "warning", "title": "[No Data on {host:a}] CPU", "monitor_id": 1},
	 {"date_happened": 1767310000, "alert_type": "error",   "title": "[Triggered on {host:a}] CPU", "monitor_id": 1}]`)
	got := ddFirings(e, t0, t0+100*hr)
	if len(got) != 2 || got[0] != (interval{1767229200, 1767234000}) || got[1].Start != 1767310000 || got[1].End != t0+100*hr {
		t.Fatalf("firings = %+v (groups a and b overlap and merge; No Data is ignored; the last one is open to the end)", got)
	}
}

func TestWTFiringsFromBacktestTransitions(t *testing.T) {
	trs := []shadowTransition{
		{ts(t0 + hr), "pending"}, {ts(t0 + 2*hr), "firing"}, {ts(t0 + 3*hr), "recovering"},
		{ts(t0 + 4*hr), "inactive"}, {ts(t0 + 5*hr), "firing"},
	}
	got, err := wtFirings(trs, t0, t0+6*hr)
	if err != nil || len(got) != 2 || got[0] != (interval{t0 + 2*hr, t0 + 3*hr}) || got[1] != (interval{t0 + 5*hr, t0 + 6*hr}) {
		t.Fatalf("firings = %+v, %v", got, err)
	}
}

func TestUnmatchedUsesTolerance(t *testing.T) {
	a := []interval{{1000, 2000}, {5000, 6000}}
	b := []interval{{2300, 2500}}
	if got := unmatched(a, b, 600); len(got) != 1 || got[0].Start != 5000 {
		t.Fatalf("within 10 minutes the first firing matches: %+v", got)
	}
	if got := unmatched(a, b, 0); len(got) != 2 {
		t.Fatalf("without tolerance nothing matches: %+v", got)
	}
}

// The fixture: five Datadog monitors against what the Watchtower backtests found.
func TestShadowReportSaysWhichMonitorsDiffer(t *testing.T) {
	tol := int64(600)
	from, to := t0, t0+14*24*hr
	fire := func(s, e int64) []interval { return []interval{{t0 + s*hr, t0 + e*hr}} }
	rows := []shadowRow{
		compareFirings(shadowRow{Monitor: "High CPU", ID: "1"}, fire(10, 12), fire(10, 12), tol),                                 // same
		compareFirings(shadowRow{Monitor: "Disk full", ID: "2"}, fire(20, 21), nil, tol),                                         // Datadog only
		compareFirings(shadowRow{Monitor: "Web errors", ID: "3"}, nil, fire(30, 31), tol),                                        // Watchtower only
		compareFirings(shadowRow{Monitor: "Quiet", ID: "4"}, nil, nil, tol),                                                      // nothing in either
		{Monitor: "Checkout journey", ID: "5", Note: "no imported rule named Checkout journey; run wtctl import datadog first"},  // synthetics
		compareFirings(shadowRow{Monitor: "Slow start", ID: "6"}, fire(40, 41), []interval{{t0 + 40*hr + 300, t0 + 41*hr}}, tol), // 5 min late: within tolerance
	}
	r := buildShadowReport(rows, from, to, tol)
	if r.Same != 3 || r.QuietInBoth != 1 || len(r.Differ) != 2 || r.NotCompared != 1 || r.Compared != 5 {
		t.Fatalf("report = same %d quiet %d differ %d not compared %d compared %d", r.Same, r.QuietInBoth, len(r.Differ), r.NotCompared, r.Compared)
	}
	var md bytes.Buffer
	r.write(&md)
	out := md.String()
	if !strings.Contains(out, "**3 of 6 monitors fired at the same times as Datadog**; here are the 3 that differ.") {
		t.Fatalf("headline missing:\n%s", out)
	}
	if !strings.Contains(out, "| Disk full | 1 | 0 | 2026-01-01 20:00 to 2026-01-01 21:00 | - |") ||
		!strings.Contains(out, "| Web errors | 0 | 1 | - | 2026-01-02 06:00 to 2026-01-02 07:00 |") ||
		!strings.Contains(out, "| Checkout journey | no imported rule named Checkout journey; run wtctl import datadog first |") {
		t.Fatalf("differing monitors not listed:\n%s", out)
	}
	if strings.Contains(out, "| High CPU |") || strings.Contains(out, "| Slow start |") {
		t.Fatalf("an agreeing monitor is listed as differing:\n%s", out)
	}
}

func TestUploadMatchesTheConsoleShape(t *testing.T) {
	tol := int64(600)
	rows := []shadowRow{
		compareFirings(shadowRow{Monitor: "A", ID: "1"}, []interval{{t0, t0 + hr}, {t0 + 5*hr, t0 + 6*hr}}, []interval{{t0, t0 + hr}}, tol),
		compareFirings(shadowRow{Monitor: "B", ID: "2"}, nil, nil, tol),
		{Monitor: "C", ID: "3", Note: "no imported rule"},
	}
	up := buildShadowReport(rows, t0, t0+14*24*hr, tol).upload()
	if up["window_days"] != 14 {
		t.Fatalf("window_days = %v", up["window_days"])
	}
	d := up["data"].([]map[string]any)
	if d[0]["status"] != "differs" || d[0]["datadog_fires"] != 2 || d[0]["watchtower_fires"] != 1 || d[0]["matched_fires"] != 1 ||
		d[1]["status"] != "match" || d[2]["status"] != "no_data" || d[2]["note"] != "no imported rule" {
		t.Fatalf("upload rows = %v", d)
	}
}
