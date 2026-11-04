package tsdb

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-cli/pluginsdk"
)

// FluxRequest is the InfluxDB 2 query request for org: the path and its JSON body. The range goes
// where the author writes v.timeRangeStart and v.timeRangeStop, as in Grafana.
func FluxRequest(org, flux string, from, to time.Time) (string, []byte, error) {
	q := strings.NewReplacer(
		"v.timeRangeStart", from.UTC().Format(time.RFC3339),
		"v.timeRangeStop", to.UTC().Format(time.RFC3339),
	).Replace(flux)
	body, err := json.Marshal(map[string]any{
		"query": q, "type": "flux",
		"dialect": map[string]any{"header": true, "annotations": []string{}, "delimiter": ","},
	})
	return "/api/v2/query?" + url.Values{"org": {org}}.Encode(), body, err
}

// ParseFlux reads an InfluxDB 2 CSV answer: one series per result table, named by its
// _measurement and _field with the other non-underscore columns as labels.
func ParseFlux(b []byte) (pluginsdk.Frames, error) {
	out := pluginsdk.Frames{Frames: []pluginsdk.Frame{}}
	r := csv.NewReader(bytes.NewReader(b))
	r.FieldsPerRecord = -1 // a new header starts every result block
	var head []string
	col := map[string]int{}
	byTable := map[string]int{} // table key -> index in out.Frames
	pts := map[int][]point{}
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return pluginsdk.Frames{}, fmt.Errorf("influxdb answer: %w", err)
		}
		// encoding/csv drops the blank lines between result blocks, so headers are found by content.
		if head == nil || isHeader(rec) {
			head, col = rec, map[string]int{}
			for i, h := range rec {
				col[h] = i
			}
			continue
		}
		if i, ok := col["error"]; ok && i < len(rec) && rec[i] != "" {
			return pluginsdk.Frames{}, errors.New(rec[i])
		}
		ti, okT := col["_time"]
		vi, okV := col["_value"]
		if !okT || !okV || ti >= len(rec) || vi >= len(rec) {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, rec[ti])
		if err != nil {
			continue
		}
		v, err := strconv.ParseFloat(rec[vi], 64)
		if err != nil {
			continue // a string or boolean field is not a series
		}
		tags := map[string]string{}
		for i, h := range head {
			if i < len(rec) && h != "" && !strings.HasPrefix(h, "_") && h != "result" && h != "table" {
				tags[h] = rec[i]
			}
		}
		name := cell(rec, col, "_measurement") + "." + cell(rec, col, "_field")
		key := labelled(name, tags)
		idx, ok := byTable[key]
		if !ok {
			idx = len(out.Frames)
			byTable[key] = idx
			out.Frames = append(out.Frames, pluginsdk.Frame{Name: key})
		}
		pts[idx] = append(pts[idx], point{at, v})
	}
	for i := range out.Frames {
		out.Frames[i] = series(out.Frames[i].Name, pts[i])
	}
	return out, nil
}

func isHeader(rec []string) bool {
	has := func(w string) bool {
		for _, c := range rec {
			if c == w {
				return true
			}
		}
		return false
	}
	return (has("result") && has("table")) || (len(rec) > 0 && rec[0] == "error")
}

func cell(rec []string, col map[string]int, name string) string {
	if i, ok := col[name]; ok && i < len(rec) {
		return rec[i]
	}
	return ""
}
