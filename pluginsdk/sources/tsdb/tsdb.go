// Package tsdb has the query paths of the InfluxDB, Graphite and OpenTSDB source plugins: each builds
// its request, and turns the answer into time series frames. A panel's query text is
// "<host>|<query>"; the plugin calls the host through the runner's egress proxy, which only reaches
// the manifest's egress_hosts and adds any credentials, so the plugin never sees them.
package tsdb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-cli/pluginsdk"
)

const maxBody = 32 << 20

var hostRE = regexp.MustCompile(`^[a-zA-Z0-9.-]+(:[0-9]+)?$`)

// Split parses "<host>|<query>".
func Split(text string) (host, query string, err error) {
	host, query, ok := strings.Cut(text, "|")
	host, query = strings.TrimSpace(host), strings.TrimSpace(query)
	if !ok || query == "" || !hostRE.MatchString(host) {
		return "", "", errors.New(`the query must be "<host>|<query>"`)
	}
	return host, query, nil
}

// Get fetches path (with its query string) from host over https, through the egress proxy.
func Get(ctx context.Context, host, path string) ([]byte, error) {
	return send(ctx, http.MethodGet, host, path, "", nil)
}

// Post sends body of contentType to path on host over https, through the egress proxy.
func Post(ctx context.Context, host, path, contentType string, body []byte) ([]byte, error) {
	return send(ctx, http.MethodPost, host, path, contentType, body)
}

func send(ctx context.Context, method, host, path, contentType string, body []byte) ([]byte, error) {
	base := os.Getenv("WT_EGRESS_URL")
	if base == "" {
		return nil, errors.New("WT_EGRESS_URL is not set")
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(base, "/")+"/https/"+url.PathEscape(host)+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %d", host, res.StatusCode)
	}
	return b, nil
}

// point is one sample.
type point struct {
	at time.Time
	v  float64
}

func series(name string, pts []point) pluginsdk.Frame {
	sort.Slice(pts, func(i, j int) bool { return pts[i].at.Before(pts[j].at) })
	ts, vs := make([]any, 0, len(pts)), make([]any, 0, len(pts))
	for _, p := range pts {
		ts = append(ts, p.at.UTC().Format(time.RFC3339))
		vs = append(vs, p.v)
	}
	return pluginsdk.Frame{Name: name, Kind: pluginsdk.FrameTimeSeries,
		Fields: []pluginsdk.Field{{Name: "time", Values: ts}, {Name: "value", Values: vs}}}
}

func labelled(name string, tags map[string]string) string {
	if len(tags) == 0 {
		return name
	}
	parts := make([]string, 0, len(tags))
	for k, v := range tags {
		parts = append(parts, k+"="+strconv.Quote(v))
	}
	sort.Strings(parts)
	return name + "{" + strings.Join(parts, ",") + "}"
}

// GraphitePath is the render request of a target over a range.
func GraphitePath(target string, from, to time.Time) string {
	q := url.Values{"target": {target}, "format": {"json"},
		"from": {strconv.FormatInt(from.Unix(), 10)}, "until": {strconv.FormatInt(to.Unix(), 10)}}
	return "/render?" + q.Encode()
}

// ParseGraphite reads a render answer: [{target, datapoints: [[value|null, unix]]}].
func ParseGraphite(b []byte) (pluginsdk.Frames, error) {
	var in []struct {
		Target     string        `json:"target"`
		Datapoints [][2]*float64 `json:"datapoints"`
	}
	if err := json.Unmarshal(b, &in); err != nil {
		return pluginsdk.Frames{}, fmt.Errorf("graphite answer: %w", err)
	}
	out := pluginsdk.Frames{Frames: []pluginsdk.Frame{}}
	for _, s := range in {
		pts := make([]point, 0, len(s.Datapoints))
		for _, d := range s.Datapoints {
			if d[0] != nil && d[1] != nil {
				pts = append(pts, point{time.Unix(int64(*d[1]), 0), *d[0]})
			}
		}
		out.Frames = append(out.Frames, series(s.Target, pts))
	}
	return out, nil
}

// InfluxPath is the InfluxQL query request, with times in seconds. db is "" when the statement
// names its database. The range goes in the statement's own WHERE, which the author writes with
// $timeFilter, replaced here.
func InfluxPath(db, influxql string, from, to time.Time) string {
	filter := fmt.Sprintf("time >= %ds AND time < %ds", from.Unix(), to.Unix())
	q := url.Values{"q": {strings.ReplaceAll(influxql, "$timeFilter", filter)}, "epoch": {"s"}}
	if db != "" {
		q.Set("db", db)
	}
	return "/query?" + q.Encode()
}

// ParseInflux reads a v1 query answer. Every column after time becomes a series.
func ParseInflux(b []byte) (pluginsdk.Frames, error) {
	var in struct {
		Results []struct {
			Error  string `json:"error"`
			Series []struct {
				Name    string            `json:"name"`
				Tags    map[string]string `json:"tags"`
				Columns []string          `json:"columns"`
				Values  [][]*float64      `json:"values"`
			} `json:"series"`
		} `json:"results"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(b, &in); err != nil {
		return pluginsdk.Frames{}, fmt.Errorf("influxdb answer: %w", err)
	}
	if in.Error != "" {
		return pluginsdk.Frames{}, errors.New(in.Error)
	}
	out := pluginsdk.Frames{Frames: []pluginsdk.Frame{}}
	for _, r := range in.Results {
		if r.Error != "" {
			return pluginsdk.Frames{}, errors.New(r.Error)
		}
		for _, s := range r.Series {
			for c := 1; c < len(s.Columns); c++ {
				pts := make([]point, 0, len(s.Values))
				for _, row := range s.Values {
					if c < len(row) && row[0] != nil && row[c] != nil {
						pts = append(pts, point{time.Unix(int64(*row[0]), 0), *row[c]})
					}
				}
				out.Frames = append(out.Frames, series(labelled(s.Name+"."+s.Columns[c], s.Tags), pts))
			}
		}
	}
	return out, nil
}

// OpenTSDBPath is the query request; m is OpenTSDB's own form, such as sum:sys.cpu{host=a}.
func OpenTSDBPath(m string, from, to time.Time) string {
	q := url.Values{"m": {m}, "start": {strconv.FormatInt(from.Unix(), 10)}, "end": {strconv.FormatInt(to.Unix(), 10)}}
	return "/api/query?" + q.Encode()
}

// ParseOpenTSDB reads a query answer: [{metric, tags, dps: {"unix": value}}].
func ParseOpenTSDB(b []byte) (pluginsdk.Frames, error) {
	var in []struct {
		Metric string              `json:"metric"`
		Tags   map[string]string   `json:"tags"`
		DPS    map[string]*float64 `json:"dps"`
	}
	if err := json.Unmarshal(b, &in); err != nil {
		return pluginsdk.Frames{}, fmt.Errorf("opentsdb answer: %w", err)
	}
	out := pluginsdk.Frames{Frames: []pluginsdk.Frame{}}
	for _, s := range in {
		pts := make([]point, 0, len(s.DPS))
		for k, v := range s.DPS {
			if n, err := strconv.ParseInt(k, 10, 64); err == nil && v != nil {
				pts = append(pts, point{time.Unix(n, 0), *v})
			}
		}
		out.Frames = append(out.Frames, series(labelled(s.Metric, s.Tags), pts))
	}
	return out, nil
}
