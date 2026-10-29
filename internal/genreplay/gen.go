package genreplay

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"github.com/watchtowerobservability/watchtower-cli/internal/netguard"
)

// `wtctl gen` replays a scenario written by `wt-testkit gen_fixtures` (testdata/scenarios/<name>.otlp.json)
// through the gateway as OTLP/HTTP JSON. Each loop shifts the scenario so it ends now and gives every
// trace and span a fresh id; the scenario logic itself lives only in the Rust testkit.

const GenUsage = "usage: wtctl gen (--file <scenario.otlp.json> | --scenario <name>) [--rate 10/s] [--duration 1m] [--endpoint http://localhost:4318] [--key-env WT_INGEST_KEY] [--dir testdata/scenarios]"

var (
	timeKeys = map[string]bool{"startTimeUnixNano": true, "endTimeUnixNano": true, "timeUnixNano": true}
	idKeys   = map[string]bool{"traceId": true, "spanId": true, "parentSpanId": true}
)

// bucket is a token bucket holding at most one token: n waits take at least (n-1)/rate seconds.
type bucket struct {
	rate   float64 // tokens per second
	tokens float64
	last   time.Time
	now    func() time.Time
	sleep  func(time.Duration)
}

func newBucket(rate float64, now func() time.Time, sleep func(time.Duration)) *bucket {
	return &bucket{rate: rate, tokens: 1, last: now(), now: now, sleep: sleep}
}

func (b *bucket) wait() {
	t := b.now()
	b.tokens = min(1, b.tokens+t.Sub(b.last).Seconds()*b.rate)
	b.last = t
	if b.tokens < 1 {
		b.sleep(time.Duration((1 - b.tokens) / b.rate * float64(time.Second)))
		b.last = b.now()
		b.tokens = 1
	}
	b.tokens--
}

// idMap hands out one fresh random id per distinct old id, of the same length.
type idMap struct {
	rng *rand.Rand
	m   map[string]string
}

func (im *idMap) get(old string) string {
	if v, ok := im.m[old]; ok {
		return v
	}
	b := make([]byte, len(old)/2)
	for i := range b {
		b[i] = byte(im.rng.Intn(256))
	}
	im.m[old] = hex.EncodeToString(b)
	return im.m[old]
}

// maxTime is the latest timestamp (ns) anywhere in the document.
func maxTime(v any) uint64 {
	var m uint64
	switch x := v.(type) {
	case map[string]any:
		for k, c := range x {
			if s, ok := c.(string); ok && timeKeys[k] {
				n, _ := strconv.ParseUint(s, 10, 64)
				m = max(m, n)
			} else {
				m = max(m, maxTime(c))
			}
		}
	case []any:
		for _, c := range x {
			m = max(m, maxTime(c))
		}
	}
	return m
}

// freshen deep-copies v with every timestamp moved by delta ns and every id replaced.
func freshen(v any, delta int64, ids *idMap) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, c := range x {
			s, isStr := c.(string)
			switch {
			case isStr && timeKeys[k]:
				n, _ := strconv.ParseUint(s, 10, 64)
				out[k] = strconv.FormatUint(uint64(int64(n)+delta), 10)
			case isStr && idKeys[k] && s != "":
				out[k] = ids.get(s)
			default:
				out[k] = freshen(c, delta, ids)
			}
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, c := range x {
			out[i] = freshen(c, delta, ids)
		}
		return out
	}
	return v
}

type signal struct{ name, path, res, scope, item string }

var signals = []signal{
	{"traces", "/v1/traces", "resourceSpans", "scopeSpans", "spans"},
	{"logs", "/v1/logs", "resourceLogs", "scopeLogs", "logRecords"},
	{"metrics", "/v1/metrics", "resourceMetrics", "scopeMetrics", "metrics"},
}

type request struct {
	path string
	body map[string]any
}

// split regroups one signal's items by trace id (items without one go under ""), keeping each
// item's resource and scope, in first-seen order.
func split(root map[string]any, sg signal) (order []string, groups map[string][]any) {
	groups = map[string][]any{}
	resources, _ := root[sg.res].([]any)
	for _, r := range resources {
		rm, _ := r.(map[string]any)
		scopes, _ := rm[sg.scope].([]any)
		for _, s := range scopes {
			sm, _ := s.(map[string]any)
			items, _ := sm[sg.item].([]any)
			byTrace := map[string][]any{}
			var keys []string
			for _, it := range items {
				im, _ := it.(map[string]any)
				tid, _ := im["traceId"].(string)
				if _, seen := byTrace[tid]; !seen {
					keys = append(keys, tid)
				}
				byTrace[tid] = append(byTrace[tid], it)
			}
			for _, tid := range keys {
				if _, seen := groups[tid]; !seen {
					order = append(order, tid)
				}
				groups[tid] = append(groups[tid], map[string]any{
					"resource": rm["resource"],
					sg.scope:   []any{map[string]any{"scope": sm["scope"], sg.item: byTrace[tid]}},
				})
			}
		}
	}
	return order, groups
}

// plan turns a document into one request list per trace (its spans, then its logs) plus a tail of
// everything not tied to a trace (metrics, loose logs).
func plan(doc map[string]any) (perTrace [][]request, tail []request) {
	byTrace := map[string][]request{}
	var order []string
	for _, sg := range signals {
		root, _ := doc[sg.name].(map[string]any)
		keys, groups := split(root, sg)
		for _, k := range keys {
			req := request{sg.path, map[string]any{sg.res: groups[k]}}
			_, known := byTrace[k]
			switch {
			case k != "" && (sg.name == "traces" || known):
				if !known {
					order = append(order, k)
				}
				byTrace[k] = append(byTrace[k], req)
			default:
				tail = append(tail, req)
			}
		}
	}
	for _, k := range order {
		perTrace = append(perTrace, byTrace[k])
	}
	return perTrace, tail
}

type genOpts struct {
	doc      map[string]any
	name     string
	endpoint string
	key      string
	rate     float64
	duration time.Duration
	client   *http.Client
	now      func() time.Time
	sleep    func(time.Duration)
	rng      *rand.Rand
}

func (o *genOpts) post(ctx context.Context, r request) error {
	body, err := json.Marshal(r.body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(o.endpoint, "/")+r.path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+o.key)
	resp, err := o.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("POST %s: HTTP %d: %s", r.path, resp.StatusCode, msg)
	}
	return nil
}

// run replays the scenario until the duration is over; it returns the number of traces sent.
func (o *genOpts) run(ctx context.Context) (loops, traces int, err error) {
	end := maxTime(o.doc)
	if end == 0 {
		return 0, 0, fmt.Errorf("scenario %q has no timestamps", o.name)
	}
	b := newBucket(o.rate, o.now, o.sleep)
	deadline := o.now().Add(o.duration)
	for o.now().Before(deadline) {
		ids := &idMap{rng: o.rng, m: map[string]string{}}
		fresh, _ := freshen(o.doc, o.now().UnixNano()-int64(end), ids).(map[string]any)
		perTrace, tail := plan(fresh)
		if len(perTrace) == 0 {
			return loops, traces, fmt.Errorf("scenario %q has no traces", o.name)
		}
		for _, reqs := range perTrace {
			b.wait()
			if err := ctx.Err(); err != nil || !o.now().Before(deadline) {
				return loops, traces, err
			}
			for _, r := range reqs {
				if err := o.post(ctx, r); err != nil {
					return loops, traces, err
				}
			}
			traces++
		}
		for _, r := range tail {
			if err := o.post(ctx, r); err != nil {
				return loops, traces, err
			}
		}
		loops++
	}
	return loops, traces, nil
}

// parseRate accepts "50/s" or "50".
func parseRate(s string) (float64, error) {
	r, err := strconv.ParseFloat(strings.TrimSuffix(s, "/s"), 64)
	if err != nil || r <= 0 {
		return 0, fmt.Errorf("bad --rate %q (want e.g. 20/s)", s)
	}
	return r, nil
}

// Builtin supplies generated scenarios for the private wt-gen command; wtctl passes nil and so
// replays only the user's own OTLP JSON files.
type Builtin interface {
	Names() []string
	// Generate returns the OTLP JSON documents of one scenario.
	Generate(name string) ([]byte, error)
}

// Main is `wtctl gen ...` (b nil) and `wt-gen ...`. The ingestion key is read from the
// environment variable named by --key-env, never from a flag.
func Main(ctx context.Context, args []string, out io.Writer, b Builtin) error {
	fs := flag.NewFlagSet("gen", flag.ContinueOnError)
	var name, rate, endpoint, keyEnv, dir, file string
	var duration time.Duration
	fs.StringVar(&name, "scenario", "", "scenario name (a file in --dir without .otlp.json)")
	fs.StringVar(&rate, "rate", "10/s", "traces per second")
	fs.DurationVar(&duration, "duration", time.Minute, "how long to keep replaying")
	fs.StringVar(&endpoint, "endpoint", "http://localhost:4318", "gateway OTLP/HTTP base URL")
	fs.StringVar(&keyEnv, "key-env", "WT_INGEST_KEY", "name of the environment variable holding the ingestion key")
	fs.StringVar(&dir, "dir", "testdata/scenarios", "directory of scenario files")
	fs.StringVar(&file, "file", "", "an OTLP/HTTP JSON file to replay")
	list := fs.Bool("list", false, "list the built-in investigation scenario generators and exit")
	if err := fs.Parse(args); err != nil {
		return errors.New(GenUsage)
	}
	if *list {
		if b != nil {
			fmt.Fprintln(out, strings.Join(b.Names(), "\n"))
		}
		return nil
	}
	if file != "" && name == "" {
		name = strings.TrimSuffix(filepath.Base(file), ".json")
	}
	if name == "" || strings.ContainsAny(name, `/\`) {
		return errors.New(GenUsage)
	}
	r, err := parseRate(rate)
	if err != nil {
		return err
	}
	key := os.Getenv(keyEnv)
	if key == "" {
		return fmt.Errorf("environment variable %s is empty; export the ingestion key there", keyEnv)
	}
	path := filepath.Join(dir, name+".otlp.json")
	if file != "" {
		path = file
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && b != nil && slices.Contains(b.Names(), name) {
		// A built-in generator (wt-gen only); ids and times are refreshed per loop.
		data, err = b.Generate(name)
	}
	if err != nil {
		return err
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("scenario %s: %w", name, err)
	}
	o := &genOpts{doc: doc, name: name, endpoint: endpoint, key: key, rate: r, duration: duration,
		client: netguard.Guarded("wtctl", 30*time.Second), now: time.Now, sleep: time.Sleep,
		rng: rand.New(rand.NewSource(time.Now().UnixNano()))}
	loops, traces, err := o.run(ctx)
	fmt.Fprintf(out, "scenario=%s loops=%d traces=%d\n", name, loops, traces)
	return err
}
