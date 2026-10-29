package genreplay

import (
	"context"
	"encoding/json"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

// A tiny scenario: one trace (root + child) with a correlated log, plus one metric. Times are
// 1s..2s after the epoch; the latest timestamp is 2s.
const genFixture = `{
 "traces":{"resourceSpans":[{"resource":{"attributes":[]},"scopeSpans":[{"spans":[
  {"traceId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","spanId":"1111111111111111","name":"root","startTimeUnixNano":"1000000000","endTimeUnixNano":"2000000000"},
  {"traceId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","spanId":"2222222222222222","parentSpanId":"1111111111111111","name":"child","startTimeUnixNano":"1100000000","endTimeUnixNano":"1900000000"}]}]}]},
 "logs":{"resourceLogs":[{"resource":{},"scopeLogs":[{"logRecords":[
  {"traceId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","spanId":"2222222222222222","timeUnixNano":"1500000000","body":{"stringValue":"hi"}}]}]}]},
 "metrics":{"resourceMetrics":[{"resource":{},"scopeMetrics":[{"metrics":[
  {"name":"m","sum":{"dataPoints":[{"startTimeUnixNano":"1000000000","timeUnixNano":"2000000000","asInt":"3"}]}}]}]}]}
}`

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time        { return c.t }
func (c *fakeClock) sleep(d time.Duration) { c.t = c.t.Add(d) }

type recorded struct {
	path string
	auth string
	body map[string]any
}

// runFixture replays genFixture against a recording server on a fake clock.
func runFixture(t *testing.T, rate float64, dur time.Duration) (now time.Time, got []recorded, loops, traces int) {
	t.Helper()
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Errorf("body is not JSON: %v", err)
		}
		mu.Lock()
		got = append(got, recorded{r.URL.Path, r.Header.Get("Authorization"), m})
		mu.Unlock()
	}))
	t.Cleanup(srv.Close)
	var doc map[string]any
	if err := json.Unmarshal([]byte(genFixture), &doc); err != nil {
		t.Fatal(err)
	}
	clk := &fakeClock{t: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
	o := &genOpts{doc: doc, name: "fixture", endpoint: srv.URL, key: "wti_secret", rate: rate, duration: dur,
		client: srv.Client(), now: clk.now, sleep: clk.sleep, rng: rand.New(rand.NewSource(1))}
	start := clk.t
	loops, traces, err := o.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return start, got, loops, traces
}

func spansOf(t *testing.T, r recorded) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, rs := range r.body["resourceSpans"].([]any) {
		for _, ss := range rs.(map[string]any)["scopeSpans"].([]any) {
			for _, s := range ss.(map[string]any)["spans"].([]any) {
				out = append(out, s.(map[string]any))
			}
		}
	}
	return out
}

func nanos(t *testing.T, v any) int64 {
	t.Helper()
	n, err := strconv.ParseInt(v.(string), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestGenReplaysScenarioTimeShifted(t *testing.T) {
	start, got, loops, traces := runFixture(t, 1, 500*time.Millisecond)
	if loops != 1 || traces != 1 {
		t.Fatalf("loops=%d traces=%d, want 1 and 1", loops, traces)
	}
	now := start.UnixNano()
	byPath := map[string]recorded{}
	for _, r := range got {
		byPath[r.path] = r
		if r.auth != "Bearer wti_secret" {
			t.Errorf("%s: Authorization %q", r.path, r.auth)
		}
	}
	for _, p := range []string{"/v1/traces", "/v1/logs", "/v1/metrics"} {
		if _, ok := byPath[p]; !ok {
			t.Fatalf("no request to %s; got %d requests", p, len(got))
		}
	}
	spans := spansOf(t, byPath["/v1/traces"])
	// The scenario ends now; offsets between timestamps are preserved.
	if e := nanos(t, spans[0]["endTimeUnixNano"]); e != now {
		t.Errorf("root end %d, want now %d", e, now)
	}
	if s := nanos(t, spans[0]["startTimeUnixNano"]); s != now-1e9 {
		t.Errorf("root start %d, want now-1s", s)
	}
	if s := nanos(t, spans[1]["startTimeUnixNano"]); s != now-9e8 {
		t.Errorf("child start %d, want now-0.9s", s)
	}
	lr := byPath["/v1/logs"].body["resourceLogs"].([]any)[0].(map[string]any)["scopeLogs"].([]any)[0].(map[string]any)["logRecords"].([]any)[0].(map[string]any)
	if ts := nanos(t, lr["timeUnixNano"]); ts != now-5e8 {
		t.Errorf("log time %d, want now-0.5s", ts)
	}
}

func TestGenFreshIDsPerLoop(t *testing.T) {
	_, got, loops, _ := runFixture(t, 1, 1500*time.Millisecond)
	if loops != 2 {
		t.Fatalf("loops=%d, want 2", loops)
	}
	var traceIDs []string
	for _, r := range got {
		if r.path != "/v1/traces" {
			continue
		}
		spans := spansOf(t, r)
		tid := spans[0]["traceId"].(string)
		traceIDs = append(traceIDs, tid)
		if tid == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || spans[0]["spanId"] == "1111111111111111" {
			t.Errorf("ids were not replaced: %v", spans[0])
		}
		// The tree survives: the child points at the new root span id and shares the trace id.
		if spans[1]["parentSpanId"] != spans[0]["spanId"] || spans[1]["traceId"] != tid {
			t.Errorf("tree broken: %v", spans)
		}
		if _, ok := spans[0]["parentSpanId"]; ok {
			t.Errorf("root gained a parent: %v", spans[0])
		}
	}
	if len(traceIDs) != 2 || traceIDs[0] == traceIDs[1] {
		t.Fatalf("want two different trace ids, got %v", traceIDs)
	}
}

func TestGenRateLimited(t *testing.T) {
	clk := &fakeClock{t: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
	start := clk.t
	b := newBucket(10, clk.now, clk.sleep)
	for range 5 {
		b.wait()
	}
	// The first token is free; the other four take 100ms each at 10/s.
	if got := clk.t.Sub(start); got != 400*time.Millisecond {
		t.Fatalf("5 waits took %v, want 400ms", got)
	}
	if _, err := parseRate("0/s"); err == nil {
		t.Error("rate 0 must be rejected")
	}
	if r, err := parseRate("25/s"); err != nil || r != 25 {
		t.Errorf("parseRate(25/s) = %v, %v", r, err)
	}
}

func TestGenRequiresKeyEnv(t *testing.T) {
	t.Setenv("WT_GEN_TEST_KEY", "")
	err := Main(context.Background(), []string{"--scenario", "x", "--key-env", "WT_GEN_TEST_KEY"}, io.Discard, nil)
	if err == nil {
		t.Fatal("want an error when the key variable is empty")
	}
	if err := Main(context.Background(), []string{"--scenario", "x", "--key", "wti_x"}, io.Discard, nil); err == nil {
		t.Fatal("--key must not exist as a flag")
	}
}
