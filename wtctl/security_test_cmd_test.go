package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuleSpecKeepsOnlyTestFields(t *testing.T) {
	spec, err := ruleSpec([]byte("apiVersion: watchtower.dev/v1\nkind: SecurityRule\nmetadata: {name: x}\nspec:\n  query: 'a:b'\n  detection: threshold\n  window_s: 300\n  cases: [{severity: high, threshold: 1}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if spec["query"] != "a:b" || spec["detection"] != "threshold" || spec["window_s"] != nil {
		t.Fatalf("unexpected spec %v", spec)
	}
	if _, err := ruleSpec([]byte("query: a:b\n")); err == nil {
		t.Fatal("a rule without detection must be refused")
	}
}

func TestSampleEventsSkipsBlankAndReportsLine(t *testing.T) {
	evs, err := sampleEvents(strings.NewReader("{\"ts\":1,\"attrs\":{\"a\":\"b\"}}\n\n{\"ts\":2,\"attrs\":{}}\n"))
	if err != nil || len(evs) != 2 {
		t.Fatalf("got %v %v", evs, err)
	}
	if _, err := sampleEvents(strings.NewReader("{\"ts\":1}\nnot json\n")); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("want a line-2 error, got %v", err)
	}
}

func TestSecurityTestPostsRuleAndEvents(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/projects/prj_1/security/rules/test" {
			t.Errorf("path %s", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"matched":1,"signals":[{"entity":"a","severity":"high","hits":1}]}`))
	}))
	defer srv.Close()
	dir := t.TempDir()
	rule := filepath.Join(dir, "r.yaml")
	sample := filepath.Join(dir, "s.ndjson")
	_ = os.WriteFile(rule, []byte("query: 'a:b'\ndetection: threshold\n"), 0o600)
	_ = os.WriteFile(sample, []byte("{\"ts\":1,\"attrs\":{\"a\":\"b\"}}\n"), 0o600)
	var out bytes.Buffer
	args := []string{rule, sample, "--api", srv.URL, "--key", "k", "--project", "prj_1"}
	if err := securityTest(context.Background(), append(args, "--expect-signals", "1"), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "SIGNAL high entity=a") || len(got["events"].([]any)) != 1 {
		t.Fatalf("out=%q body=%v", out.String(), got)
	}
	if err := securityTest(context.Background(), append(args, "--expect-signals", "0"), &out); err == nil {
		t.Fatal("a signal count mismatch must fail")
	}
}
