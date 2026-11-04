package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSelfMonitorInitCreatesDashboardAndRules(t *testing.T) {
	var paths, titles []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		paths = append(paths, r.Method+" "+r.URL.Path)
		if s, ok := m["title"].(string); ok {
			titles = append(titles, s)
		}
		if k, ok := m["kind"]; ok && k != "metric" { // the API's RuleKind for PromQL rules (wt-rules)
			t.Errorf("rule kind %v", k)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"d1"}`))
	}))
	defer srv.Close()
	var out bytes.Buffer
	if err := selfMonitorInit(context.Background(), srv.URL, "k", "p1", &out); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 6 || paths[0] != "POST /v1/projects/p1/dashboards" {
		t.Fatalf("calls %v", paths)
	}
	for _, p := range paths[1:] {
		if p != "POST /v1/projects/p1/alert-rules" {
			t.Fatalf("calls %v", paths)
		}
	}
	if len(titles) != 1 || titles[0] != "Platform health" || !strings.Contains(out.String(), "Outbox age") {
		t.Fatalf("%v %s", titles, out.String())
	}
}
