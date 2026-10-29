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
	"sync"
	"testing"
)

// pipelineAPI is a tiny in-memory pipelines API: one pipeline, versions, activate.
type pipelineAPI struct {
	mu       sync.Mutex
	pipeline map[string]any
	versions []map[string]any
	writes   int
}

func (p *pipelineAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	path := strings.TrimPrefix(r.URL.Path, "/v1/projects/prj_test/")
	reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	switch {
	case r.Method == http.MethodGet && path == "pipelines":
		data := []any{}
		if p.pipeline != nil {
			data = append(data, p.pipeline)
		}
		reply(map[string]any{"data": data, "next_cursor": nil})
	case r.Method == http.MethodPost && path == "pipelines":
		p.writes++
		p.pipeline = map[string]any{"id": "p1", "signal": body["signal"], "name": body["name"], "description": "", "active_version": nil}
		reply(p.pipeline)
	case r.Method == http.MethodPost && path == "pipelines/p1/versions":
		p.writes++
		v := map[string]any{"version": float64(len(p.versions) + 1), "config": body["config"], "tests": []any{}}
		if t, ok := body["tests"]; ok {
			v["tests"] = t
		}
		p.versions = append(p.versions, v)
		w.WriteHeader(http.StatusCreated)
		reply(v)
	case r.Method == http.MethodPost && path == "pipelines/p1/activate":
		p.writes++
		p.pipeline["active_version"] = body["version"]
		reply(p.pipeline)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "pipelines/p1/versions/"):
		n := int(p.pipeline["active_version"].(float64))
		reply(p.versions[n-1])
	default:
		http.NotFound(w, r)
	}
}

const pipelineManifest = `apiVersion: watchtower.dev/v1
kind: Pipeline
metadata: {name: main}
spec:
  signal: logs
  config:
    version: 1
    stages:
      - {type: filter, drop_if: {attr: level, eq: debug}}
  tests:
    - {name: drops debug, input: {attrs: {level: debug}}, expect: {dropped: true}}
`

func TestApplyPipelineRoundTrip(t *testing.T) {
	api := &pipelineAPI{}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "p.yaml"), []byte(pipelineManifest), 0o644); err != nil {
		t.Fatal(err)
	}
	conn := []string{"--api", srv.URL, "--key", "k", "--project", "prj_test"}
	ctx := context.Background()
	var out bytes.Buffer
	if err := applyMain(ctx, append([]string{"-f", dir}, conn...), &out); err != nil {
		t.Fatal(err, out.String())
	}
	if !strings.Contains(out.String(), "applied 1 change(s)") || len(api.versions) != 1 || api.pipeline["active_version"] != float64(1) {
		t.Fatalf("create must add and activate version 1: %s", out.String())
	}
	// Applying the same manifest changes nothing.
	before := api.writes
	out.Reset()
	if err := applyMain(ctx, append([]string{"-f", dir}, conn...), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "applied 0 change(s)") || api.writes != before {
		t.Fatalf("second apply must be a no-op: %s", out.String())
	}
	// Export, then applying the export is a no-op too.
	exp := filepath.Join(t.TempDir(), "exp")
	if err := exportMain(ctx, append([]string{"--out", exp, "--kinds", "Pipeline"}, conn...), &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := applyMain(ctx, append([]string{"-f", exp}, conn...), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "applied 0 change(s)") || api.writes != before {
		t.Fatalf("exported manifest must round-trip: %s", out.String())
	}
	// A changed stage adds version 2 and activates it.
	changed := strings.Replace(pipelineManifest, "eq: debug}}", "eq: trace}}", 1)
	if err := os.WriteFile(filepath.Join(dir, "p.yaml"), []byte(changed), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := applyMain(ctx, append([]string{"-f", dir}, conn...), &out); err != nil {
		t.Fatal(err)
	}
	if len(api.versions) != 2 || api.pipeline["active_version"] != float64(2) {
		t.Fatalf("a change must activate version 2: %s", out.String())
	}
}
