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

func TestPipelineTestAndDiff(t *testing.T) {
	var simBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/projects/prj_test/pipelines/simulate":
			_ = json.NewDecoder(r.Body).Decode(&simBody)
			_ = json.NewEncoder(w).Encode(map[string]any{"diffs": []any{
				map[string]any{"index": 0, "dropped_by": "filter", "changes": []any{}},
				map[string]any{"index": 1, "changes": []any{
					map[string]any{"field": "attrs.team", "before": nil, "after": "core"},
				}},
			}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects/prj_test/pipelines/p1/diff":
			if r.URL.Query().Get("from") != "1" || r.URL.Query().Get("to") != "2" {
				http.Error(w, "bad query", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"stages": []any{
				map[string]any{"index": 0, "change": "changed", "before": map[string]any{"type": "enrich"}, "after": map[string]any{"type": "remap"}},
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	cfg := filepath.Join(dir, "p.yaml")
	if err := os.WriteFile(cfg, []byte("version: 1\nstages:\n  - type: enrich\n    set: {team: core}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	samples := filepath.Join(dir, "s.json")
	if err := os.WriteFile(samples, []byte(`[{"body":"a"},{"body":"b"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	common := []string{"--api", srv.URL, "--key", "k", "--project", "prj_test"}

	var out bytes.Buffer
	args := append([]string{"test", cfg, "--samples", samples, "--signal", "spans"}, common...)
	if err := pipelineMain(context.Background(), args, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"record 0: dropped by filter", "attrs.team: (none) -> \"core\"", "2 records, 1 dropped"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("test output missing %q:\n%s", want, out.String())
		}
	}
	if simBody["signal"] != "spans" || len(simBody["records"].([]any)) != 2 {
		t.Errorf("simulate request = %v", simBody)
	}
	if cfgBody, _ := simBody["config"].(map[string]any); cfgBody["version"] != float64(1) {
		t.Errorf("yaml config not sent as JSON: %v", simBody["config"])
	}

	out.Reset()
	args = append([]string{"diff", "--id", "p1", "--from", "1", "--to", "2"}, common...)
	if err := pipelineMain(context.Background(), args, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `stage 0: changed {"type":"remap"}`) {
		t.Errorf("diff output:\n%s", out.String())
	}

	out.Reset()
	args = append([]string{"validate", cfg}, common...)
	if err := pipelineMain(context.Background(), args, &out); err != nil || strings.TrimSpace(out.String()) != "valid" {
		t.Errorf("validate: %v %q", err, out.String())
	}
}
