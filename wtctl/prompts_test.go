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

// promptAPI is an in-memory registry: one prompt, versions as pushed.
type promptAPI struct {
	versions []map[string]any
	labels   map[string]int
	created  bool
}

func (a *promptAPI) detail() map[string]any {
	d := map[string]any{"id": "p1", "name": "greet", "folder": "support", "type": "text"}
	var ls []map[string]any
	for l, v := range a.labels {
		ls = append(ls, map[string]any{"label": l, "version": v})
	}
	d["labels"] = ls
	if n := len(a.versions); n > 0 {
		v := a.versions[n-1]
		d["latest"] = map[string]any{"version": n, "template": v["template"], "config": v["config"], "commit_message": v["commit_message"]}
	}
	return d
}

func (a *promptAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	p := strings.TrimPrefix(r.URL.Path, "/v1/projects/prj_1/llm/prompts")
	switch {
	case r.Method == http.MethodGet && p == "":
		if a.created {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"id": "p1", "name": "greet"}}})
		} else {
			_, _ = w.Write([]byte(`{"data":[]}`))
		}
	case r.Method == http.MethodPost && p == "":
		a.created, a.labels = true, map[string]int{}
		a.versions = append(a.versions, body)
		_ = json.NewEncoder(w).Encode(a.detail())
	case r.Method == http.MethodGet && p == "/p1":
		_ = json.NewEncoder(w).Encode(a.detail())
	case r.Method == http.MethodPost && p == "/p1/versions":
		a.versions = append(a.versions, body)
		_, _ = w.Write([]byte(`{"version":` + string(rune('0'+len(a.versions))) + `}`))
	case r.Method == http.MethodPut && strings.HasPrefix(p, "/p1/labels/"):
		a.labels[strings.TrimPrefix(p, "/p1/labels/")] = int(body["version"].(float64))
		_, _ = w.Write([]byte(`{}`))
	default:
		http.NotFound(w, r)
	}
}

func TestPromptsPushPullRoundtrip(t *testing.T) {
	api := &promptAPI{}
	srv := httptest.NewServer(api)
	defer srv.Close()
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "support"), 0o750); err != nil {
		t.Fatal(err)
	}
	yml := "name: greet\nfolder: support\ntype: text\ntemplate: Hello {{name}}\nlabels: [production]\n"
	if err := os.WriteFile(filepath.Join(src, "support", "greet.yaml"), []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	common := []string{"--api", srv.URL, "--key", "k", "--project", "prj_1"}
	var out bytes.Buffer
	if err := promptsMain(context.Background(), append([]string{"push", "--dir", src}, common...), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "created") || api.labels["production"] != 1 {
		t.Fatalf("out %q labels %v", out.String(), api.labels)
	}
	// Same content again: no new version.
	out.Reset()
	if err := promptsMain(context.Background(), append([]string{"push", "--dir", src}, common...), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "unchanged") || len(api.versions) != 1 {
		t.Fatalf("out %q versions %d", out.String(), len(api.versions))
	}
	dst := t.TempDir()
	if err := promptsMain(context.Background(), append([]string{"pull", "--dir", dst}, common...), &out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dst, "support", "greet.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"name: greet", "Hello {{name}}", "production"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("pulled file lacks %q:\n%s", want, got)
		}
	}
}
