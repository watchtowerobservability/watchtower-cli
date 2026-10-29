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

	"github.com/watchtowerobservability/watchtower-cli/internal/ascode/ascodetest"
)

// internalFake serves orgs, projects, environments and credentials; project-scoped as-code
// resources go to the shared ascodetest fake (project id ascodetest.Project).
type internalFake struct {
	mu     sync.Mutex
	orgs   []map[string]any
	prjs   []map[string]any
	creds  []map[string]any
	delegt http.Handler
}

func (f *internalFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	list := func(d []map[string]any) { reply(map[string]any{"data": d, "next_cursor": nil}) }
	add := func(dst *[]map[string]any, id string, extra map[string]any) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		b["id"] = id
		for k, v := range extra {
			b[k] = v
		}
		*dst = append(*dst, b)
		reply(b)
	}
	p := r.URL.Path
	switch {
	case p == "/v1/orgs" && r.Method == http.MethodGet:
		list(f.orgs)
	case p == "/v1/orgs":
		add(&f.orgs, "org_1", nil)
	case strings.HasSuffix(p, "/projects") && r.Method == http.MethodGet:
		list(f.prjs)
	case strings.HasSuffix(p, "/projects"):
		add(&f.prjs, ascodetest.Project, nil)
	case strings.HasSuffix(p, "/environments"):
		list([]map[string]any{{"id": "env_1"}})
	case strings.HasSuffix(p, "/credentials") && r.Method == http.MethodGet:
		list(f.creds)
	case strings.HasSuffix(p, "/credentials"):
		add(&f.creds, "cred_"+string(rune('a'+len(f.creds))), map[string]any{"token": "wti_secret"})
	default:
		f.delegt.ServeHTTP(w, r)
	}
}

func TestBootstrapIsIdempotent(t *testing.T) {
	as := ascodetest.New(t)
	f := &internalFake{delegt: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		as.Config.Handler.ServeHTTP(w, r)
	})}
	srv := httptest.NewServer(f)
	defer srv.Close()
	dir := t.TempDir()
	dash := filepath.Join(dir, "d")
	if err := os.Mkdir(dash, 0o755); err != nil {
		t.Fatal(err)
	}
	spec := `{"version":1,"variables":[],"panels":[{"id":"a","title":"A","type":"timeseries","grid":{"x":0,"y":0,"w":12,"h":6},"query":{"kind":"promql","text":"up"}}]}`
	if err := os.WriteFile(filepath.Join(dash, "ingestion.json"), []byte(spec), 0o600); err != nil {
		t.Fatal(err)
	}
	o := internalOpts{api: srv.URL, key: "test-key", dashboards: dash, secretOut: filepath.Join(dir, "secret.yaml")}
	run := func() string {
		var out bytes.Buffer
		if err := internalBootstrap(context.Background(), o, &out); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	first := run()
	if !strings.Contains(first, "credential wt-api created") || as.Count("Dashboard") != 1 {
		t.Fatalf("first run: %q dashboards=%d", first, as.Count("Dashboard"))
	}
	if strings.Contains(first, "wti_secret") {
		t.Fatal("token printed")
	}
	writes := as.Writes()
	second := run()
	if strings.Contains(second, "created") || as.Writes() != writes || len(f.orgs) != 1 || len(f.prjs) != 1 || len(f.creds) != len(internalServices) {
		t.Fatalf("second run not a no-op: %q", second)
	}
}
