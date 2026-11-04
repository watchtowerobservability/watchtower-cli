package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestContextsFillUnsetVariables(t *testing.T) {
	t.Setenv("WTCTL_CONFIG", filepath.Join(t.TempDir(), "wtctl", "config.json"))
	for _, k := range []string{"WT_CONTEXT", "WT_API", "WT_API_URL", "WT_API_KEY", "WT_PROJECT"} {
		t.Setenv(k, "")
	}
	c, p, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	c.Contexts["prod"] = wtContext{API: "https://wt.example", Key: "wtk_prod", Project: "prj_p"}
	c.Contexts["dev"] = wtContext{API: "http://localhost:8080", Key: "wtk_dev", Project: "prj_d"}
	c.Current = "dev"
	if err := saveConfig(c, p); err != nil {
		t.Fatal(err)
	}
	// Windows has no Unix permission bits.
	if fi, _ := os.Stat(p); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("config mode %v", fi.Mode().Perm())
	}
	args, err := applyContext([]string{"query", "logs", "--context", "prod", "--limit", "5"})
	if err != nil || strings.Join(args, " ") != "query logs --limit 5" {
		t.Fatalf("args %v %v", args, err)
	}
	if os.Getenv("WT_API") != "https://wt.example" || os.Getenv("WT_PROJECT") != "prj_p" || os.Getenv("WT_API_KEY") != "wtk_prod" {
		t.Fatal("prod context not applied")
	}
	// An explicit variable wins over the (current) context.
	t.Setenv("WT_PROJECT", "prj_mine")
	t.Setenv("WT_API", "")
	if _, err := applyContext([]string{"query", "logs"}); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("WT_PROJECT") != "prj_mine" || os.Getenv("WT_API") != "http://localhost:8080" {
		t.Fatal("current context or precedence wrong")
	}
	if _, err := applyContext([]string{"--context=nope", "query"}); err == nil {
		t.Fatal("unknown context accepted")
	}
	var out bytes.Buffer
	if err := contextMain(context.Background(), []string{"list"}, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "wtk_") || !strings.Contains(out.String(), "* dev") {
		t.Fatalf("list %q", out.String())
	}
	if err := contextMain(context.Background(), []string{"use", "prod"}, &out); err != nil {
		t.Fatal(err)
	}
	if c, _, _ := loadConfig(); c.Current != "prod" {
		t.Fatalf("current %q", c.Current)
	}
}

func TestQueryCommandsCallTheAPI(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		switch r.URL.Path {
		case "/v1/projects/prj_1/logs/search":
			_, _ = w.Write([]byte(`{"data":[{"ts_ns":1700000000000000000,"service":"api","severity_text":"ERROR","body":"boom\nline2"}]}`))
		case "/v1/projects/prj_1/query/traces":
			_, _ = w.Write([]byte(`{"traces":[{"trace_id":"abc","matched_span_count":3}]}`))
		case "/v1/projects/prj_1/prometheus/api/v1/query_range":
			_, _ = w.Write([]byte(`{"data":{"result":[{"metric":{"__name__":"up","job":"api"},"values":[[1700000000,"1"]]}]}}`))
		case "/v1/projects/prj_1/logs/tail":
			_, _ = w.Write([]byte("event: log\ndata: {\"service\":\"api\",\"severity_text\":\"INFO\",\"body\":\"hi\"}\n\nevent: end\ndata: done\n\n"))
		}
	}))
	defer srv.Close()
	flags := []string{"--api", srv.URL, "--key", "k", "--project", "prj_1"}
	run := func(f func(context.Context, []string, *bytes.Buffer) error, args ...string) string {
		var out bytes.Buffer
		if err := f(context.Background(), append(args, flags...), &out); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		return out.String()
	}
	q := func(ctx context.Context, a []string, o *bytes.Buffer) error { return queryMain(ctx, a, o) }
	l := func(ctx context.Context, a []string, o *bytes.Buffer) error { return logsMain(ctx, a, o) }
	if got := run(q, "logs", "--text", "boom"); !strings.Contains(got, "2023-11-14T22:13:20Z  api      ERROR          boom line2") {
		t.Errorf("logs table %q", got)
	}
	if got := run(q, "traces", `{ status = error }`, "-o", "json"); strings.TrimSpace(got) != `{"matched_span_count":3,"trace_id":"abc"}` {
		t.Errorf("traces json %q", got)
	}
	if got := run(q, "metrics", "up", "--step", "30s"); !strings.Contains(got, `up{job="api"}`) {
		t.Errorf("metrics %q", got)
	}
	if got := run(l, "tail", "--follow"); got != " api [INFO] hi\n" {
		t.Errorf("tail %q", got)
	}
	if !strings.Contains(paths[0], "text=boom") || !strings.Contains(paths[2], "step=30") || !strings.HasPrefix(paths[1], "POST ") {
		t.Errorf("paths %v", paths)
	}
}
