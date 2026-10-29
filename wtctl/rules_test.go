package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRulesImportPutsEachGroup(t *testing.T) {
	var paths, bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		paths = append(paths, r.Method+" "+r.URL.Path)
		bodies = append(bodies, string(b))
		if r.Header.Get("Authorization") != "Bearer k" {
			w.WriteHeader(http.StatusUnauthorized)
		}
		_, _ = w.Write([]byte(`{"name":"ok"}`))
	}))
	defer srv.Close()
	f := filepath.Join(t.TempDir(), "rules.yaml")
	yml := "groups:\n- name: a\n  rules:\n  - record: x:y\n    expr: up\n- name: b\n  interval: 30s\n  rules: []\n"
	if err := os.WriteFile(f, []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	args := []string{"import", f, "--api", srv.URL, "--key", "k", "--project", "prj_1"}
	if err := rulesMain(context.Background(), args, &out); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || paths[0] != "PUT /v1/projects/prj_1/rule-groups/a" || paths[1] != "PUT /v1/projects/prj_1/rule-groups/b" {
		t.Fatalf("paths %v", paths)
	}
	if !strings.Contains(bodies[0], `"record":"x:y"`) {
		t.Fatalf("body %s", bodies[0])
	}
}

func TestRoutingImportPreviewUnlessApply(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.RequestURI()
		_, _ = w.Write([]byte(`{"applied":false}`))
	}))
	defer srv.Close()
	f := filepath.Join(t.TempDir(), "am.yaml")
	if err := os.WriteFile(f, []byte("route: {receiver: a}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	base := []string{"import-alertmanager", f, "--api", srv.URL, "--key", "k", "--project", "p"}
	var out bytes.Buffer
	if err := routingMain(context.Background(), base, &out); err != nil || got != "/v1/projects/p/routing:import-alertmanager" {
		t.Fatalf("%v %s", err, got)
	}
	if err := routingMain(context.Background(), append(base, "--apply"), &out); err != nil || !strings.HasSuffix(got, "?apply=true") {
		t.Fatalf("%v %s", err, got)
	}
}
