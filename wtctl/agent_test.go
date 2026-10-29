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

func TestAgentSetupClaudeMergesAndKeepsKeyOffDisk(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(`{"permissions":{"allow":["Bash"]},"env":{"KEEP":"1"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WT_INGEST_KEY", "wti_secret")
	var out bytes.Buffer
	if err := agentMain(context.Background(), []string{"setup", "claude", "--endpoint", "http://gw:4318/", "--dir", dir}, &out); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	var s map[string]any
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	env := s["env"].(map[string]any)
	if env["KEEP"] != "1" || env["OTEL_EXPORTER_OTLP_ENDPOINT"] != "http://gw:4318" || env["CLAUDE_CODE_ENABLE_TELEMETRY"] != "1" {
		t.Fatalf("env not merged: %v", env)
	}
	if s["permissions"] == nil || s["otelHeadersHelper"] != "wtctl agent headers" {
		t.Fatalf("settings: %v", s)
	}
	if strings.Contains(string(b), "wti_secret") {
		t.Fatal("key written to disk")
	}
	if _, err := os.Stat(filepath.Join(dir, ".mcp.json")); err != nil {
		t.Fatal("mcp config missing")
	}
}

func TestAgentSetupDryRunWritesNothing(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if err := agentMain(context.Background(), []string{"setup", "gemini", "--endpoint", "http://gw", "--dir", dir, "--dry-run"}, &out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".gemini")); err == nil {
		t.Fatal("dry run wrote files")
	}
	if !strings.Contains(out.String(), "otlpEndpoint") {
		t.Fatal(out.String())
	}
}

func TestAgentHeadersNeedsKey(t *testing.T) {
	t.Setenv("WT_INGEST_KEY", "")
	if err := agentMain(context.Background(), []string{"headers"}, &bytes.Buffer{}); err == nil {
		t.Fatal("want error")
	}
	t.Setenv("WT_INGEST_KEY", "k")
	var out bytes.Buffer
	if err := agentMain(context.Background(), []string{"headers"}, &out); err != nil || !strings.Contains(out.String(), "Bearer k") {
		t.Fatal(err, out.String())
	}
}

func TestAgentInspectIsReadOnly(t *testing.T) {
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method+" "+r.URL.Path)
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()
	for _, what := range [][]string{{"issues"}, {"monitors"}, {"logs", "--text", "boom"}, {"trace", "abc"}} {
		var out bytes.Buffer
		args := append([]string{"inspect"}, what...)
		args = append(args, "--api", srv.URL, "--key", "k", "--project", "prj1")
		if err := agentMain(context.Background(), args, &out); err != nil {
			t.Fatal(what, err)
		}
	}
	for _, m := range methods {
		if !strings.HasPrefix(m, "GET /v1/projects/prj1/") {
			t.Fatalf("unexpected call %s", m)
		}
	}
	if len(methods) != 4 {
		t.Fatal(methods)
	}
}
