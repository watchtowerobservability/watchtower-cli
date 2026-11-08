package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// captureServer answers the import routes like importServer but records every text field.
func captureServer(t *testing.T, final string, fields *map[string]string) *httptest.Server {
	t.Helper()
	polls := 0
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/projects/prj_1/imports":
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				t.Errorf("multipart: %v", err)
			}
			m := map[string]string{}
			for k, v := range r.MultipartForm.Value {
				m[k] = v[0]
			}
			for role := range r.MultipartForm.File {
				f, _, _ := r.FormFile(role)
				var b bytes.Buffer
				_, _ = b.ReadFrom(f)
				m["file:"+role] = b.String()
			}
			*fields = m
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"job1","state":"queued"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects/prj_1/imports/job1":
			polls++
			if polls < 2 {
				_, _ = w.Write([]byte(`{"id":"job1","state":"running"}`))
				return
			}
			_, _ = w.Write([]byte(final))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

var connArgs = func(srv *httptest.Server) []string {
	return []string{"--api", srv.URL, "--key", "wtk_x", "--project", "prj_1"}
}

func TestLiveImportSendsTheVendorKeyFromTheEnvironment(t *testing.T) {
	importPollEvery = time.Millisecond
	t.Setenv("PD_KEY", "pd-secret-1")
	var got map[string]string
	srv := captureServer(t, `{"id":"job1","state":"succeeded","result":{"output":"would create 2 schedule\n","report":{"mapped":2},"markdown":"# r\n"}}`, &got)
	defer srv.Close()
	report := filepath.Join(t.TempDir(), "rep")
	var out bytes.Buffer
	args := append([]string{"pagerduty", "--api-key-env", "PD_KEY", "--region", "eu", "--scope", "policy=P1", "--report", report}, conn(srv)...)
	if err := importMain(context.Background(), args, &out); err != nil {
		t.Fatal(err)
	}
	if got["source"] != "pagerduty" || got["mode"] != "dry_run" || got["api_key"] != "pd-secret-1" || got["region"] != "eu" || got["scope"] != "policy=P1" {
		t.Fatalf("upload: %v", got)
	}
	if strings.Contains(out.String(), "pd-secret-1") || !strings.Contains(out.String(), "would create 2 schedule") {
		t.Fatalf("output %q", out.String())
	}
	if b, _ := os.ReadFile(report + ".json"); !strings.Contains(string(b), `"mapped":2`) {
		t.Fatalf("report.json %q", b)
	}
}

func TestLiveImportNeedsItsKeyVariableAndMapsAliases(t *testing.T) {
	importPollEvery = time.Millisecond
	var got map[string]string
	srv := captureServer(t, `{"id":"job1","state":"succeeded","result":{"output":"ok\n"}}`, &got)
	defer srv.Close()
	err := importMain(context.Background(), append([]string{"opsgenie", "--api-key-env", "UNSET_OG_KEY"}, conn(srv)...), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "UNSET_OG_KEY") {
		t.Fatalf("want an empty-variable error, got %v", err)
	}
	t.Setenv("DD_API", "dd1")
	t.Setenv("DD_APP", "dd2")
	args := append([]string{"datadog", "--live", "--api-key-env", "DD_API", "--app-key-env", "DD_APP", "--apply", "--report", filepath.Join(t.TempDir(), "r")}, conn(srv)...)
	if err := importMain(context.Background(), args, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if got["source"] != "datadog-live" || got["mode"] != "apply" || got["api_key"] != "dd1" || got["app_key"] != "dd2" {
		t.Fatalf("upload: %v", got)
	}
}

func TestChecksImportOpenAPIUploadsTheSpecAndWritesTheMonitor(t *testing.T) {
	importPollEvery = time.Millisecond
	var got map[string]string
	srv := captureServer(t, `{"id":"job1","state":"succeeded","result":{"output":"monitor \"pets\" (multistep)\n","monitor":{"name":"pets","kind":"multistep","config":{"steps":[]}}}}`, &got)
	defer srv.Close()
	dir := t.TempDir()
	spec := filepath.Join(dir, "spec.yaml")
	_ = os.WriteFile(spec, []byte("openapi: 3.0.0\n"), 0o600)
	outFile := filepath.Join(dir, "monitor.json")
	var out bytes.Buffer
	args := append([]string{"import-openapi", spec, "--base-url", "https://api.example.com", "--auth-secret", "TOKEN", "--name", "pets", "--out", outFile}, conn(srv)...)
	if err := checksMain(context.Background(), args, &out); err != nil {
		t.Fatal(err)
	}
	if got["source"] != "checks-openapi" || got["file:spec"] != "openapi: 3.0.0\n" || got["base_url"] != "https://api.example.com" ||
		got["auth_secret"] != "TOKEN" || got["name"] != "pets" || got["mode"] != "dry_run" {
		t.Fatalf("upload: %v", got)
	}
	if b, _ := os.ReadFile(outFile); !strings.Contains(string(b), `"kind":"multistep"`) {
		t.Fatalf("monitor file %q", b)
	}
}

func TestChecksRequireConnectionFlags(t *testing.T) {
	t.Setenv("WT_API", "")
	t.Setenv("WT_API_KEY", "")
	t.Setenv("WT_PROJECT", "")
	err := checksMain(context.Background(), []string{"import-openapi", "spec.yaml", "--base-url", "https://x"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "--api") {
		t.Fatalf("want the connection-flag error, got %v", err)
	}
}

func TestGuardedClientHonoursTheProxyEnvironment(t *testing.T) {
	// net/http reads the environment once per process, so only the wiring is checked here.
	h, isHeader := guardedClient(time.Second).Transport.(clientHeader) // names the version on every request
	if !isHeader {
		t.Fatal("the transport does not send X-WT-Client")
	}
	tr, ok := h.next.(*http.Transport)
	if !ok || tr.Proxy == nil {
		t.Fatal("the transport has no proxy function (D-85)")
	}
}

// conn is the API connection flags pointing at srv.
func conn(srv *httptest.Server) []string {
	return []string{"--api", srv.URL, "--key", "wtk_x", "--project", "prj_1"}
}
