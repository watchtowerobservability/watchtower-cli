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

// importServer fakes the two import routes: the POST answers queued, the GET answers running once
// and then the final state.
func importServer(t *testing.T, final string, got *map[string]string) *httptest.Server {
	t.Helper()
	polls := 0
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer wtk_x" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/projects/prj_1/imports":
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				t.Errorf("multipart: %v", err)
			}
			m := map[string]string{"source": r.FormValue("source"), "mode": r.FormValue("mode"), "dataset": r.FormValue("dataset")}
			for role := range r.MultipartForm.File {
				f, _, _ := r.FormFile(role)
				var b bytes.Buffer
				_, _ = b.ReadFrom(f)
				m["file:"+role] = b.String()
			}
			*got = m
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

func TestImportUploadsAndPolls(t *testing.T) {
	importPollEvery = time.Millisecond
	var got map[string]string
	srv := importServer(t, `{"id":"job1","state":"succeeded","result":{"output":"would create 1 alert_rule\n","report":{"mapped":1},"markdown":"# Import report\n"}}`, &got)
	defer srv.Close()
	dir := t.TempDir()
	alerts := filepath.Join(dir, "alerts.json")
	_ = os.WriteFile(alerts, []byte(`{"policies":[]}`), 0o600)
	report := filepath.Join(dir, "rep")
	var out bytes.Buffer
	err := importMain(context.Background(), []string{"newrelic", "--alerts", alerts, "--report", report,
		"--api", srv.URL, "--key", "wtk_x", "--project", "prj_1"}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if got["source"] != "newrelic" || got["mode"] != "dry_run" || got["file:alerts"] != `{"policies":[]}` {
		t.Fatalf("upload: %v", got)
	}
	if !strings.Contains(out.String(), "would create 1 alert_rule") {
		t.Fatalf("output %q", out.String())
	}
	if b, _ := os.ReadFile(report + ".json"); !strings.Contains(string(b), `"mapped":1`) {
		t.Fatalf("report.json %q", b)
	}
	if b, _ := os.ReadFile(report + ".md"); !strings.HasPrefix(string(b), "# Import report") {
		t.Fatalf("report.md %q", b)
	}
}

func TestImportApplyAndFailure(t *testing.T) {
	importPollEvery = time.Millisecond
	var got map[string]string
	srv := importServer(t, `{"id":"job1","state":"failed","error":"boom"}`, &got)
	defer srv.Close()
	dir := t.TempDir()
	f := filepath.Join(dir, "d.json")
	_ = os.WriteFile(f, []byte(`{}`), 0o600)
	err := importMain(context.Background(), []string{"kibana", "--dashboards", f, "--apply", "--report", filepath.Join(dir, "r"),
		"--api", srv.URL, "--key", "wtk_x", "--project", "prj_1"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("want the job error, got %v", err)
	}
	if got["mode"] != "apply" {
		t.Fatalf("mode %q", got["mode"])
	}
}

func TestImportRefusesUnknownSourceAndMissingFile(t *testing.T) {
	for _, args := range [][]string{{"pagerduty"}, {"newrelic", "--api", "http://x", "--key", "k", "--project", "p"}} {
		if err := importMain(context.Background(), args, &bytes.Buffer{}); err == nil {
			t.Errorf("%v must fail", args)
		}
	}
}

func TestDatasetsImportUploadsTheFile(t *testing.T) {
	importPollEvery = time.Millisecond
	var got map[string]string
	srv := importServer(t, `{"id":"job1","state":"succeeded","result":{"output":"pushed 1 items\n"}}`, &got)
	defer srv.Close()
	f := filepath.Join(t.TempDir(), "items.jsonl")
	_ = os.WriteFile(f, []byte(`{"input":"a"}`+"\n"), 0o600)
	var out bytes.Buffer
	err := datasetsMain(context.Background(), []string{"import", f, "--dataset", "math", "--format", "langfuse", "--create",
		"--api", srv.URL, "--key", "wtk_x", "--project", "prj_1"}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if got["source"] != "dataset-langfuse" || got["dataset"] != "math" || got["mode"] != "apply" || !strings.Contains(out.String(), "pushed 1 items") {
		t.Fatalf("upload %v out %q", got, out.String())
	}
}
