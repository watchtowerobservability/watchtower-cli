package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// api fakes the check-runs endpoints: the run reports `final` after one poll.
func api(t *testing.T, final string, results []runResult) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer wtk_ok" {
			http.NotFound(w, r)
			return
		}
		doc := runDoc{ID: "run-1", Tag: "ci", Status: "running", Results: []runResult{{Name: "api", Status: "pending"}}}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/projects/prj_1/check-runs":
			w.WriteHeader(http.StatusAccepted)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects/prj_1/check-runs/run-1":
			doc.Status, doc.Results = final, results
		default:
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(doc)
	}))
}

func runCLI(t *testing.T, srv *httptest.Server, extra ...string) (int, string) {
	t.Helper()
	var out, errb bytes.Buffer
	args := append([]string{"--api", srv.URL, "--key", "wtk_ok", "--project", "prj_1", "--wait", "--poll", "1ms"}, extra...)
	code := checksRun(t.Context(), args, &out, &errb)
	return code, out.String() + errb.String()
}

func TestWtctlChecksRunExitCode(t *testing.T) {
	pass := api(t, "passed", []runResult{{Name: "api", Status: "passed"}})
	defer pass.Close()
	if code, out := runCLI(t, pass); code != 0 {
		t.Fatalf("passing run exit = %d: %s", code, out)
	}
	fail := api(t, "failed", []runResult{{Name: "api", Status: "failed", Error: "status 500"}})
	defer fail.Close()
	if code, out := runCLI(t, fail); code != 1 || !strings.Contains(out, "FAIL api: status 500") {
		t.Fatalf("failing run exit = %d: %s", code, out)
	}
	// errors are 2, never 1: a bad key, missing flags, a run that timed out on the server
	if code := checksRun(t.Context(), []string{"--api", pass.URL, "--key", "bad", "--project", "prj_1"}, &bytes.Buffer{}, &bytes.Buffer{}); code != 2 {
		t.Fatalf("bad key exit = %d", code)
	}
	if code := checksRun(t.Context(), []string{}, &bytes.Buffer{}, &bytes.Buffer{}); code != 2 {
		t.Fatalf("no flags exit = %d", code)
	}
	late := api(t, "timed_out", []runResult{{Name: "api", Status: "pending"}})
	defer late.Close()
	if code, _ := runCLI(t, late); code != 2 {
		t.Fatalf("server-side timeout exit = %d", code)
	}
	stuck := api(t, "running", nil)
	defer stuck.Close()
	if code, out := runCLI(t, stuck, "--timeout", "20ms"); code != 2 || !strings.Contains(out, "timed out") {
		t.Fatalf("client timeout exit = %d: %s", code, out)
	}
}

func TestRunOptsBody(t *testing.T) {
	o := runOpts{
		tag: "ci", startURL: "https://pr-42.example.com",
		vars: map[string]string{"ENV": "pr-42"}, locations: []string{"eu"}, ids: []string{"mon_a"},
	}
	b := o.body()
	if got := b["monitor_ids"].([]string); len(got) != 1 || got[0] != "mon_a" {
		t.Fatalf("monitor_ids = %v", b["monitor_ids"])
	}
	ov := b["overrides"].(map[string]any)
	if ov["start_url"] != "https://pr-42.example.com" {
		t.Fatalf("start_url = %v", ov["start_url"])
	}
	if ov["variables"].(map[string]string)["ENV"] != "pr-42" || ov["locations"].([]string)[0] != "eu" {
		t.Fatalf("overrides = %v", ov)
	}
	// a plain tag run carries no overrides key
	if _, ok := (runOpts{tag: "ci"}).body()["overrides"]; ok {
		t.Fatal("bare run should not carry overrides")
	}
}

func TestJUnitOutput(t *testing.T) {
	srv := api(t, "failed", []runResult{
		{Name: "api", Status: "passed"},
		{Name: "checkout", Status: "failed", Error: `status 500 <"boom">`},
		{Name: "slow", Status: "pending"},
	})
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "out.xml")
	if code, out := runCLI(t, srv, "--junit", path); code != 1 {
		t.Fatalf("exit = %d: %s", code, out)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc junitSuites
	if err := xml.Unmarshal(b, &doc); err != nil {
		t.Fatalf("not valid XML: %v\n%s", err, b)
	}
	s := doc.Suites[0]
	if s.Tests != 3 || s.Failures != 1 || s.Errors != 1 || s.Cases[1].Failure.Message != `status 500 <"boom">` {
		t.Fatalf("suite = %+v\n%s", s, b)
	}
	if code := checksRun(t.Context(), []string{"--api", srv.URL, "--key", "wtk_ok", "--project", "prj_1", "--junit", path}, &bytes.Buffer{}, &bytes.Buffer{}); code != 2 {
		t.Fatalf("--junit without --wait exit = %d", code)
	}
}
