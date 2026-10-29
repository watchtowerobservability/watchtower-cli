package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// ttServer answers the start call and then the run list; the first list is still running.
func ttServer(t *testing.T, final string) *httptest.Server {
	var polls atomic.Int32
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer k" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/projects/prj_1/trace-test-suites/s1/runs":
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"ref":"ref1","runs":[{"id":"r1","test_name":"checkout","state":"pending"}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects/prj_1/trace-test-runs":
			if r.URL.Query().Get("ref") != "ref1" {
				t.Errorf("ref = %q", r.URL.Query().Get("ref"))
			}
			if polls.Add(1) == 1 {
				_, _ = w.Write([]byte(`{"data":[{"id":"r1","test_name":"checkout","state":"running"}]}`))
				return
			}
			_, _ = w.Write([]byte(final))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
}

func runTT(t *testing.T, srv *httptest.Server, junit string) (int, string) {
	args := []string{"--api", srv.URL, "--key", "k", "--project", "prj_1", "--suite", "s1", "--wait", "--poll", "5ms"}
	if junit != "" {
		args = append(args, "--junit", junit)
	}
	var out bytes.Buffer
	code := traceTestRun(context.Background(), args, &out, &out)
	return code, out.String()
}

func TestWtctlRunExitCodeAndJunit(t *testing.T) {
	failed := `{"data":[{"id":"r1","test_name":"checkout","state":"failed","result":{"error":"assertion failed",
		"assertions":[{"name":"status == 200","ok":true},{"name":"{ db }","ok":false,"detail":"0 spans matched"}]}}]}`
	srv := ttServer(t, failed)
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "out.xml")
	code, out := runTT(t, srv, path)
	if code != exitFail || !strings.Contains(out, "FAILED checkout") {
		t.Fatalf("code=%d out=%q", code, out)
	}
	xml, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`tests="2"`, `failures="1"`, `message="0 spans matched"`} {
		if !strings.Contains(string(xml), want) {
			t.Errorf("junit lacks %s:\n%s", want, xml)
		}
	}

	ok := ttServer(t, `{"data":[{"id":"r1","test_name":"checkout","state":"passed"}]}`)
	defer ok.Close()
	if code, out := runTT(t, ok, ""); code != exitPass {
		t.Fatalf("passing suite: code=%d out=%q", code, out)
	}
}

func TestWtctlRunTimeoutIsExitError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_, _ = w.Write([]byte(`{"ref":"ref1","runs":[]}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"r1","test_name":"t","state":"running"}]}`))
	}))
	defer srv.Close()
	var out bytes.Buffer
	code := traceTestRun(context.Background(), []string{"--api", srv.URL, "--key", "k", "--project", "p", "--suite", "s",
		"--wait", "--timeout", "30ms", "--poll", "5ms"}, &out, &out)
	if code != exitError || !strings.Contains(out.String(), "timed out") {
		t.Fatalf("code=%d out=%q", code, out.String())
	}
}
