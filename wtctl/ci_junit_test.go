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

func TestCiUploadJunitSendsMultipart(t *testing.T) {
	var fields map[string]string
	var file string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/projects/prj_1/test-runs" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer k" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Errorf("not multipart: %v", err)
			return
		}
		fields = map[string]string{}
		for k, v := range r.MultipartForm.Value {
			fields[k] = v[0]
		}
		f, _, err := r.FormFile("file")
		if err != nil {
			t.Errorf("no file: %v", err)
			return
		}
		b, _ := io.ReadAll(f)
		file = string(b)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"tests":1}`))
	}))
	defer srv.Close()
	p := filepath.Join(t.TempDir(), "r.xml")
	xml := `<testsuite name="u"><testcase name="a"/></testsuite>`
	if err := os.WriteFile(p, []byte(xml), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	args := []string{"upload-junit", p, "--api", srv.URL, "--key", "k", "--project", "prj_1",
		"--run-id", "r9", "--sha", "abc", "--coverage", "80"}
	if err := ciMain(context.Background(), args, &out); err != nil {
		t.Fatal(err)
	}
	if fields["run_id"] != "r9" || fields["sha"] != "abc" || fields["coverage_pct"] != "80" {
		t.Errorf("fields = %v", fields)
	}
	if _, ok := fields["branch"]; ok {
		t.Errorf("empty branch must not be sent: %v", fields)
	}
	if file != xml {
		t.Errorf("file = %q", file)
	}
	if !strings.Contains(out.String(), `"tests":1`) {
		t.Errorf("out = %q", out.String())
	}
}

func TestCiUploadJunitErrors(t *testing.T) {
	var out bytes.Buffer
	if err := ciMain(context.Background(), []string{"upload-junit", "x.xml"}, &out); err == nil {
		t.Error("missing flags must fail")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusUnprocessableEntity)
	}))
	defer srv.Close()
	_, err := uploadJunit(context.Background(), srv.Client(),
		junitUpload{api: srv.URL, key: "k", project: "p", runID: "r"}, []byte("<x/>"))
	if err == nil || !strings.Contains(err.Error(), "422") {
		t.Errorf("err = %v", err)
	}
	big := make([]byte, maxJunitBytes)
	if _, err := uploadJunit(context.Background(), srv.Client(), junitUpload{api: srv.URL}, big); err == nil {
		t.Error("over the limit must fail before sending")
	}
}
