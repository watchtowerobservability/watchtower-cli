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

func TestConvertCpuprofileToFolded(t *testing.T) {
	const prof = `{"nodes":[
	 {"id":1,"callFrame":{"functionName":"(root)","url":"","lineNumber":-1},"children":[2]},
	 {"id":2,"callFrame":{"functionName":"main","url":"app.js","lineNumber":0},"children":[3]},
	 {"id":3,"callFrame":{"functionName":"","url":"","lineNumber":0}}],
	 "samples":[3,3,2]}`
	f := filepath.Join(t.TempDir(), "x.cpuprofile")
	if err := os.WriteFile(f, []byte(prof), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := convertCpuprofile(f, &out); err != nil {
		t.Fatal(err)
	}
	want := "(root);main (app.js:1) 1\n(root);main (app.js:1);(anonymous) 2\n"
	if out.String() != want {
		t.Fatalf("got %q want %q", out.String(), want)
	}
}

func TestUploadCommandPostsFormatFolded(t *testing.T) {
	var gotQuery, gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotQuery, gotAuth, gotBody = r.URL.RawQuery, r.Header.Get("Authorization"), string(b)
		if r.URL.Path != "/v1/profiles" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"profile_id":"p1"}`)
	}))
	defer srv.Close()
	f := filepath.Join(t.TempDir(), "cpu.folded")
	if err := os.WriteFile(f, []byte("a;b 3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := profileMain(context.Background(), []string{"upload", f, "--endpoint", srv.URL, "--key", "wti_k", "--service", "checkout", "--version", "1.2"}, &out)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"service=checkout", "version=1.2", "format=folded"} {
		if !strings.Contains(gotQuery, w) {
			t.Errorf("query %q lacks %s", gotQuery, w)
		}
	}
	if gotAuth != "Bearer wti_k" || gotBody != "a;b 3\n" {
		t.Fatalf("auth=%q body=%q", gotAuth, gotBody)
	}
}

func TestProfileTopCallsAPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/projects/prj_1/profiles/top" || r.URL.Query().Get("service") != "checkout" {
			t.Errorf("unexpected %s", r.URL)
		}
		_, _ = io.WriteString(w, `{"data":[{"function":"main"}]}`)
	}))
	defer srv.Close()
	var out bytes.Buffer
	args := []string{"top", "checkout", "--api", srv.URL, "--key", "k", "--project", "prj_1"}
	if err := profileMain(context.Background(), args, &out); err != nil || !strings.Contains(out.String(), "main") {
		t.Fatalf("err=%v out=%q", err, out.String())
	}
}
