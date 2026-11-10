package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type upload struct {
	kind, name, release, auth, encoding string
	body                                []byte
}

// artifactServer records uploads and answers status.
func artifactServer(t *testing.T, status int) (*httptest.Server, func() []upload) {
	t.Helper()
	var mu sync.Mutex
	var got []upload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/projects/prj_1/artifacts" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Errorf("body is not gzip: %v", err)
			return
		}
		b, _ := io.ReadAll(zr)
		q := r.URL.Query()
		mu.Lock()
		got = append(got, upload{q.Get("kind"), q.Get("name"), q.Get("release"), r.Header.Get("Authorization"), r.Header.Get("Content-Encoding"), b})
		mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"detail":"nope"}`))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []upload { mu.Lock(); defer mu.Unlock(); return got }
}

func write(t *testing.T, p string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSourcemapsUploadSendsRelativeNames(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "static", "app.js.map"), []byte(`{"version":3}`))
	write(t, filepath.Join(dir, "app.js"), []byte("x"))
	outside := t.TempDir()
	write(t, filepath.Join(outside, "secret.map"), []byte("secret"))
	if err := os.Symlink(filepath.Join(outside, "secret.map"), filepath.Join(dir, "link.map")); err != nil {
		t.Skip("no symlinks:", err)
	}
	srv, got := artifactServer(t, http.StatusCreated)
	o := artifactOpts{api: srv.URL + "/", key: "k", project: "prj_1", release: "1.0.0"}
	var out bytes.Buffer
	if err := sourcemapsUpload(context.Background(), o, dir, &out); err != nil {
		t.Fatal(err)
	}
	ups := got()
	if len(ups) != 1 {
		t.Fatalf("uploads = %+v (only the regular .map file, not the JS or the symlink)", ups)
	}
	u := ups[0]
	if u.kind != "sourcemap" || u.name != "static/app.js.map" || u.release != "1.0.0" || u.auth != "Bearer k" || u.encoding != "gzip" || string(u.body) != `{"version":3}` {
		t.Fatalf("upload = %+v", u)
	}
}

func TestSourcemapsUploadErrors(t *testing.T) {
	dir := t.TempDir()
	o := artifactOpts{api: "http://127.0.0.1:1", key: "k", project: "prj_1"}
	if err := sourcemapsUpload(context.Background(), o, dir, io.Discard); err == nil || !strings.Contains(err.Error(), "no .map") {
		t.Fatalf("empty dir: %v", err)
	}
	if err := sourcemapsUpload(context.Background(), o, filepath.Join(dir, "missing"), io.Discard); err == nil {
		t.Fatal("missing dir must fail")
	}
	write(t, filepath.Join(dir, "a.map"), []byte("{}"))
	srv, _ := artifactServer(t, http.StatusUnprocessableEntity)
	o.api = srv.URL
	err := sourcemapsUpload(context.Background(), o, dir, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "422") || !strings.Contains(err.Error(), "a.map") {
		t.Fatalf("server refusal must name the file and status: %v", err)
	}
	if err := uploadArtifact(context.Background(), o, "sourcemap", "big.map", make([]byte, maxArtifactBytes+1)); err == nil {
		t.Fatal("oversize file must be refused before sending")
	}
	if err := sourcemapsMain(context.Background(), []string{"upload"}, io.Discard); err == nil {
		t.Fatal("usage error expected")
	}
	if err := sourcemapsMain(context.Background(), []string{"upload", dir}, io.Discard); err == nil {
		t.Fatal("--api/--key/--project are required")
	}
}

func TestDebugFilesDetectKindAndSkipOthers(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "lib.so"), append([]byte("\x7fELF"), make([]byte, 60)...))
	write(t, filepath.Join(dir, "App.pdb"), append([]byte("Microsoft C/C++ MSF 7.00\r\n"), make([]byte, 60)...))
	write(t, filepath.Join(dir, "mac", "app"), []byte{0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0})
	write(t, filepath.Join(dir, "mapping.txt"), []byte("a.B -> c:\n"))
	write(t, filepath.Join(dir, "notes.txt"), []byte("hello"))
	write(t, filepath.Join(dir, "Symbols", "LineNumberMappings.json"), []byte(`{"a.cpp": {"a.cs": {"1": 1}}}`))
	write(t, filepath.Join(dir, "fat"), []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2})
	srv, got := artifactServer(t, http.StatusCreated)
	o := artifactOpts{api: srv.URL, key: "k", project: "prj_1"}
	var out bytes.Buffer
	if err := debugFilesUpload(context.Background(), o, []string{dir}, &out); err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for _, u := range got() {
		kinds[u.name] = u.kind
	}
	want := map[string]string{"lib.so": "elf", "App.pdb": "pdb", "mac/app": "macho", "mapping.txt": "proguard", "Symbols/LineNumberMappings.json": "il2cpp"}
	if len(kinds) != len(want) {
		t.Fatalf("kinds = %v", kinds)
	}
	for n, k := range want {
		if kinds[n] != k {
			t.Errorf("%s: %q, want %q", n, kinds[n], k)
		}
	}
	if !strings.Contains(out.String(), "skipped notes.txt") || !strings.Contains(out.String(), "skipped fat") {
		t.Errorf("skips not reported:\n%s", out.String())
	}
	if err := debugFilesUpload(context.Background(), o, []string{filepath.Join(dir, "notes.txt")}, io.Discard); err == nil {
		t.Fatal("nothing uploadable must be an error")
	}
	if err := debugFilesMain(context.Background(), []string{"upload", "--api", "x"}, io.Discard); err == nil {
		t.Fatal("paths are required")
	}
}

func TestSourcemapsUploadReadsEnvAndCreatesTheRelease(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("WT_API", srv.URL)
	t.Setenv("WT_API_KEY", "k")
	t.Setenv("WT_PROJECT", "prj_1")
	dir := t.TempDir()
	write(t, filepath.Join(dir, "a.js.map"), []byte(`{"version":3}`))
	if err := sourcemapsMain(context.Background(), []string{"upload", dir, "--release", "1.0.0"}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || paths[0] != "POST /v1/projects/prj_1/releases" || paths[1] != "POST /v1/projects/prj_1/artifacts" {
		t.Fatalf("calls = %v", paths)
	}
}
