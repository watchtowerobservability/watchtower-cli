package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSourcemapsBundleRetryAndFallback(t *testing.T) {
	retryBase = time.Millisecond
	dir := t.TempDir()
	write(t, filepath.Join(dir, "a.js.map"), []byte("{}"))
	write(t, filepath.Join(dir, "b.js.map"), []byte("{}"))
	var bundleCalls, single atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/artifacts/bundle"):
			if bundleCalls.Add(1) == 1 {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(429)
				return
			}
			_, _ = io.WriteString(w, `{"uploaded":2,"skipped":0,"failed":0,"errors":[]}`)
		default:
			single.Add(1)
			w.WriteHeader(201)
		}
	}))
	defer srv.Close()
	o := artifactOpts{api: srv.URL, key: "k", project: "p", release: "r", bundle: true, del: true}
	var out bytes.Buffer
	if err := sourcemapsUpload(context.Background(), o, dir, &out); err != nil {
		t.Fatal(err, out.String())
	}
	if bundleCalls.Load() != 2 || single.Load() != 0 || !strings.Contains(out.String(), "2 uploaded") {
		t.Fatalf("calls bundle=%d single=%d out=%s", bundleCalls.Load(), single.Load(), out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "a.js.map")); err == nil {
		t.Fatal("--delete must remove stored maps")
	}
}

func TestSourcemapsFallbackPerFileAndFailureExit(t *testing.T) {
	retryBase = time.Millisecond
	dir := t.TempDir()
	write(t, filepath.Join(dir, "a.map"), []byte("{}"))
	write(t, filepath.Join(dir, "bad.map"), []byte("{}"))
	var tries atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/bundle"):
			w.WriteHeader(404)
		case r.URL.Query().Get("name") == "bad.map":
			tries.Add(1)
			w.WriteHeader(503)
		default:
			w.WriteHeader(201)
		}
	}))
	defer srv.Close()
	o := artifactOpts{api: srv.URL, key: "k", project: "p", bundle: true, concurrency: 2}
	var out bytes.Buffer
	err := sourcemapsUpload(context.Background(), o, dir, &out)
	if err == nil || !strings.Contains(err.Error(), "1 of 2") || tries.Load() != maxTries {
		t.Fatalf("err=%v tries=%d out=%s", err, tries.Load(), out.String())
	}
}

func TestDeployRecordsOneDeploymentPerService(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, r.Method+" "+r.URL.Path+" "+string(b))
		if r.Method == "GET" {
			_, _ = io.WriteString(w, `{"data":[{"id":"env_9","name":"production"}]}`)
			return
		}
		w.WriteHeader(201)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer srv.Close()
	t.Setenv("GITHUB_ACTIONS", "true")
	var out bytes.Buffer
	args := []string{"--api", srv.URL, "--key", "k", "--project", "p", "--release", "abc1234", "--services", "api, worker", "--dir", t.TempDir()}
	if err := deployMain(context.Background(), args, &out); err != nil {
		t.Fatal(err)
	}
	dep := 0
	for _, g := range got {
		if strings.HasPrefix(g, "POST /v1/projects/p/deployments") {
			dep++
			var m map[string]any
			_ = json.Unmarshal([]byte(strings.SplitN(g, " ", 3)[2]), &m)
			if m["env_id"] != "env_9" || m["source"] != "github-actions" || m["version"] != "abc1234" {
				t.Fatalf("deployment body %v", m)
			}
		}
	}
	if dep != 2 || !strings.HasPrefix(got[0], "POST /v1/projects/p/releases") {
		t.Fatalf("calls: %v", got)
	}
}

func TestInitDetectsStackAndKeepsKeysUncreated(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "package.json"), []byte(`{"dependencies":{"next":"1","pg":"1","ioredis":"1"}}`))
	var out bytes.Buffer
	if err := initMain(context.Background(), []string{"--dir", dir}, &out); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "watchtower.yaml"))
	for _, want := range []string{"postgres-tcp", "redis-tcp", "services:"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("starter lacks %s:\n%s", want, b)
		}
	}
	if !strings.Contains(out.String(), "wta_") || !strings.Contains(out.String(), "ci:write") {
		t.Errorf("key help missing: %s", out.String())
	}
	if err := initMain(context.Background(), []string{"--dir", dir}, &out); err == nil {
		t.Fatal("second init must refuse to overwrite")
	}
}

func TestInitCreateKeysReusesAccountAndPrintsTokenOnce(t *testing.T) {
	var posts []string
	accounts := `{"data":[]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		switch {
		case r.URL.Path == "/v1/projects/prj_1":
			_, _ = io.WriteString(w, `{"org_id":"org_1"}`)
		case r.Method == "GET":
			_, _ = io.WriteString(w, accounts)
		case strings.HasSuffix(r.URL.Path, "/keys"):
			posts = append(posts, "key "+string(b))
			w.WriteHeader(201)
			_, _ = io.WriteString(w, `{"token":"wta_secret"}`)
		default:
			posts = append(posts, "account "+string(b))
			w.WriteHeader(201)
			_, _ = io.WriteString(w, `{"id":"sa_1","name":"wtctl-ci"}`)
		}
	}))
	defer srv.Close()
	run := func() (string, string) {
		dir := t.TempDir()
		var out bytes.Buffer
		if err := initMain(context.Background(), []string{"--dir", dir, "--create-keys", "--api", srv.URL, "--key", "k", "--project", "prj_1"}, &out); err != nil {
			t.Fatal(err)
		}
		files, _ := os.ReadDir(dir)
		for _, f := range files {
			if b, _ := os.ReadFile(filepath.Join(dir, f.Name())); strings.Contains(string(b), "wta_secret") {
				t.Fatal("token written to a file")
			}
		}
		return out.String(), strings.Join(posts, "\n")
	}
	out, p := run()
	if !strings.Contains(out, "wta_secret") || !strings.Contains(out, "Store it now") ||
		!strings.Contains(p, `account {"name":"wtctl-ci","projects":["prj_1"],"role":"engineer"}`) ||
		!strings.Contains(p, `"scopes":["ci:write","events:write","monitors:write"]`) || !strings.Contains(p, `"project_id":"prj_1"`) {
		t.Fatalf("out=%s posts=%s", out, p)
	}
	posts, accounts = nil, `{"data":[{"id":"sa_1","name":"wtctl-ci"}]}`
	if _, p = run(); strings.Contains(p, "account ") || !strings.Contains(p, "key ") {
		t.Fatalf("existing account must be reused: %s", p)
	}
}
