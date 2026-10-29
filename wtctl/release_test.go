package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func run(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.email=dev@example.com", "-c", "user.name=dev", "-c", "commit.gpgsign=false"}, args...)...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
}

func TestReleaseCreateAutoCommits(t *testing.T) {
	dir := t.TempDir()
	run(t, dir, "init", "-q")
	for _, f := range []string{"a.txt", "b.txt"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(f), 0o644); err != nil {
			t.Fatal(err)
		}
		run(t, dir, "add", f)
		run(t, dir, "commit", "-q", "-m", "add "+f)
	}

	var rel struct {
		Version string
		Commits []commit
	}
	var deployed map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer k" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		b, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/v1/projects/prj_1/releases":
			_ = json.Unmarshal(b, &rel)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"rel_1"}`))
		case "/v1/projects/prj_1/environments":
			_, _ = w.Write([]byte(`{"data":[{"id":"env_1","name":"production"}]}`))
		case "/v1/projects/prj_1/deployments":
			_ = json.Unmarshal(b, &deployed)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	var out bytes.Buffer
	err := releaseMain(context.Background(), []string{"create", "1.0.0", "--api", srv.URL, "--key", "k",
		"--project", "prj_1", "--commits", "auto", "--deploy", "production", "--dir", dir}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if len(rel.Commits) != 2 || rel.Version != "1.0.0" {
		t.Fatalf("release = %+v", rel)
	}
	// Newest first, each with its changed file and author.
	c := rel.Commits[0]
	if c.Message != "add b.txt" || len(c.Files) != 1 || c.Files[0] != "b.txt" || c.AuthorEmail != "dev@example.com" {
		t.Fatalf("commit = %+v", c)
	}
	if deployed["env_id"] != "env_1" || deployed["version"] != "1.0.0" {
		t.Fatalf("deployment = %v", deployed)
	}
	if !strings.Contains(out.String(), "deployed to production") {
		t.Fatalf("out = %q", out.String())
	}
}

func TestGitCommitsCapsFiles(t *testing.T) {
	dir := t.TempDir()
	run(t, dir, "init", "-q")
	for i := 0; i < 600; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%03d.txt", i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run(t, dir, "add", ".")
	run(t, dir, "commit", "-q", "-m", "big")
	cs, err := gitCommits(context.Background(), dir, "auto")
	if err != nil || len(cs) != 1 {
		t.Fatalf("commits = %v, err = %v", cs, err)
	}
	if len(cs[0].Files) != 500 {
		t.Fatalf("files = %d, want 500", len(cs[0].Files))
	}
}

func TestParseLogDropsLongPaths(t *testing.T) {
	out := "\x1esha\x1fa@b.c\x1f2026-01-01T00:00:00Z\x1fmsg\n\nok.rs\n" + strings.Repeat("x", 2001) + "\n"
	cs := parseLog(out)
	if len(cs) != 1 || len(cs[0].Files) != 1 || cs[0].Files[0] != "ok.rs" {
		t.Fatalf("commits = %+v", cs)
	}
}
