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
	"time"
)

func TestDetectLang(t *testing.T) {
	for marker, want := range map[string]string{"go.mod": "go", "package.json": "node", "Gemfile": "ruby", "Cargo.toml": "rust", "App.csproj": "dotnet"} {
		d := t.TempDir()
		if err := os.WriteFile(filepath.Join(d, marker), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if got := detectLang(d); got != want {
			t.Fatalf("%s: got %q want %q", marker, got, want)
		}
	}
	if detectLang(t.TempDir()) != "" {
		t.Fatal("empty dir must be unknown")
	}
}

func TestTemplatesNeverHoldSecrets(t *testing.T) {
	for lang, in := range instrumentTemplates {
		if len(in.Files) == 0 {
			t.Fatalf("%s: no files", lang)
		}
		for _, f := range in.Files {
			if strings.Contains(f.Content, "wti_") || strings.Contains(f.Content, "http://") || strings.Contains(f.Content, "https://") {
				t.Fatalf("%s/%s embeds an endpoint or key", lang, f.Path)
			}
			if !strings.Contains(f.Content, "WT_") {
				t.Fatalf("%s/%s must read its settings from WT_* variables", lang, f.Path)
			}
		}
	}
}

func TestApplyKeepsExistingFiles(t *testing.T) {
	d := t.TempDir()
	_ = os.WriteFile(filepath.Join(d, "package.json"), []byte("{}"), 0o644)
	var out bytes.Buffer
	if err := instrumentMain(context.Background(), []string{"apply", "--dir", d}, &out); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(d, "watchtower-otel.js")
	_ = os.WriteFile(p, []byte("mine"), 0o644)
	if err := instrumentMain(context.Background(), []string{"apply", "--dir", d}, &out); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "mine" || !strings.Contains(out.String(), "kept existing") {
		t.Fatalf("overwrote a user file: %q", b)
	}
}

func TestSafeBranchNeverDefault(t *testing.T) {
	if safeBranch("main", "main") || safeBranch("feature/x", "main") || safeBranch("watchtower/x", "") || !safeBranch("watchtower/x", "main") {
		t.Fatal("branch guard wrong")
	}
	if safeBranch("watchtower/instrument", "watchtower/instrument") {
		t.Fatal("a default branch under watchtower/ must still be refused")
	}
}

func TestOpenPRIsDraftOnNewBranch(t *testing.T) {
	var pull map[string]any
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/repos/o/r":
			_, _ = w.Write([]byte(`{"default_branch":"main"}`))
		case r.URL.Path == "/repos/o/r/pulls":
			_ = json.NewDecoder(r.Body).Decode(&pull)
			_, _ = w.Write([]byte(`{"html_url":"https://github.com/o/r/pull/1"}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer gh.Close()
	var git []string
	p := prOpener{HTTP: gh.Client(), GitHub: gh.URL, Token: "t", Repo: "o/r", Dir: ".",
		Git: func(_ context.Context, _ string, args ...string) error {
			git = append(git, strings.Join(args, " "))
			return nil
		}}
	u, err := p.Open(context.Background(), []string{"a.js"}, instrumentTemplates["node"], time.Unix(0, 0))
	if err != nil || u != "https://github.com/o/r/pull/1" {
		t.Fatalf("%q %v", u, err)
	}
	if pull["draft"] != true || pull["base"] != "main" || !strings.HasPrefix(pull["head"].(string), "watchtower/instrument-") {
		t.Fatalf("pull %v", pull)
	}
	for _, g := range git {
		if strings.Contains(g, "main") || strings.Contains(g, "--force") {
			t.Fatalf("git touched the default branch or forced: %s", g)
		}
	}
}

func TestPRNeedsProjectOptIn(t *testing.T) {
	for allow, wantErr := range map[string]bool{`{"allow_pr_creation":false}`: true, `{"allow_pr_creation":true}`: false} {
		api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(allow)) }))
		err := prAllowed(context.Background(), api.Client(), api.URL, "k", "p1")
		api.Close()
		if (err != nil) != wantErr {
			t.Fatalf("%s: err=%v", allow, err)
		}
	}
	gone := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(404) }))
	defer gone.Close()
	if prAllowed(context.Background(), gone.Client(), gone.URL, "k", "p1") == nil {
		t.Fatal("a 404 must refuse")
	}
}

func TestSkillsInstall(t *testing.T) {
	d := t.TempDir()
	var out bytes.Buffer
	if err := skillsMain([]string{"install", "--dir", d}, &out); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"watchtower-instrument", "watchtower-investigate"} {
		if b, err := os.ReadFile(filepath.Join(d, n, "SKILL.md")); err != nil || !strings.HasPrefix(string(b), "---\nname: "+n) {
			t.Fatalf("%s: %v", n, err)
		}
	}
}
