package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// provServer is a fake API; posts counts POSTs per path.
func provServer(t *testing.T) (*httptest.Server, *map[string]int) {
	t.Helper()
	var mu sync.Mutex
	posts := map[string]int{}
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		page := func(rows string) { _, _ = w.Write([]byte(`{"data":` + rows + `,"next_cursor":null}`)) }
		if r.Method == "POST" {
			posts[r.URL.Path]++
			n++
			if r.Header.Get("Authorization") != "Bearer wtk_admin" {
				t.Errorf("auth header %q", r.Header.Get("Authorization"))
			}
		}
		switch {
		case r.URL.Path == "/v1/platforms/config":
			_, _ = w.Write([]byte(`{"ingest_url":"https://ingest.x","edge_url":"https://edge.x"}`))
		case r.URL.Path == "/v1/orgs":
			page(`[{"id":"org_1"}]`)
		case r.URL.Path == "/v1/orgs/org_1/projects" && r.Method == "GET":
			page(`[]`)
		case r.URL.Path == "/v1/orgs/org_1/projects":
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"id":"prj_1","slug":"shop"}`))
		case r.URL.Path == "/v1/projects/prj_1/environments" && r.Method == "GET":
			page(`[{"id":"env_1","name":"production"}]`)
		case r.URL.Path == "/v1/projects/prj_1/credentials":
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"token":"wti_secret` + string(rune('a'+n)) + `"}`))
		case r.URL.Path == "/v1/orgs/org_1/api-keys":
			var b map[string]any
			_ = json.NewDecoder(r.Body).Decode(&b)
			if b["role"] != "engineer" || b["project_id"] != "prj_1" || b["name"] != "wtctl provision shop" {
				t.Errorf("api key body %v", b)
			}
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"token":"wtk_cisecret` + string(rune('a'+n)) + `"}`))
		case r.URL.Path == "/v1/projects/prj_1/rum/keys":
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"key":"wtp_pub` + string(rune('a'+n)) + `"}`))
		default:
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"code":"not_found","detail":"nope"}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &posts
}

func runProv(t *testing.T, srv *httptest.Server, out string, extra ...string) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	args := append([]string{"--api", srv.URL, "--key", "wtk_admin", "--project", "shop", "--out", out}, extra...)
	err := provisionMain(context.Background(), args, &buf)
	return buf.String(), err
}

func TestProvisionCreateReuseRotate(t *testing.T) {
	srv, posts := provServer(t)
	out := filepath.Join(t.TempDir(), "watchtower.env")
	stdout, err := runProv(t, srv, out, "--origins", "https://a.example,https://b.example")
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(out)
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if strings.Contains(stdout, "wti_secret") || strings.Contains(stdout, "wtk_cisecret") || strings.Contains(stdout, "wtp_pub") {
		t.Fatalf("secret on stdout: %s", stdout)
	}
	env, _ := readEnvFile(out)
	for _, k := range []string{"WT_ORG_ID", "WT_PROJECT_ID", "WT_ENV_PRODUCTION", "WT_OTLP_ENDPOINT", "WT_EDGE_URL", "WT_INGEST_KEY", "WT_CI_API_KEY", "WT_RUM_KEY", "WT_RUM_ENDPOINT", "WT_RUM_SCRIPT_URL", "WT_RUM_ORIGINS"} {
		if env[k] == "" {
			t.Errorf("missing %s", k)
		}
	}
	if env["WT_RUM_SCRIPT_URL"] != "https://edge.x/sdk/v0/wt.min.js" || env["WT_OTLP_ENDPOINT"] != "https://ingest.x" {
		t.Errorf("urls %v", env)
	}
	first := *posts
	mints := func() int {
		return (*posts)["/v1/projects/prj_1/credentials"] + (*posts)["/v1/orgs/org_1/api-keys"] + (*posts)["/v1/projects/prj_1/rum/keys"]
	}
	if mints() != 3 || first["/v1/orgs/org_1/projects"] != 1 {
		t.Fatalf("posts %v", *posts)
	}

	// Reuse: a second run mints nothing and keeps the secrets.
	old := env["WT_INGEST_KEY"]
	if _, err := runProv(t, srv, out, "--origins", "https://a.example,https://b.example"); err != nil {
		t.Fatal(err)
	}
	if mints() != 3 {
		t.Fatalf("reuse minted: %v", *posts)
	}
	if env2, _ := readEnvFile(out); env2["WT_INGEST_KEY"] != old {
		t.Fatal("secret changed on reuse")
	}

	// Rotate: fresh secrets, file still 0600.
	if _, err := runProv(t, srv, out, "--origins", "https://a.example", "--rotate"); err != nil {
		t.Fatal(err)
	}
	if mints() != 6 {
		t.Fatalf("rotate: %v", *posts)
	}
	if env3, _ := readEnvFile(out); env3["WT_INGEST_KEY"] == old {
		t.Fatal("rotate kept the old secret")
	}
	if fi, _ := os.Stat(out); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode after rotate %v", fi.Mode())
	}
}

func TestProvisionJSONHasNoSecrets(t *testing.T) {
	srv, _ := provServer(t)
	out := filepath.Join(t.TempDir(), "w.env")
	stdout, err := runProv(t, srv, out, "--json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout, "secret") || !strings.Contains(stdout, "prj_1") {
		t.Fatalf("json: %s", stdout)
	}
}

func TestProvisionProblemError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`{"code":"forbidden","detail":"needs project_admin"}`))
	}))
	defer srv.Close()
	_, err := runProv(t, srv, filepath.Join(t.TempDir(), "w.env"))
	if err == nil || (!strings.Contains(err.Error(), "needs project_admin") && !strings.Contains(err.Error(), "refus")) {
		t.Fatalf("err %v", err)
	}
}
