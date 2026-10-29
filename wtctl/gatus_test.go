package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestWtctlGatusConfigNoSecrets(t *testing.T) {
	// The API lists tokens with their non-secret prefix; none of it may reach the output.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/projects/prj_1/environments":
			_, _ = w.Write([]byte(`{"data":[{"id":"env_1","name":"prod"},{"id":"env_2","name":"staging"}],"next_cursor":null}`))
		case "/v1/projects/prj_1/health-tokens":
			_, _ = w.Write([]byte(`{"data":[
			 {"id":"t1","name":"whole","prefix":"wth_abcd1234","env_id":null,"service":null,"revoked_at":null},
			 {"id":"t2","name":"checkout","prefix":"wth_efgh5678","env_id":"env_1","service":"checkout","revoked_at":null},
			 {"id":"t3","name":"staging","prefix":"wth_ijkl9012","env_id":"env_2","service":null,"revoked_at":null},
			 {"id":"t4","name":"old","prefix":"wth_mnop3456","env_id":"env_1","service":"old","revoked_at":"2026-10-01T00:00:00Z"}],"next_cursor":null}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	var out bytes.Buffer
	args := []string{"config", "--api", srv.URL, "--key", "wtk_secretapikey", "--project", "shop", "--project-id", "prj_1", "--public-url", "https://wt.example.com"}
	if err := gatusMain(context.Background(), args, &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if regexp.MustCompile(`wth_|wtk_|secretapikey`).MatchString(got) {
		t.Fatalf("output carries a token-looking string:\n%s", got)
	}
	for _, want := range []string{
		`"https://wt.example.com/v1/health/shop"`,
		`"https://wt.example.com/v1/health/shop/prod/checkout"`,
		`"https://wt.example.com/v1/health/shop/staging"`,
		"Bearer ${WT_HEALTH_TOKEN_1}", "Bearer ${WT_HEALTH_TOKEN_3}",
		"external-endpoints:", "${WT_GATUS_SELF_TOKEN}", "interval: 3m",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "/old") || strings.Contains(got, "WT_HEALTH_TOKEN_4") {
		t.Errorf("revoked token exported:\n%s", got)
	}

	out.Reset()
	if err := gatusMain(context.Background(), append(args, "--env", "prod"), &out); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); strings.Contains(got, "/staging") || !strings.Contains(got, "shop/prod/checkout") || strings.Contains(got, "health/shop\"") {
		t.Errorf("--env prod filter wrong:\n%s", got)
	}
}

func TestWtctlGatusConfigRequiresProjectID(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer srv.Close()
	err := gatusMain(context.Background(), []string{"config", "--api", srv.URL, "--key", "k", "--project", "shop"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "--project-id") || called {
		t.Fatalf("err %v, API called %v", err, called)
	}
}
