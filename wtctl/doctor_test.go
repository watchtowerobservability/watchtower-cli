package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestKeyPrefixNeverShowsTheSecret(t *testing.T) {
	if got := keyPrefix("wtk_abcd1234secret"); got != "wtk_abcd..." {
		t.Fatalf("%q", got)
	}
	if keyPrefix("") != "" {
		t.Fatal("empty")
	}
}

func TestEnvSaysWhereValuesCameFrom(t *testing.T) {
	t.Setenv("WT_API", "https://x.example")
	t.Setenv("WT_API_KEY", "wtk_abcd1234secret")
	t.Setenv("WT_PROJECT", "")
	var b bytes.Buffer
	_ = envMain(context.Background(), nil, &b)
	s := b.String()
	if !strings.Contains(s, "$WT_API") || strings.Contains(s, "secret") || !strings.Contains(s, "unset") {
		t.Fatalf("%s", s)
	}
}

func TestDoctorFlagsAnIngestKeyAndPrintsTheFix(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/platforms/config" {
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()
	t.Setenv("WT_API", srv.URL)
	t.Setenv("WT_API_KEY", "wti_abcd1234")
	t.Setenv("WT_PROJECT", "prj_1")
	var b bytes.Buffer
	if err := doctorMain(context.Background(), nil, &b); err == nil {
		t.Fatal("want a failing exit")
	}
	if !strings.Contains(b.String(), "cannot call the API") || !strings.Contains(b.String(), "fix:") {
		t.Fatalf("%s", b.String())
	}
}

func TestDoctorPrintsTheKeysRealScopes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/key":
			_, _ = w.Write([]byte(`{"kind":"service_account_key","prefix":"wta_cd34","name":"bot","scopes":["query:read"]}`))
		case "/v1/platforms/config":
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()
	t.Setenv("WT_API", srv.URL)
	t.Setenv("WT_API_KEY", "wta_cd34secret")
	t.Setenv("WT_PROJECT", "prj_1")
	var b bytes.Buffer
	_ = doctorMain(context.Background(), nil, &b)
	if !strings.Contains(b.String(), "scopes: query:read") || strings.Contains(b.String(), "guessed") || strings.Contains(b.String(), "secret") {
		t.Fatalf("%s", b.String())
	}
}

func TestDoctorFallsBackToThePrefixOn404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/key" {
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("WT_API", srv.URL)
	t.Setenv("WT_API_KEY", "wtk_ab12secret")
	t.Setenv("WT_PROJECT", "")
	var b bytes.Buffer
	_ = doctorMain(context.Background(), nil, &b)
	if !strings.Contains(b.String(), "guessed from the prefix") {
		t.Fatalf("%s", b.String())
	}
}
