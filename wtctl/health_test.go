package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func healthServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/platforms/config":
			_, _ = w.Write([]byte(`{}`))
		case "/v1/orgs", "/v1/projects/p1/environments", "/v1/projects/p1/credentials":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case "/v1/projects/p1/onboarding/first-event":
			_, _ = w.Write([]byte(`{"received":true,"signal":"logs","at":"t"}`))
		case "/v1/projects/p1/integration-health":
			_, _ = w.Write([]byte(`{"data":[{"kind":"connector","name":"aws","status":"pending"}]}`))
		case "/v1/projects/p1/monitors":
			if c, ok := r.URL.Query()["cursor"]; ok && c[0] == "" {
				w.WriteHeader(http.StatusUnprocessableEntity) // like the API
				return
			}
			_, _ = w.Write([]byte(`{"data":[{"id":"m1","name":"web","status":"up"},{"id":"m2","name":"old","status":"paused"}]}`))
		case "/v1/auth/key":
			_, _ = w.Write([]byte(`{"kind":"api_key","prefix":"wtk_ab12","org_id":"o1","role":"admin","expires_at":null}`))
		case "/healthz":
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("WT_API", srv.URL)
	t.Setenv("WT_API_KEY", "wtk_ab12SECRETSECRET")
	t.Setenv("WT_PROJECT", "p1")
}

func TestHealthFailOnSemanticsAndJSONShape(t *testing.T) {
	healthServer(t)
	// the pending connector and the unadvertised ingest/edge hosts are warnings.
	var b bytes.Buffer
	if err := healthMain(context.Background(), []string{"--json", "--fail-on", "never"}, &b); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Checks []check `json:"checks"`
		OK     bool    `json:"ok"`
	}
	if err := json.Unmarshal(b.Bytes(), &got); err != nil || !got.OK {
		t.Fatalf("%v %s", err, b.String())
	}
	ids := map[string]string{}
	for _, c := range got.Checks {
		ids[c.ID] = c.Status
	}
	if ids["integration.connector.aws"] != "warning" || ids["telemetry.received"] != "ok" || ids["monitor.m1"] != "ok" || ids["api.reachable"] != "ok" {
		t.Fatalf("%v", ids)
	}
	if _, paused := ids["monitor.m2"]; paused {
		t.Fatal("paused monitor should not be checked")
	}
	if strings.Contains(b.String(), "SECRET") {
		t.Fatal("key leaked")
	}
	// only warnings: error and never exit 0, warning exits 1
	for fail, want := range map[string]bool{"error": false, "warning": true, "never": false} {
		err := healthMain(context.Background(), []string{"--json", "--fail-on", fail}, &bytes.Buffer{})
		if (err != nil) != want {
			t.Fatalf("fail-on %s: err=%v", fail, err)
		}
	}
	if healthMain(context.Background(), []string{"--fail-on", "bogus"}, &bytes.Buffer{}) == nil {
		t.Fatal("bad --fail-on accepted")
	}
}

func TestHealthWarningOnlyExitsPerFailOn(t *testing.T) {
	d := &doctor{out: io.Discard}
	d.add("x", "warning", "w", "r")
	if d.bad != 0 || d.checks[0].Status != "warning" {
		t.Fatal("warning must not count as an error")
	}
}

func TestWhoamiPrintsPrefixOnly(t *testing.T) {
	healthServer(t)
	var b bytes.Buffer
	if err := whoamiMain(context.Background(), nil, &b); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	if !strings.Contains(s, "wtk_ab12") || !strings.Contains(s, "role admin") || strings.Contains(s, "SECRET") {
		t.Fatal(s)
	}
	b.Reset()
	if err := whoamiMain(context.Background(), []string{"--json"}, &b); err != nil || !strings.Contains(b.String(), `"prefix":"wtk_ab12"`) {
		t.Fatalf("%v %s", err, b.String())
	}
}

func TestWhoamiErrorsOn404(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	t.Setenv("WT_API", srv.URL)
	t.Setenv("WT_API_KEY", "wtk_x")
	if err := whoamiMain(context.Background(), nil, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("%v", err)
	}
}
