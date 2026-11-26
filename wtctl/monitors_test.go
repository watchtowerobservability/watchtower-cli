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

func TestMonitorsPruneAndListRetired(t *testing.T) {
	var got []string
	var prune map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Method+" "+r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &prune)
			_, _ = w.Write([]byte(`{"retired":[{"id":"mon_1","name":"linkhub-x"}],"dry_run":true}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"mon_1","name":"linkhub-x","kind":"heartbeat","status":"retired","service":"linkhub-worker"}],"next_cursor":null}`))
	}))
	defer srv.Close()
	base := []string{"--api", srv.URL, "--key", "wtk_x", "--project", "linkhub/linkhub"}
	var out bytes.Buffer
	if err := monitorsMain(context.Background(), append([]string{"prune", "--service", "linkhub-worker", "--dry-run"}, base...), &out); err != nil {
		t.Fatal(err)
	}
	if prune["service"] != "linkhub-worker" || prune["dry_run"] != true || !strings.Contains(out.String(), "would retire linkhub-x") {
		t.Fatalf("prune body %v, out %q", prune, out.String())
	}
	out.Reset()
	if err := monitorsMain(context.Background(), append([]string{"list", "--status", "retired"}, base...), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "retired") || !strings.Contains(strings.Join(got, "\n"), "GET /v1/projects/linkhub~linkhub/monitors?limit=100&status=retired") {
		t.Fatalf("calls %v out %q", got, out.String())
	}
	if err := monitorsMain(context.Background(), append([]string{"prune"}, base...), &out); err == nil {
		t.Fatal("prune without --service must fail")
	}
}
