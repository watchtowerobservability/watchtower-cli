package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSpanFilterBuildsPipeQuery(t *testing.T) {
	f := spanFilter{name: `GET "/cart"`, kind: "server", status: "error", services: "api, web", minDuration: 500 * time.Millisecond, where: `attrs.region == "eu"`, limit: 20}
	q, err := f.pipeQuery()
	if err != nil {
		t.Fatal(err)
	}
	want := `spans | where name == "GET \"/cart\"" and kind == 2 and status_code == 2 and (service == "api" or service == "web") and duration_ns >= 500000000 and (attrs.region == "eu") | sort -start_ns | limit 20`
	if q != want {
		t.Fatalf("got  %s\nwant %s", q, want)
	}
	if q, _ := (spanFilter{limit: 5}).pipeQuery(); q != "spans | sort -start_ns | limit 5" {
		t.Fatalf("bare %q", q)
	}
	for _, bad := range []spanFilter{{kind: "weird", limit: 1}, {status: "bad", limit: 1}, {limit: 0}} {
		if _, err := bad.pipeQuery(); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}

func TestSpansSearchAndAnnotateCallTheAPI(t *testing.T) {
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		b["path"] = r.URL.Path
		bodies = append(bodies, b)
		if r.URL.Path == "/v1/projects/prj_1/query/search" {
			_, _ = w.Write([]byte(`{"columns":["start","service","name","trace_id"],"data":[["2026-01-01T00:00:00Z","api","GET /cart","abc"]]}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"s1"}`))
	}))
	defer srv.Close()
	flags := []string{"--api", srv.URL, "--key", "k", "--project", "prj_1"}
	var out bytes.Buffer
	if err := spansMain(context.Background(), append([]string{"search", "--status", "error"}, flags...), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "GET /cart") || bodies[0]["language"] != "pipe" || !strings.Contains(bodies[0]["q"].(string), "status_code == 2") {
		t.Fatalf("search %q %v", out.String(), bodies[0])
	}
	out.Reset()
	args := append([]string{"annotate", "0123456789abcdef0123456789abcdef", "0123456789abcdef", "--name", "correctness", "--value", "0.5"}, flags...)
	if err := spansMain(context.Background(), args, &out); err != nil {
		t.Fatal(err)
	}
	b := bodies[1]
	if b["path"] != "/v1/projects/prj_1/llm/scores" || b["value"] != 0.5 || b["span_id"] != "0123456789abcdef" || b["source"] != "human" {
		t.Fatalf("annotate %v", b)
	}
	if scoreValue("true") != true || scoreValue("good") != "good" {
		t.Fatal("scoreValue")
	}
}

func TestSelfUpdateVerifiesChecksumAndReplaces(t *testing.T) {
	bin := []byte("new wtctl")
	sum := sha256.Sum256(bin)
	good := hex.EncodeToString(sum[:]) + "  " + updateAsset() + "\n"
	// /bad publishes a checksum that does not match the binary
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rel/SHA256SUMS":
			_, _ = w.Write([]byte(good))
		case "/bad/SHA256SUMS":
			_, _ = w.Write([]byte(strings.Repeat("0", 64) + "  " + updateAsset() + "\n"))
		case "/rel/" + updateAsset(), "/bad/" + updateAsset():
			_, _ = w.Write(bin)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	target := filepath.Join(t.TempDir(), "wtctl")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := selfUpdate(context.Background(), srv.URL+"/bad", target, false, &out); err == nil {
		t.Fatal("accepted a checksum mismatch")
	}
	if b, _ := os.ReadFile(target); string(b) != "old" {
		t.Fatalf("replaced on mismatch: %q", b)
	}
	if err := selfUpdate(context.Background(), srv.URL+"/rel", target, false, &out); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "new wtctl" {
		t.Fatalf("not replaced: %q", b)
	}
	if err := selfUpdate(context.Background(), "http://example.com/rel", target, true, &out); err == nil {
		t.Fatal("accepted plain http")
	}
}
