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
	"testing"
)

func TestHeliconeExportBecomesGenAISpans(t *testing.T) {
	var got map[string]any
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
	}))
	defer srv.Close()
	file := filepath.Join(t.TempDir(), "export.jsonl")
	rows := `{"response_id":"r1","request_created_at":"2026-01-02T03:04:05.000Z","response_status":200,"model":"gpt-4o","prompt_tokens":12,"completion_tokens":3,"latency":250,"cost":0.0021,"request_user_id":"u1","request_properties":{"app":"shop","wt.tenant":"x","n":2}}
not json
{"response_id":"","request_created_at":"2026-01-02T03:04:05Z"}
`
	if err := os.WriteFile(file, []byte(rows), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := importHelicone(context.Background(), []string{"--file", file, "--endpoint", srv.URL, "--key", "wti_k"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "imported 1 ") || !strings.Contains(out.String(), "skipped 2") || auth != "Bearer wti_k" {
		t.Fatalf("out=%q auth=%q", out.String(), auth)
	}
	span := got["resourceSpans"].([]any)[0].(map[string]any)["scopeSpans"].([]any)[0].(map[string]any)["spans"].([]any)[0].(map[string]any)
	attrs := map[string]any{}
	for _, a := range span["attributes"].([]any) {
		kv := a.(map[string]any)
		for _, v := range kv["value"].(map[string]any) {
			attrs[kv["key"].(string)] = v
		}
	}
	if attrs["gen_ai.request.model"] != "gpt-4o" || attrs["gen_ai.usage.input_tokens"] != "12" || attrs["helicone.property.app"] != "shop" || attrs["helicone.property.n"] != "2" {
		t.Fatalf("attrs %v", attrs)
	}
	if _, ok := attrs["helicone.property.wt.tenant"]; ok {
		t.Fatal("wt.* properties must be dropped")
	}
	if span["endTimeUnixNano"] != "1767323045250000000" {
		t.Fatalf("end %v (latency 250 ms)", span["endTimeUnixNano"])
	}
	// the same response id always gives the same trace and span id, so a rerun deduplicates
	s2, _ := heliconeSpan(heliconeRow{ResponseID: "r1", RequestCreatedAt: "2026-01-02 03:04:05"})
	if s2["traceId"] != span["traceId"] || s2["spanId"] != span["spanId"] {
		t.Fatal("ids must be derived from the response id")
	}
}
