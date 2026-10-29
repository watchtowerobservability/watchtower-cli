package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	colllogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	colltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"
)

func TestSendTestPrintsTraceID(t *testing.T) {
	var mu sync.Mutex
	var spanTID, logTID []byte
	var gauges int
	auth := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		auth[r.Header.Get("Authorization")] = true
		switch r.URL.Path {
		case "/v1/traces":
			var m colltrace.ExportTraceServiceRequest
			if proto.Unmarshal(b, &m) == nil {
				spanTID = m.ResourceSpans[0].ScopeSpans[0].Spans[0].TraceId
			}
		case "/v1/logs":
			var m colllogs.ExportLogsServiceRequest
			if proto.Unmarshal(b, &m) == nil {
				logTID = m.ResourceLogs[0].ScopeLogs[0].LogRecords[0].TraceId
			}
		case "/v1/metrics":
			var m collmetrics.ExportMetricsServiceRequest
			if proto.Unmarshal(b, &m) == nil {
				for _, sm := range m.ResourceMetrics[0].ScopeMetrics {
					for _, mt := range sm.Metrics {
						if mt.GetGauge() != nil {
							gauges++
						}
					}
				}
			}
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
	}))
	defer srv.Close()

	var out bytes.Buffer
	if err := sendTest(context.Background(), srv.URL, "wti_k", "http", &out); err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`trace_id=([0-9a-f]{32})`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("output %q", out.String())
	}
	want, _ := hex.DecodeString(m[1])
	if !bytes.Equal(spanTID, want) || !bytes.Equal(logTID, want) {
		t.Fatalf("span %x log %x want %x", spanTID, logTID, want)
	}
	if gauges != 1 {
		t.Fatalf("gauges=%d", gauges)
	}
	if len(auth) != 1 || !auth["Bearer wti_k"] {
		t.Fatalf("auth headers %v", auth)
	}
}

func TestSendTestFailsWhenReceiverRejects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 401) }))
	defer srv.Close()
	var out bytes.Buffer
	if err := sendTest(context.Background(), srv.URL, "x", "http", &out); err == nil || strings.Contains(out.String(), "trace_id=") {
		t.Fatalf("expected failure, got %v %q", err, out.String())
	}
}
