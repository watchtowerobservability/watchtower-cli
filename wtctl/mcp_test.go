package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMCPProxy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer wtk_x" || r.URL.Query().Get("project") != "p1" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		b := new(bytes.Buffer)
		b.ReadFrom(r.Body)
		switch {
		case strings.Contains(b.String(), "notifications/"):
			w.WriteHeader(http.StatusAccepted)
		case strings.Contains(b.String(), "sse"):
			w.Header().Set("Content-Type", "text/event-stream")
			w.Write([]byte("event: message\ndata: {\"id\":2}\n\n"))
		default:
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"id":1}`))
		}
	}))
	defer srv.Close()
	in := `{"id":1}` + "\n" + `{"method":"notifications/initialized"}` + "\n" + `{"id":2,"x":"sse"}` + "\n"
	var out bytes.Buffer
	if err := mcpProxy(context.Background(), srv.URL+"?project=p1", "wtk_x", strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), "{\"id\":1}\n{\"id\":2}\n"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if err := mcpProxy(context.Background(), srv.URL+"?project=p1", "bad", strings.NewReader(in), &out); err == nil || strings.Contains(err.Error(), "bad\"") {
		t.Fatalf("want status error, got %v", err)
	}
}

func TestMCPKeyRefStable(t *testing.T) {
	if len(mcpKeyRef("wtk_a")) != 16 || mcpKeyRef("wtk_a") == mcpKeyRef("wtk_b") {
		t.Fatal("key ref")
	}
}
