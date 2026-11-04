package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMetricsImportUploadsTheFile(t *testing.T) {
	var path, auth, body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, auth = r.URL.Path, r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		_, _ = w.Write([]byte(`{"imported":1}`))
	}))
	defer srv.Close()
	file := filepath.Join(t.TempDir(), "m.om")
	if err := os.WriteFile(file, []byte("x 1 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := metricsMain(context.Background(), []string{"import", "--api", srv.URL, "--key", "k", "--project", "p1", "--file", file}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if path != "/v1/projects/p1/metrics/import" || auth != "Bearer k" || body != "x 1 2\n" {
		t.Fatalf("got %q %q %q", path, auth, body)
	}
	if !strings.Contains(out.String(), "imported") {
		t.Fatal(out.String())
	}
}

func TestMetricsImportRequiresFlags(t *testing.T) {
	if err := metricsMain(context.Background(), []string{"import"}, io.Discard); err == nil {
		t.Fatal("expected usage error")
	}
}
