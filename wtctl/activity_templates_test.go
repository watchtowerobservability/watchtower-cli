package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestActivityTemplates(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/projects/p/activity/schema-imports" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"template":"hipaa","imported":["phi.viewed"],"skipped":["user.login"]}`))
	}))
	defer srv.Close()
	var out bytes.Buffer
	if err := activityMain(context.Background(), []string{"templates"}, &out); err != nil || !strings.Contains(out.String(), "iso27001") {
		t.Fatalf("list: %v %q", err, out.String())
	}
	out.Reset()
	args := []string{"templates", "--import", "hipaa", "--project", "p", "--api", srv.URL, "--key", "k"}
	if err := activityMain(context.Background(), args, &out); err != nil {
		t.Fatal(err)
	}
	if got["template"] != "hipaa" || !strings.Contains(out.String(), "imported 1") || !strings.Contains(out.String(), "skipped 1") {
		t.Fatalf("got %v, out %q", got, out.String())
	}
	if err := activityMain(context.Background(), []string{"templates", "--import", "pci"}, &out); err == nil {
		t.Fatal("unknown template accepted")
	}
}
