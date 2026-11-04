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

func TestCopyConfig(t *testing.T) {
	var writes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if r.Method != http.MethodGet {
			var b map[string]any
			_ = json.NewDecoder(r.Body).Decode(&b)
			j, _ := json.Marshal(b)
			writes = append(writes, r.Method+" "+p+" "+string(j))
			_, _ = w.Write([]byte(`{}`))
			return
		}
		switch p {
		case "/v1/projects/a/activity/schemas":
			_, _ = w.Write([]byte(`{"data":[{"action":"doc.made","version":3,"target_types":["doc"],"metadata_schema":{"type":"object"},"mode":"enforce","created_at":"x"}],"next_cursor":null}`))
		case "/v1/projects/a/activity/redaction":
			_, _ = w.Write([]byte(`{"rules":[{"path":"metadata.ssn","action":"drop"}],"detectors":["jwt"]}`))
		case "/v1/projects/a/activity/theme":
			_, _ = w.Write([]byte(`{"theme":{"accent":"#111"},"draft":{},"warnings":[],"badge_entitled":false}`))
		case "/v1/projects/a/activity/rules":
			_, _ = w.Write([]byte(`{"data":[{"name":"admins","match":{"actions":["role.*"]},"channel":{"kind":"email","to":"sec@x.io"},"account_id":null},{"name":"hook","match":{},"channel":{"kind":"webhook"}},{"name":"dup","channel":{"kind":"email","to":"a@b"}}]}`))
		case "/v1/projects/b/activity/rules":
			_, _ = w.Write([]byte(`{"data":[{"name":"dup","channel":{"kind":"email"}}]}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	var out bytes.Buffer
	if err := activityCopyMain(context.Background(), []string{"--from", "a", "--to", "b", "--api", srv.URL, "--key", "k"}, &out); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(writes, "\n")
	for _, want := range []string{
		`PUT /v1/projects/b/activity/schemas/doc.made {"description":null,"metadata_schema":{"type":"object"},"mode":"enforce","target_types":["doc"]}`,
		`PUT /v1/projects/b/activity/redaction {"rules":[{"action":"drop","path":"metadata.ssn"}]}`,
		`PUT /v1/projects/b/activity/theme {"draft":{"accent":"#111"}}`,
		`POST /v1/projects/b/activity/rules {"channel":{"kind":"email","to":"sec@x.io"},"match":{"actions":["role.*"]},"name":"admins"}`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s in\n%s", want, got)
		}
	}
	if len(writes) != 4 || !strings.Contains(out.String(), `skip rule "hook"`) || !strings.Contains(out.String(), `skip rule "dup"`) {
		t.Fatalf("writes %d, out:\n%s", len(writes), out.String())
	}
	writes = nil
	if err := activityCopyMain(context.Background(), []string{"--from", "a", "--to", "b", "--api", srv.URL, "--key", "k", "--dry-run"}, &out); err != nil || len(writes) != 0 {
		t.Fatalf("dry run wrote %v (%v)", writes, err)
	}
}
