package ascode_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/watchtowerobservability/watchtower-cli/internal/ascode"
)

// A ServiceAccountKey that exists is left alone, a new one is minted under its account, and the
// secret is shown once.
func TestServiceAccountKeyKind(t *testing.T) {
	var posts []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/projects/prj_test":
			_, _ = w.Write([]byte(`{"org_id":"org_1"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/orgs/org_1/service-accounts":
			_, _ = w.Write([]byte(`{"data":[{"id":"sa_1","name":"bot"}],"next_cursor":null}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/orgs/org_1/service-accounts/sa_1/keys":
			_, _ = w.Write([]byte(`{"data":[{"id":"k1","name":"existing"},{"id":"k0","name":"old","revoked_at":"2026-01-01T00:00:00Z"}],"next_cursor":null}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/orgs/org_1/service-accounts/sa_1/keys":
			var b map[string]any
			_ = json.NewDecoder(r.Body).Decode(&b)
			posts = append(posts, b)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"k2","name":"ci","token":"wta_once","secret":"wta_once"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c, err := ascode.New(srv.URL, "wtk_test", "prj_test", nil)
	if err != nil {
		t.Fatal(err)
	}
	docs, err := ascode.ParseDocs([]byte(`apiVersion: watchtower.dev/v1
kind: ServiceAccountKey
metadata: {name: bot/existing}
spec: {scopes: [admin:read]}
---
apiVersion: watchtower.dev/v1
kind: ServiceAccountKey
metadata: {name: bot/ci}
spec: {scopes: [admin:read], expires_in_days: 30}
`))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := c.Plan(context.Background(), docs, false)
	if err != nil {
		t.Fatal(err)
	}
	var secret strings.Builder
	done, err := c.Apply(context.Background(), plan, false, &secret)
	if err != nil || ascode.Count(done) != 1 {
		t.Fatalf("done=%v err=%v", done, err)
	}
	if len(posts) != 1 || posts[0]["name"] != "ci" || posts[0]["expires_in_days"] != 30.0 {
		t.Fatalf("posts = %v", posts)
	}
	if !strings.Contains(secret.String(), "ServiceAccountKey/bot/ci") || !strings.Contains(secret.String(), "wta_once") {
		t.Fatalf("the secret must be shown once: %q", secret.String())
	}
}

func TestOrganizationKindNeedsNoOrg(t *testing.T) {
	k := ascode.ByKind("Organization")
	if k == nil || !k.Account || !k.CreateOnly || !k.NoDelete || k.Key != "slug" {
		t.Fatalf("Organization kind = %+v", k)
	}
}
