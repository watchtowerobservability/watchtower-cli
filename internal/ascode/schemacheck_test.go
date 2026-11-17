package ascode_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/watchtowerobservability/watchtower-cli/internal/ascode"
	"github.com/watchtowerobservability/watchtower-cli/internal/ascode/ascodetest"
)

const tinyAPI = `{"paths":{
 "/v1/projects/{prj}/monitors":{"post":{"requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Monitor"}}}}}},
 "/v1/projects/{prj}/slos":{"post":{"requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Slo"}}}}}}},
 "components":{"schemas":{
  "Monitor":{"type":"object","additionalProperties":false,"required":["name","kind"],"properties":{"name":{"type":"string"},"kind":{"type":"string","enum":["http","tcp"]},"env_id":{"type":"string"},"interval_s":{"type":"integer"},"config":{"type":"object"}}},
  "Slo":{"type":"object","additionalProperties":false,"required":["name","target"],"properties":{"name":{"type":"string"},"target":{"type":"number"},"sli":{"oneOf":[{"type":"object","additionalProperties":false,"properties":{"availability":{"type":"object"}}},{"type":"object","additionalProperties":false,"properties":{"latency":{"type":"object"}}}]}}}}}}`

const goodMon = `apiVersion: watchtower.dev/v1
kind: Monitor
metadata: {name: m1}
spec: {kind: http, interval_s: 60}
`

// front serves the tiny OpenAPI document (when asked) and a 422 for every POST to slos, else the fake.
func front(t *testing.T, doc string, failSlo bool) (*ascodetest.Server, *ascode.Client) {
	t.Helper()
	fake := ascodetest.New(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/openapi.json" && doc != "":
			io.WriteString(w, doc)
		case failSlo && r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/slos"):
			http.Error(w, `{"detail":"kind: unknown field"}`, http.StatusUnprocessableEntity)
		default:
			fake.Config.Handler.ServeHTTP(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	c, err := ascode.New(ts.URL, "test-key", ascodetest.Project, nil)
	if err != nil {
		t.Fatal(err)
	}
	return fake, c
}

func TestPlanRejectsWhatTheSchemaRejects(t *testing.T) {
	_, c := front(t, tinyAPI, false)
	docs, err := ascode.ParseDocs([]byte(goodMon + `---
apiVersion: watchtower.dev/v1
kind: Monitor
metadata: {name: m2}
spec: {kind: udp, bogus: 1}
---
apiVersion: watchtower.dev/v1
kind: Slo
metadata: {name: s1}
spec: {target: 99.9, kind: request}
`))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Plan(context.Background(), docs, false)
	if err == nil {
		t.Fatal("plan accepted an invalid manifest")
	}
	for _, want := range []string{"Slo/s1: kind: unknown field", "Monitor/m2: bogus: unknown field", "Monitor/m2: kind: ", "is not one of"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in:\n%v", want, err)
		}
	}
	if strings.Contains(err.Error(), "Monitor/m1") {
		t.Errorf("valid monitor reported:\n%v", err)
	}
}

func TestPlanSkipsWithoutDocument(t *testing.T) {
	_, c := front(t, "", false)
	docs, _ := ascode.ParseDocs([]byte(goodMon + "---\napiVersion: watchtower.dev/v1\nkind: Slo\nmetadata: {name: s1}\nspec: {target: 99.9, kind: request}\n"))
	if _, err := c.Plan(context.Background(), docs, false); err != nil {
		t.Fatal(err)
	}
}

func TestApplyRollsBackAfterFailure(t *testing.T) {
	fake, c := front(t, "", true)
	docs, _ := ascode.ParseDocs([]byte(goodMon + `---
apiVersion: watchtower.dev/v1
kind: Monitor
metadata: {name: m2}
spec: {kind: http}
---
apiVersion: watchtower.dev/v1
kind: Slo
metadata: {name: s1}
spec: {target: 99.9}
`))
	plan, err := c.Plan(context.Background(), docs, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Apply(context.Background(), plan, false, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "rolled back 2 change(s)") {
		t.Fatalf("want a rollback of 2, got %v", err)
	}
	if n := fake.Count("Monitor"); n != 0 {
		t.Fatalf("%d monitors left behind", n)
	}
}

func TestExportDropsFieldsTheCreateBodyRefuses(t *testing.T) {
	_, c := front(t, tinyAPI, false)
	ctx := context.Background()
	if err := c.Do(ctx, http.MethodPost, "monitors", nil, map[string]any{"name": "m1", "kind": "http", "stale": true}, nil); err != nil {
		t.Fatal(err)
	}
	docs, err := c.Export(ctx, []string{"Monitor"})
	if err != nil || len(docs) != 1 {
		t.Fatalf("export: %v %v", docs, err)
	}
	if _, ok := docs[0].Spec["stale"]; ok {
		t.Errorf("read-only field kept: %v", docs[0].Spec)
	}
	if docs[0].Spec["kind"] != "http" {
		t.Errorf("accepted field dropped: %v", docs[0].Spec)
	}
}
