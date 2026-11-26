package ascode_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/watchtowerobservability/watchtower-cli/internal/ascode"
)

const ingestKeyDoc = `apiVersion: watchtower.dev/v1
kind: IngestKey
metadata: {name: web}
spec: {env: prod, scopes: [ingest:logs]}
`

// dryServer answers the lists a plan needs and hands every create to post.
func dryServer(t *testing.T, post func(w http.ResponseWriter, r *http.Request)) (*ascode.Client, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/environments"):
			_, _ = w.Write([]byte(`{"data":[{"id":"env_1","name":"prod"}],"next_cursor":null}`))
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/credentials"):
			_, _ = w.Write([]byte(`{"data":[],"next_cursor":null}`))
		case r.Method == http.MethodPost:
			post(w, r)
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := ascode.New(srv.URL, "wtk_test", "prj_test", nil)
	if err != nil {
		t.Fatal(err)
	}
	return c, &calls
}

func dryApply(t *testing.T, c *ascode.Client) ([]ascode.Change, error) {
	t.Helper()
	docs, err := ascode.ParseDocs([]byte(ingestKeyDoc))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := c.Plan(context.Background(), docs, false)
	if err != nil {
		t.Fatal(err)
	}
	return c.Apply(context.Background(), plan, true, io.Discard)
}

func TestDryRunAsksTheServerToValidateEachCreate(t *testing.T) {
	c, calls := dryServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("dryRun") != "1" {
			t.Errorf("a dry run must only send ?dryRun=1: %s", r.URL)
		}
		_, _ = w.Write([]byte(`{"dryRun":true,"name":"web"}`))
	})
	done, err := dryApply(t, c)
	if err != nil || len(done) != 1 || !done[0].Checked || !strings.Contains(done[0].String(), "checked by the server") {
		t.Fatalf("done=%v err=%v", done, err)
	}
	if !strings.Contains(strings.Join(*calls, "\n"), "POST /v1/projects/prj_test/credentials?dryRun=1") {
		t.Fatalf("calls: %v", *calls)
	}
}

func TestDryRunPrintsTheServersValidationErrors(t *testing.T) {
	c, _ := dryServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"code":"validation","errors":[{"name":"scopes","reason":"unknown scope"}]}`))
	})
	_, err := dryApply(t, c)
	if err == nil || !strings.Contains(err.Error(), "the server would refuse it") || !strings.Contains(err.Error(), "unknown scope") {
		t.Fatalf("err = %v", err)
	}
}

// A server that predates ?dryRun=1 writes the resource: the dry run takes it back and says so.
func TestDryRunAgainstAServerThatIgnoresItRemovesWhatItMade(t *testing.T) {
	c, calls := dryServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"cred_new","name":"web","token":"wti_secret"}`))
	})
	_, err := dryApply(t, c)
	if err == nil || !strings.Contains(err.Error(), "does not support ?dryRun=1") || strings.Contains(err.Error(), "wti_secret") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(strings.Join(*calls, "\n"), "DELETE /v1/projects/prj_test/credentials/cred_new") {
		t.Fatalf("the created key must be deleted again: %v", *calls)
	}
}
