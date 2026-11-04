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

func TestRulesTestSendsRuleFilesAndFailsOnFailure(t *testing.T) {
	var got struct {
		RuleFiles []string `json:"rule_files"`
		Tests     string   `json:"tests"`
	}
	var path string
	passed := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		if passed {
			_, _ = w.Write([]byte(`{"passed":true,"tests":[{"name":"a","passed":true,"failures":[]}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"passed":false,"tests":[{"name":"a","passed":false,"failures":["alertname: X"]}]}`))
	}))
	defer srv.Close()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "r1.yaml"), []byte("groups: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tf := filepath.Join(dir, "t.yaml")
	if err := os.WriteFile(tf, []byte("rule_files: ['r*.yaml']\ntests: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	args := []string{"test", tf, "--api", srv.URL, "--key", "k", "--project", "p"}
	var out bytes.Buffer
	if err := rulesMain(context.Background(), args, &out); err != nil {
		t.Fatal(err)
	}
	if path != "/v1/projects/p/rule-groups:test" || len(got.RuleFiles) != 1 || !strings.Contains(got.Tests, "tests") {
		t.Fatalf("%s %+v", path, got)
	}
	if !strings.Contains(out.String(), "PASS a") {
		t.Fatal(out.String())
	}
	passed = false
	out.Reset()
	if err := rulesMain(context.Background(), args, &out); err == nil || !strings.Contains(out.String(), "FAIL a") {
		t.Fatalf("%v %s", err, out.String())
	}
}

func TestRuleTestFilesMissingGlobIsAnError(t *testing.T) {
	if _, err := ruleTestFiles(filepath.Join(t.TempDir(), "t.yaml"), []byte("rule_files: [nope.yaml]\n")); err == nil {
		t.Fatal("want an error")
	}
}
