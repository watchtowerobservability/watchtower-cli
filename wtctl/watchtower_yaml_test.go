package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/watchtowerobservability/watchtower-cli/internal/ascode"
	"github.com/watchtowerobservability/watchtower-cli/internal/ascode/ascodetest"
)

const bundleYAML = `monitors:
  - name: api-health
    env_id: env_1
    kind: http
    interval_s: 60
    config: {url: "https://example.com/health"}
receivers:
  - name: ops
    kind: webhook
    secrets: {url: "${WT_TEST_HOOK}"}
quality_gates:
  - name: gate
    window_min: 30
    conditions: {}
`

func TestBundleExpandsToManifests(t *testing.T) {
	docs, err := ascode.ParseDocs([]byte(bundleYAML))
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, d := range docs {
		got = append(got, d.Kind+"/"+d.Metadata.Name)
		if _, has := d.Spec["name"]; has {
			t.Errorf("%s: name must move to metadata", d.Kind)
		}
	}
	if strings.Join(got, " ") != "Monitor/api-health QualityGate/gate Receiver/ops" {
		t.Fatalf("docs = %v", got)
	}
	if _, err := ascode.ParseDocs([]byte("bogus: []\n")); err == nil {
		t.Fatal("unknown section must fail")
	}
	// a plaintext secret is refused, exactly as in a manifest
	if _, err := ascode.ParseDocs([]byte("receivers:\n  - {name: r, kind: webhook, secrets: {url: https://hook}}\n")); err == nil {
		t.Fatal("literal secret must be refused")
	}
}

func TestPlanDetailedExitcodeAndNoSecretOutput(t *testing.T) {
	t.Setenv("WT_TEST_HOOK", "https://hooks.example/s3cr3t-hook")
	srv := ascodetest.New(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "watchtower.yaml")
	if err := os.WriteFile(f, []byte(bundleYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	conn := []string{"-f", f, "--api", srv.URL, "--key", "test-key", "--project", ascodetest.Project}
	var out bytes.Buffer
	err := planMain(context.Background(), append([]string{"--detailed-exitcode"}, conn...), &out)
	var ec exitCode
	if !errors.As(err, &ec) || ec != 2 {
		t.Fatalf("want exit 2, got %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "+ Monitor/api-health") || strings.Contains(out.String(), "s3cr3t-hook") {
		t.Fatalf("plan output: %s", out.String())
	}
	out.Reset()
	if err := applyMain(context.Background(), conn, &out); err != nil {
		t.Fatal(err, out.String())
	}
	if strings.Contains(out.String(), "s3cr3t-hook") {
		t.Fatal("apply leaked a secret")
	}
	out.Reset()
	if err := planMain(context.Background(), append([]string{"--detailed-exitcode"}, conn...), &out); err != nil {
		t.Fatalf("after apply the plan must be empty: %v\n%s", err, out.String())
	}
}

func TestExampleFileParses(t *testing.T) {
	b, err := os.ReadFile("../../docs/product/examples/watchtower.yaml")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SLACK_WEBHOOK_URL", "https://hooks.example/x")
	if _, err := ascode.ParseDocs(b); err != nil {
		t.Fatal(err)
	}
	if _, err := ascode.ParseDocs([]byte(starterYAML([]string{"next", "pg"}))); err != nil {
		t.Fatal(err)
	}
}
