package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/watchtowerobservability/watchtower-cli/internal/repofile"
)

func runIntegration(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := integrationMain(context.Background(), args, &out)
	return out.String(), err
}

func TestIntegrationNewValidateTestRoundTrip(t *testing.T) {
	root := t.TempDir()
	if _, err := runIntegration(t, "new", "acme", "--dir", root); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "acme")
	if out, err := runIntegration(t, "validate", dir); err != nil {
		t.Fatalf("scaffold must validate: %v\n%s", err, out)
	}
	if out, err := runIntegration(t, "test", dir, "--fixture", filepath.Join(dir, "fixture.txt")); err != nil {
		t.Fatalf("scaffold must pass its own fixture: %v\n%s", err, out)
	}
	if _, err := runIntegration(t, "new", "acme", "--dir", root); err == nil {
		t.Fatal("new must not overwrite")
	}
	if _, err := runIntegration(t, "new", "Bad-Name", "--dir", root); err == nil {
		t.Fatal("a bad name must be refused")
	}
}

func TestIntegrationValidateWarnsOnUndocumentedMetricsAndTestCatchesMissingOnes(t *testing.T) {
	root := t.TempDir()
	if _, err := runIntegration(t, "new", "acme", "--dir", root); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "acme")
	f := filepath.Join(dir, "manifest.yaml")
	b, _ := os.ReadFile(f)
	if err := os.WriteFile(f, []byte(strings.Replace(string(b), `{name: "acme_up"`, `{name: "acme_other"`, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := runIntegration(t, "validate", dir)
	if err != nil || !strings.Contains(out, `warning:`) || !strings.Contains(out, `"acme_up"`) {
		t.Fatalf("an undocumented metric is a warning: %v\n%s", err, out)
	}
	if _, err := runIntegration(t, "validate", dir, "--strict"); err == nil {
		t.Fatal("--strict must fail on it")
	}
	if out, err := runIntegration(t, "test", dir, "--fixture", filepath.Join(dir, "fixture.txt")); err == nil {
		t.Fatalf("a documented metric missing from the fixture must fail: %s", out)
	}
}

// Golden: the shipped envoy manifest validates, and replaying a recorded /stats/prometheus
// payload through its collector yields every documented series.
func TestIntegrationToolingOnAShippedManifest(t *testing.T) {
	dir := filepath.Dir(repofile.Path("integrations/envoy/manifest.yaml"))
	fix := filepath.Join(t.TempDir(), "envoy.txt")
	payload := "# TYPE envoy_server_live gauge\nenvoy_server_live 1\n# TYPE envoy_cluster_upstream_rq_total counter\nenvoy_cluster_upstream_rq_total{envoy_cluster_name=\"api\"} 4\n" +
		"# TYPE envoy_cluster_membership_healthy gauge\nenvoy_cluster_membership_healthy{envoy_cluster_name=\"api\"} 2\n"
	if err := os.WriteFile(fix, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := runIntegration(t, "validate", dir); err != nil {
		t.Fatalf("envoy: %v\n%s", err, out)
	}
	if out, err := runIntegration(t, "test", dir, "--fixture", fix); err != nil {
		t.Fatalf("envoy replay: %v\n%s", err, out)
	}
}

// Every shipped manifest validates, and squid's counters fixture replays through its collector.
func TestIntegrationShippedSetValidatesAndSquidReplays(t *testing.T) {
	root := filepath.Dir(filepath.Dir(repofile.Path("integrations/squid/manifest.yaml"))) // the integrations dir
	if out, err := runIntegration(t, "validate", root); err != nil {
		t.Fatalf("shipped manifests: %v\n%s", err, out)
	}
	fix := filepath.Join(t.TempDir(), "squid.txt")
	payload := "sample_time = 1.0\nclient_http.requests = 120\nclient_http.hits = 80\nclient_http.errors = 2\n"
	if err := os.WriteFile(fix, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := runIntegration(t, "test", filepath.Join(root, "squid"), "--fixture", fix); err != nil {
		t.Fatalf("squid replay: %v\n%s", err, out)
	}
}

// The multi-endpoint and tool-driven kinds replay from the fixture directory their manifest ships
// (integrations/<name>/fixtures): every documented metric must come out, and the collector must
// report wt.integration.up = 1.
func TestIntegrationFixtureDirReplayOfMultiAPIKinds(t *testing.T) {
	root := filepath.Dir(filepath.Dir(repofile.Path("integrations/squid/manifest.yaml")))
	for _, name := range []string{"snowflake", "databricks", "vercel", "cloudflare", "dcgm"} {
		dir := filepath.Join(root, name)
		out, err := runIntegration(t, "test", dir, "--fixture", filepath.Join(dir, "fixtures"), "--timeout", "3s")
		if err != nil {
			t.Errorf("%s: %v\n%s", name, err, out)
		}
	}
}

func TestIntegrationFixtureDirFailsOnAnUnmappedEndpoint(t *testing.T) {
	root := filepath.Dir(filepath.Dir(repofile.Path("integrations/squid/manifest.yaml")))
	empty := t.TempDir()
	if out, err := runIntegration(t, "test", filepath.Join(root, "databricks"), "--fixture", empty); err == nil || !strings.Contains(err.Error(), "no fixture") {
		t.Fatalf("a request with no fixture file must fail the test: %v\n%s", err, out)
	}
}
