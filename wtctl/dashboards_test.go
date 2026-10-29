package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/watchtowerobservability/watchtower-cli/internal/ascode/ascodetest"
)

const dashManifest = `apiVersion: watchtower.dev/v1
kind: Dashboard
metadata: {name: Checkout}
spec:
  description: golden signals
  spec:
    version: 1
    variables:
      - {name: service, type: service, default: checkout}
    panels:
      - {id: rate, title: Rate, type: timeseries, grid: {x: 0, y: 0, w: 12, h: 6}, query: {kind: promql, text: 'sum(rate(http_requests_total{service="$service"}[5m]))'}}
`

func dashSetup(t *testing.T) (*ascodetest.Server, string, []string) {
	t.Helper()
	srv := ascodetest.New(t)
	file := filepath.Join(t.TempDir(), "checkout.yaml")
	if err := os.WriteFile(file, []byte(dashManifest), 0o644); err != nil {
		t.Fatal(err)
	}
	return srv, file, []string{"--api", srv.URL, "--key", "test-key", "--project", ascodetest.Project}
}

func TestApplyDashboardRoundTrip(t *testing.T) {
	ctx := context.Background()
	srv, file, conn := dashSetup(t)
	var out bytes.Buffer
	if err := dashboardsMain(ctx, append([]string{"apply", "-f", file}, conn...), &out); err != nil {
		t.Fatal(err, out.String())
	}
	if !strings.Contains(out.String(), "applied 1 change(s)") || srv.Count("Dashboard") != 1 {
		t.Fatalf("first apply: %s", out.String())
	}

	// A second apply changes nothing.
	out.Reset()
	before := srv.Writes()
	if err := dashboardsMain(ctx, append([]string{"apply", "-f", file}, conn...), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "applied 0 change(s)") || srv.Writes() != before {
		t.Fatalf("second apply must be a no-op: %s", out.String())
	}

	// What export writes applies as a no-op, and carries no server fields.
	exp := filepath.Join(t.TempDir(), "exported.yaml")
	if err := dashboardsMain(ctx, append([]string{"export", "Checkout", "--out", exp}, conn...), &out); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(exp)
	for _, bad := range []string{"project_id", "created_at", "version"} {
		// Server fields would sit directly under spec (2 spaces); the dashboard document's own nested version is data.
		if strings.Contains(string(b), "\n  "+bad+":") || strings.Contains(string(b), "\n"+bad+":") {
			t.Fatalf("export leaks %q:\n%s", bad, b)
		}
	}
	out.Reset()
	if err := dashboardsMain(ctx, append([]string{"apply", "-f", exp}, conn...), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "applied 0 change(s)") {
		t.Fatalf("exported manifest must apply as a no-op: %s", out.String())
	}

	// An edit is a diff (exit 1), then an update in place (PUT on the same id).
	edited := strings.Replace(dashManifest, "golden signals", "RED signals", 1)
	if err := os.WriteFile(file, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	err := dashboardsMain(ctx, append([]string{"diff", "-f", file}, conn...), &out)
	var ec exitCode
	if !errors.As(err, &ec) || ec != 1 || !strings.Contains(out.String(), "description: ") {
		t.Fatalf("diff: %v\n%s", err, out.String())
	}
	if err := dashboardsMain(ctx, append([]string{"apply", "-f", file}, conn...), &out); err != nil {
		t.Fatal(err)
	}
	if srv.Count("Dashboard") != 1 || srv.Body("Dashboard", "Checkout")["description"] != "RED signals" {
		t.Fatal("update must change the dashboard in place")
	}
	var put bool
	for _, c := range srv.Calls {
		put = put || strings.HasPrefix(c, "PUT dashboards/dashboard_")
	}
	if !put {
		t.Fatalf("no PUT in %v", srv.Calls)
	}
}

func TestDashboardsApplyRefusesOtherKinds(t *testing.T) {
	_, _, conn := setup(t) // manifests holds a Monitor and more
	dir := t.TempDir()
	f := filepath.Join(dir, "m.yaml")
	if err := os.WriteFile(f, []byte(manifests), 0o644); err != nil {
		t.Fatal(err)
	}
	err := dashboardsMain(context.Background(), append([]string{"apply", "-f", f}, conn...), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "Dashboard only") {
		t.Fatalf("got %v", err)
	}
}

func TestImportFormatDetection(t *testing.T) {
	for _, c := range []struct{ flag, path, body, want string }{
		{"", "a.yaml", "", "yaml"},
		{"", "a.yml", "", "yaml"},
		{"", "a.json", `{"schemaVersion": 38, "panels": []}`, "grafana"},
		{"", "a.json", `{"format": "watchtower.dashboard/v1"}`, "json"},
		{"grafana", "a.yaml", "", "grafana"},
	} {
		if got := importFormat(c.flag, c.path, []byte(c.body)); got != c.want {
			t.Errorf("%+v: got %s", c, got)
		}
	}
}
