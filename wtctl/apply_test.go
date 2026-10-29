package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/watchtowerobservability/watchtower-cli/internal/ascode/ascodetest"
)

const manifests = `apiVersion: watchtower.dev/v1
kind: Monitor
metadata: {name: api-health}
spec:
  env_id: env_1
  kind: http
  interval_s: 60
  config: {url: "https://example.com/health"}
---
apiVersion: watchtower.dev/v1
kind: Template
metadata: {name: slack-default}
spec: {channel_kind: slack, body: "{{ .Title }}"}
---
apiVersion: watchtower.dev/v1
kind: CheckSecret
metadata: {name: api-token}
spec: {value: "${WT_TEST_API_TOKEN}"}
---
apiVersion: watchtower.dev/v1
kind: HealthToken
metadata: {name: ci}
spec: {}
---
apiVersion: watchtower.dev/v1
kind: RuleGroup
metadata: {name: node}
spec: {interval: 1m, rules: []}
`

func setup(t *testing.T) (*ascodetest.Server, string, []string) {
	t.Helper()
	t.Setenv("WT_TEST_API_TOKEN", "s3cr3t-value")
	secretOut = io.Discard
	t.Cleanup(func() { secretOut = os.Stderr })
	srv := ascodetest.New(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "all.yaml"), []byte(manifests), 0o644); err != nil {
		t.Fatal(err)
	}
	return srv, dir, []string{"--api", srv.URL, "--key", "test-key", "--project", ascodetest.Project}
}

func TestApplyCreatesThenNoop(t *testing.T) {
	srv, dir, conn := setup(t)
	var secrets bytes.Buffer
	secretOut = &secrets
	t.Cleanup(func() { secretOut = os.Stderr })

	var out bytes.Buffer
	if err := applyMain(context.Background(), append([]string{"-f", dir}, conn...), &out); err != nil {
		t.Fatal(err, out.String())
	}
	if !strings.Contains(out.String(), "applied 5 change(s)") {
		t.Fatalf("first apply: %s", out.String())
	}
	if srv.Count("Monitor") != 1 || srv.Count("Template") != 1 || srv.Count("HealthToken") != 1 {
		t.Fatal("resources not created")
	}
	if !strings.Contains(secrets.String(), "HealthToken/ci: token wth_once_") {
		t.Fatalf("health token not shown once on stderr: %q", secrets.String())
	}
	if len(srv.Secrets) != 1 || srv.Secrets[0] != "s3cr3t-value" {
		t.Fatalf("check secret value was not expanded from env: %v", srv.Secrets)
	}

	secrets.Reset()
	out.Reset()
	if err := applyMain(context.Background(), append([]string{"-f", dir}, conn...), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "applied 0 change(s)") {
		t.Fatalf("second apply must change nothing: %s", out.String())
	}
	if secrets.Len() != 0 {
		t.Fatalf("a secret was shown twice: %q", secrets.String())
	}
}

func TestDiffShowsFieldChanges(t *testing.T) {
	_, dir, conn := setup(t)
	if err := applyMain(context.Background(), append([]string{"-f", dir}, conn...), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(manifests, "interval_s: 60", "interval_s: 30", 1)
	if err := os.WriteFile(filepath.Join(dir, "all.yaml"), []byte(changed), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := diffMain(context.Background(), append([]string{"-f", dir}, conn...), &out)
	var ec exitCode
	if !errors.As(err, &ec) || ec != 1 {
		t.Fatalf("diff with changes must exit 1, got %v", err)
	}
	for _, want := range []string{"~ Monitor/api-health", "interval_s: 60 -> 30", "1 change(s)"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q in:\n%s", want, out.String())
		}
	}
}

func TestExportRoundTripsApply(t *testing.T) {
	srv, dir, conn := setup(t)
	if err := applyMain(context.Background(), append([]string{"-f", dir}, conn...), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	exp := filepath.Join(t.TempDir(), "exported")
	var out bytes.Buffer
	args := append([]string{"--out", exp, "--kinds", "Monitor,Template,CheckSecret"}, conn...)
	if err := exportMain(context.Background(), args, &out); err != nil {
		t.Fatal(err)
	}
	before := srv.Writes()
	out.Reset()
	if err := applyMain(context.Background(), append([]string{"-f", exp}, conn...), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "applied 0 change(s)") || srv.Writes() != before {
		t.Fatalf("exported manifests must apply as a no-op: %s", out.String())
	}
}

func TestSecretRefsFromEnvNeverWrittenToFile(t *testing.T) {
	_, dir, conn := setup(t)
	if err := applyMain(context.Background(), append([]string{"-f", dir}, conn...), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := exportMain(context.Background(), append([]string{"--kinds", "CheckSecret"}, conn...), &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "s3cr3t-value") || !strings.Contains(out.String(), "${WT_CHECKSECRET_API_TOKEN_VALUE}") {
		t.Fatalf("export must hold a reference, not the value:\n%s", out.String())
	}
	// A literal secret in a manifest is refused before anything is sent.
	bad := strings.Replace(manifests, "${WT_TEST_API_TOKEN}", "literal-secret", 1)
	if err := os.WriteFile(filepath.Join(dir, "all.yaml"), []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	err := applyMain(context.Background(), append([]string{"-f", dir}, conn...), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "${ENV} reference") {
		t.Fatalf("literal secret accepted: %v", err)
	}
	// An unset variable is an error too.
	t.Setenv("WT_TEST_API_TOKEN", "")
	good := []byte(manifests)
	_ = os.WriteFile(filepath.Join(dir, "all.yaml"), good, 0o644)
	srv2 := ascodetest.New(t)
	args := []string{"-f", dir, "--api", srv2.URL, "--key", "test-key", "--project", ascodetest.Project}
	if err := applyMain(context.Background(), args, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "WT_TEST_API_TOKEN") {
		t.Fatalf("unset env must fail: %v", err)
	}
}

func TestPruneOnlyWithFlag(t *testing.T) {
	srv, dir, conn := setup(t)
	if err := applyMain(context.Background(), append([]string{"-f", dir}, conn...), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	mon := func(name string) string {
		return "apiVersion: watchtower.dev/v1\nkind: Monitor\nmetadata: {name: " + name + "}\n" +
			"spec: {env_id: env_1, kind: http, interval_s: 60, config: {url: \"https://example.com/health\"}}\n"
	}
	write := func(name string) string {
		d := t.TempDir()
		if err := os.WriteFile(filepath.Join(d, "m.yaml"), []byte(mon(name)), 0o644); err != nil {
			t.Fatal(err)
		}
		return d
	}
	// A second monitor exists live; the manifests name only api-health.
	if err := applyMain(context.Background(), append([]string{"-f", write("other")}, conn...), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	only := write("api-health")
	var out bytes.Buffer
	if err := applyMain(context.Background(), append([]string{"-f", only}, conn...), &out); err != nil || srv.Count("Monitor") != 2 {
		t.Fatalf("no --prune must delete nothing: %v monitors=%d", err, srv.Count("Monitor"))
	}
	out.Reset()
	if err := applyMain(context.Background(), append([]string{"-f", only, "--prune", "--dry-run"}, conn...), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "- Monitor/other") || srv.Count("Monitor") != 2 {
		t.Fatalf("dry-run prune must only show the deletion: %s", out.String())
	}
	if err := applyMain(context.Background(), append([]string{"-f", only, "--prune"}, conn...), &out); err != nil {
		t.Fatal(err)
	}
	if srv.Count("Monitor") != 1 || srv.Count("Template") != 1 {
		t.Fatalf("prune deletes the unnamed monitor only (monitors=%d templates=%d)", srv.Count("Monitor"), srv.Count("Template"))
	}
}

func TestCompletionShells(t *testing.T) {
	for _, sh := range []string{"bash", "zsh", "fish", "powershell"} {
		var out bytes.Buffer
		if err := completionMain(context.Background(), []string{sh}, &out); err != nil || !strings.Contains(out.String(), "apply") {
			t.Fatalf("%s: %v %q", sh, err, out.String())
		}
	}
	if completionMain(context.Background(), []string{"tcsh"}, &bytes.Buffer{}) == nil {
		t.Fatal("unknown shell accepted")
	}
}
