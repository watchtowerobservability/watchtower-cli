package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMigrateDatadogPullsLiveWithDefaultKeyVariablesAndPrintsTheReport(t *testing.T) {
	importPollEvery = time.Millisecond
	t.Setenv("DD_API_KEY", "k1")
	t.Setenv("DD_APP_KEY", "k2")
	var got map[string]string
	srv := captureServer(t, `{"id":"job1","state":"succeeded","result":{"output":"would create 1 alert_rule\n","markdown":"# Import report\n- Migrated SLOs: 1 of 2 (50.0%)\n"}}`, &got)
	defer srv.Close()
	var out bytes.Buffer
	args := append([]string{"datadog", "--site", "datadoghq.eu", "--report", filepath.Join(t.TempDir(), "r")}, conn(srv)...)
	if err := migrateMain(context.Background(), args, &out); err != nil {
		t.Fatal(err)
	}
	if got["source"] != "datadog-live" || got["api_key"] != "k1" || got["app_key"] != "k2" || got["site"] != "datadoghq.eu" || got["mode"] != "dry_run" {
		t.Fatalf("upload: %v", got)
	}
	if !strings.Contains(out.String(), "would create 1 alert_rule") || !strings.Contains(out.String(), "Migrated SLOs: 1 of 2") {
		t.Fatalf("output %q", out.String())
	}
}

func TestMigrateTerraformDatadogUploadsTheState(t *testing.T) {
	importPollEvery = time.Millisecond
	var got map[string]string
	srv := captureServer(t, `{"id":"job1","state":"succeeded","result":{"output":"ok\n","markdown":"# Import report\n"}}`, &got)
	defer srv.Close()
	state := filepath.Join(t.TempDir(), "state.json")
	_ = os.WriteFile(state, []byte(`{"values":{"root_module":{"resources":[]}}}`), 0o600)
	args := append([]string{"terraform-datadog", state, "--apply", "--report", filepath.Join(t.TempDir(), "r")}, conn(srv)...)
	if err := migrateMain(context.Background(), args, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if got["source"] != "datadog" || got["mode"] != "apply" || !strings.Contains(got["file:terraform"], "root_module") {
		t.Fatalf("upload: %v", got)
	}
	if err := migrateMain(context.Background(), []string{"nope"}, &bytes.Buffer{}); err == nil {
		t.Fatal("want usage")
	}
}

func TestWriteImportReportWritesTerraform(t *testing.T) {
	var v importJobView
	v.Result.Terraform = "resource \"watchtower_slo\" \"a\" {}\n"
	prefix := filepath.Join(t.TempDir(), "rep")
	if err := writeImportReport(prefix, v); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(prefix + ".tf"); err != nil || string(b) != v.Result.Terraform {
		t.Fatalf("%q %v", b, err)
	}
}
