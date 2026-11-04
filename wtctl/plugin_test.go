package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPluginPackSignsWhatTheRunnerVerifies(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "src")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	yaml := "name: influxdb\nversion: 1.0.0\nkinds: [source]\npermissions:\n  egress_hosts: [influx.example]\n"
	_ = os.WriteFile(filepath.Join(dir, "plugin.yaml"), []byte(yaml), 0o600)
	seedFile, out := filepath.Join(tmp, "k.seed"), filepath.Join(tmp, "p.tar.gz")

	// Without the executable the pack is refused.
	var log bytes.Buffer
	if err := pluginMain(context.Background(), []string{"keygen", "--out", seedFile}, &log); err != nil {
		t.Fatal(err)
	}
	if err := pluginMain(context.Background(), []string{"pack", "--dir", dir, "--key", seedFile, "--out", out}, &log); err == nil {
		t.Fatal("packed without a plugin executable")
	}
	_ = os.WriteFile(filepath.Join(dir, "plugin"), []byte("#!/bin/sh\n"), 0o700)
	if err := pluginMain(context.Background(), []string{"pack", "--dir", dir, "--key", seedFile, "--out", out}, &log); err != nil {
		t.Fatal(err)
	}

	// The signature is over the tarball's SHA-256, under the key keygen printed.
	tarball, _ := os.ReadFile(out)
	sig64, _ := os.ReadFile(out + ".sig")
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig64)))
	if err != nil {
		t.Fatal(err)
	}
	line := strings.SplitN(log.String(), "\n", 2)[0]
	pub, err := base64.StdEncoding.DecodeString(line[strings.LastIndex(line, " ")+1:])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(tarball)
	if !ed25519.Verify(pub, sum[:], sig) {
		t.Fatal("signature does not verify")
	}

	// Same inputs, same bytes; and the manifest the API takes comes back out.
	again, err := packPlugin(dir)
	if err != nil || !bytes.Equal(again, tarball) {
		t.Fatalf("pack is not reproducible: %v", err)
	}
	m, err := manifestOf(tarball)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Name        string `json:"name"`
		Permissions struct {
			EgressHosts []string `json:"egress_hosts"`
		} `json:"permissions"`
	}
	if err := json.Unmarshal(m, &got); err != nil || got.Name != "influxdb" || got.Permissions.EgressHosts[0] != "influx.example" {
		t.Fatalf("manifest %s: %v", m, err)
	}

	// keygen never overwrites a publisher key.
	if err := pluginMain(context.Background(), []string{"keygen", "--out", seedFile}, &log); err == nil {
		t.Fatal("keygen overwrote an existing key")
	}
}
