package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/watchtowerobservability/watchtower-cli/internal/archivecrypt"
)

func TestArchiveDecryptUsage(t *testing.T) {
	var b bytes.Buffer
	if err := archiveMain(context.Background(), nil, &b); err == nil {
		t.Fatal("no subcommand must fail with the usage")
	}
	if err := archiveMain(context.Background(), []string{"decrypt", "--project", "nope", "x"}, &b); err == nil {
		t.Fatal("bad project must fail")
	}
}

func TestArchiveObjectFormatRoundTripsOnDisk(t *testing.T) {
	dk, _ := archivecrypt.NewDataKey()
	enc, err := archivecrypt.Seal(dk, "p", []byte("PAR1 rows"))
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "part-0000.parquet")
	if err := os.WriteFile(f, enc, 0o600); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(f)
	if pt, err := archivecrypt.Open(dk, "p", b); err != nil || string(pt) != "PAR1 rows" {
		t.Fatalf("%q %v", pt, err)
	}
}
