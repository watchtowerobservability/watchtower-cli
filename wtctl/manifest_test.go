package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/watchtowerobservability/watchtower-cli/internal/ascode/ascodetest"
)

func TestFailOnDriftExit2(t *testing.T) {
	srv := ascodetest.New(t)
	secretOut = io.Discard
	t.Cleanup(func() { secretOut = os.Stderr })
	file := filepath.Join(t.TempDir(), "watchtower.yaml")
	src := "apiVersion: watchtower.dev/v1\nkind: Template\nmetadata: {name: a}\nspec: {channel_kind: slack, body: \"1\"}\n"
	if err := os.WriteFile(file, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	conn := []string{"--api", srv.URL, "--key", "test-key", "--project", ascodetest.Project, "--file", file, "--repo", "o/r"}
	ctx := context.Background()

	var out bytes.Buffer
	if err := manifestMain(ctx, append([]string{"plan"}, conn...), &out); err != nil {
		t.Fatalf("plan without --fail-on-drift must exit 0: %v", err)
	}
	err := manifestMain(ctx, append([]string{"plan", "--fail-on-drift"}, conn...), &out)
	var ec exitCode
	if !errors.As(err, &ec) || ec != 2 {
		t.Fatalf("drift must exit 2, got %v", err)
	}
	if err := manifestMain(ctx, append([]string{"apply"}, conn...), &out); err != nil {
		t.Fatal(err)
	}
	if err := manifestMain(ctx, append([]string{"drift"}, conn...), &out); err != nil {
		t.Fatalf("no drift after apply: %v", err)
	}
}
