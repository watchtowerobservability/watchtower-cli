package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/watchtowerobservability/watchtower-cli/internal/ascode/ascodetest"
)

func TestStatusPageDesugarsToReceiverAndRoutes(t *testing.T) {
	t.Setenv("WT_STATUSPAGE_SNAPNEDIT_URL", "https://hook.example/x")
	t.Setenv("WT_STATUSPAGE_SNAPNEDIT_SECRET", "s3cr3t")
	secretOut = &bytes.Buffer{}
	t.Cleanup(func() { secretOut = os.Stderr })
	srv := ascodetest.New(t)
	dir := t.TempDir()
	y := `status_pages:
  - name: snapnedit
    provider: forumulate
    space: snap
    components:
      - {monitor: mon_1, label: Website}
`
	if err := os.WriteFile(filepath.Join(dir, "watchtower.yaml"), []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	conn := []string{"-f", dir, "--api", srv.URL, "--key", "test-key", "--project", ascodetest.Project}
	var out bytes.Buffer
	if err := planMain(context.Background(), conn, &out); err != nil || !strings.Contains(out.String(), "Receiver/status-snapnedit") || !strings.Contains(out.String(), "Routing") {
		t.Fatalf("plan must show the expansion: %v\n%s", err, out.String())
	}
	out.Reset()
	if err := applyMain(context.Background(), conn, &out); err != nil {
		t.Fatal(err, out.String())
	}
	if srv.Count("Receiver") != 1 || srv.Count("Routing") != 1 {
		t.Fatalf("receiver %d routing %d", srv.Count("Receiver"), srv.Count("Routing"))
	}
}

func TestStatusPageManifestKind(t *testing.T) {
	b, pages, err := splitStatusPages([]byte("apiVersion: watchtower.dev/v1\nkind: StatusPage\nmetadata: {name: p}\nspec: {components: [{monitor: m}]}\n"))
	if err != nil || len(pages) != 1 || pages[0].Name != "p" || len(bytes.TrimSpace(b)) != 0 {
		t.Fatalf("%v %v %q", err, pages, b)
	}
}
