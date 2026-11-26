package ascode_test

import (
	"os"
	"strings"
	"testing"

	"github.com/watchtowerobservability/watchtower-cli/internal/ascode"
)

// The watchtower.yaml example of the developer-API page parses as a bundle into two AlertRule documents.
func TestDeveloperAPIDocExampleParses(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/product/developer-api-observability.md")
	if err != nil {
		t.Skip("not a monorepo checkout")
	}
	_, rest, ok := strings.Cut(string(raw), "```yaml\n")
	if !ok {
		t.Fatal("no yaml block")
	}
	block, _, _ := strings.Cut(rest, "```")
	docs, err := ascode.ParseDocs([]byte(block))
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 2 || docs[0].Kind != "AlertRule" || docs[1].Kind != "AlertRule" {
		t.Fatalf("docs: %+v", docs)
	}
}
