package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestSourcemapsVerifyNeedsPosition(t *testing.T) {
	var out bytes.Buffer
	err := sourcemapsVerify(context.Background(), []string{"--api", "https://x", "--key", "k", "--project", "prj_1", "--release", "1", "--url", "a.js"}, &out)
	if err == nil || !strings.Contains(err.Error(), "--line") {
		t.Fatalf("want a missing-flag error, got %v", err)
	}
}
