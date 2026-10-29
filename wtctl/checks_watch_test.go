package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWatchLoopReappliesOnChange(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "m.yaml")
	if err := os.WriteFile(file, []byte("kind: Monitor\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var runs atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- watchLoop(ctx, dir, 20*time.Millisecond, &out, func(context.Context) error {
			if runs.Add(1) == 2 {
				return os.ErrInvalid // a bad edit must not stop the watch
			}
			return nil
		})
	}()
	waitFor := func(n int32) {
		t.Helper()
		for i := 0; i < 200 && runs.Load() < n; i++ {
			time.Sleep(10 * time.Millisecond)
		}
		if runs.Load() < n {
			t.Fatalf("apply ran %d times, want %d", runs.Load(), n)
		}
	}
	waitFor(1) // the initial apply
	time.Sleep(100 * time.Millisecond)
	if runs.Load() != 1 {
		t.Fatalf("an unchanged tree re-applied: %d", runs.Load())
	}
	// a non-manifest file is ignored
	_ = os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o600)
	time.Sleep(100 * time.Millisecond)
	if runs.Load() != 1 {
		t.Fatalf("a non-manifest change re-applied: %d", runs.Load())
	}
	_ = os.WriteFile(file, []byte("kind: Monitor\nmetadata: {name: a}\n"), 0o600)
	waitFor(2)
	_ = os.WriteFile(file, []byte("kind: Monitor\nmetadata: {name: bb}\n"), 0o600)
	waitFor(3) // the failed apply did not end the loop
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "apply failed") {
		t.Errorf("output = %q", out.String())
	}
}
