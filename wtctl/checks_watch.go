package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-cli/internal/ascode"
)

const checksWatchUsage = "usage: wtctl checks watch -f <dir|file> --project <id> [--api <url>] [--key <key>] [--prune] [--interval 1s]"

// checkKinds are the manifest kinds `checks watch` applies; other kinds in the path are ignored.
var checkKinds = []string{"Monitor", "CheckSecret"}

// checksWatch is `wtctl checks watch`: apply the monitor manifests now and again after every
// change to them, until interrupted. A bad edit is reported and the watch goes on.
func checksWatch(ctx context.Context, args []string, out io.Writer) error {
	var o asCodeOpts
	fl := o.flags("checks watch")
	interval := fl.Duration("interval", time.Second, "how often to look for changes")
	c, err := o.client(fl, args)
	if err != nil {
		return fmt.Errorf("%w\n%s", err, checksWatchUsage)
	}
	if o.file == "" || *interval < 100*time.Millisecond {
		return errors.New("-f <dir|file> is required and --interval is at least 100ms\n" + checksWatchUsage)
	}
	return watchLoop(ctx, o.file, *interval, out, func(ctx context.Context) error {
		docs, err := ascode.LoadDocs(o.file)
		if err != nil {
			return err
		}
		docs = slices.DeleteFunc(docs, func(d ascode.Doc) bool { return !slices.Contains(checkKinds, d.Kind) })
		plan, err := c.Plan(ctx, docs, o.prune)
		if err != nil {
			return err
		}
		done, err := c.Apply(ctx, plan, false, secretOut)
		for _, ch := range done {
			if ch.Changed() {
				fmt.Fprintln(out, ch)
			}
		}
		if err == nil {
			fmt.Fprintf(out, "applied %d change(s)\n", ascode.Count(done))
		}
		return err
	})
}

// watchLoop runs apply once, then whenever the files under path change. It returns when ctx ends.
func watchLoop(ctx context.Context, path string, every time.Duration, out io.Writer, apply func(context.Context) error) error {
	last, err := fingerprint(path)
	if err != nil {
		return err
	}
	run := func() {
		if err := apply(ctx); err != nil {
			fmt.Fprintln(out, "apply failed, waiting for the next change:", err)
		}
	}
	run()
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		now, err := fingerprint(path)
		if err != nil || now == last {
			continue // a file mid-save may be briefly missing
		}
		// wait one more tick so an editor's write-then-rename settles into one apply
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		if again, err := fingerprint(path); err != nil || again != now {
			continue
		}
		last = now
		fmt.Fprintln(out, "change detected")
		run()
	}
}

// fingerprint hashes the names, sizes and modification times of the manifest files under path.
func fingerprint(path string) ([32]byte, error) {
	var sb strings.Builder
	err := filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(p)) {
		case ".yaml", ".yml", ".json":
		default:
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		fmt.Fprintf(&sb, "%s|%d|%d\n", p, info.Size(), info.ModTime().UnixNano())
		return nil
	})
	if err == nil && sb.Len() == 0 {
		if _, serr := os.Stat(path); serr != nil {
			err = serr
		}
	}
	return sha256.Sum256([]byte(sb.String())), err
}
