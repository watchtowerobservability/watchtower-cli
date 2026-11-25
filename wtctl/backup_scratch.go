package main

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
)

// scratchPGOpts keeps the throwaway cluster small and fast: it is destroyed right after the check.
var scratchPGOpts = "-c listen_addresses= -c fsync=off -c synchronous_commit=off -c full_page_writes=off " +
	"-c shared_buffers=64MB -c max_wal_size=1GB -c autovacuum=off"

// scratchURL is the libpq URL of a cluster listening only on a unix socket in dir.
func scratchURL(dir string) string {
	return "postgres://wt@/postgres?sslmode=disable&host=" + url.QueryEscape(dir)
}

// withScratchPG runs fn against a private, empty Postgres cluster (initdb + pg_ctl from the image, so it
// must not run as root) in a temp dir, then stops and deletes it.
func withScratchPG(ctx context.Context, fn func(url string) error) error {
	dir, err := os.MkdirTemp("", "wt-scratch-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	data := filepath.Join(dir, "data")
	if _, err := runCmd(ctx, envOr("WT_INITDB", "initdb"), "-D", data, "-U", "wt", "-A", "trust", "-N"); err != nil {
		return err
	}
	ctl := envOr("WT_PG_CTL", "pg_ctl")
	if _, err := runCmd(ctx, ctl, "-D", data, "-w", "-t", "120", "-o", scratchPGOpts+" -c unix_socket_directories="+dir, "start"); err != nil {
		return err
	}
	defer func() { _, _ = runCmd(context.WithoutCancel(ctx), ctl, "-D", data, "-m", "immediate", "stop") }()
	return fn(scratchURL(dir))
}
