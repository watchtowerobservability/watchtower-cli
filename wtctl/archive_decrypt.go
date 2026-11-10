package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/watchtowerobservability/watchtower-cli/internal/archivecrypt"
)

const archiveUsage = "usage: wtctl archive decrypt --project <uuid> [--out <dir>] <file>...\n" +
	"       Decrypts archive objects downloaded from your bucket (objects start with WTE1).\n" +
	"       Run it where WT_PG_URL and WT_SECRET_KEY of the deployment are set (operator or org admin).\n" +
	"       Plain objects are copied unchanged. Fails with exit 1 after the project's keys were shredded."

// archiveMain: `wtctl archive decrypt`, so encrypted archives are never a lock-in (G6-07).
func archiveMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "decrypt" {
		return errors.New(archiveUsage)
	}
	fs := flag.NewFlagSet("archive decrypt", flag.ContinueOnError)
	project := fs.String("project", "", "project uuid the objects belong to")
	dir := fs.String("out", "", "output directory (default: next to each file, suffix .decrypted)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	pid, err := uuid.Parse(*project)
	if err != nil || fs.NArg() == 0 {
		return errors.New(archiveUsage)
	}
	master, pgURL := os.Getenv("WT_SECRET_KEY"), os.Getenv("WT_PG_URL")
	if master == "" || pgURL == "" {
		return errors.New("WT_SECRET_KEY and WT_PG_URL are required")
	}
	dk, err := loadDataKey(ctx, pgURL, master, pid)
	if err != nil {
		return err
	}
	for _, f := range fs.Args() {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		pt, err := archivecrypt.Open(dk, pid.String(), b)
		if err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		dst := f + ".decrypted"
		if *dir != "" {
			dst = filepath.Join(*dir, filepath.Base(f))
		}
		if err := os.WriteFile(dst, pt, 0o600); err != nil {
			return err
		}
		fmt.Fprintln(out, dst)
	}
	return nil
}

func loadDataKey(ctx context.Context, pgURL, master string, pid uuid.UUID) ([]byte, error) {
	c, err := pgx.Connect(ctx, pgURL)
	if err != nil {
		return nil, err
	}
	defer c.Close(ctx)
	var wrapped []byte
	var shredded bool
	err = c.QueryRow(ctx, `SELECT wrapped_key, shredded_at IS NOT NULL FROM tenant_data_keys WHERE scope_project = $1`, pid).Scan(&wrapped, &shredded)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil, errors.New("no archive key for this project (nothing was encrypted)")
	case err != nil:
		return nil, err
	case shredded:
		return nil, errors.New("the project's archive keys were shredded by an erasure; the objects cannot be decrypted")
	}
	return archivecrypt.Unwrap(master, pid, wrapped)
}
