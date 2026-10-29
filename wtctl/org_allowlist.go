package main

// Break-glass for a locked-out org (P6-E5, SEC-012): `wtctl org allowlist clear --org <id>`
// disables every IP allowlist of the org directly in Postgres (needs WT_PG_URL, i.e. database
// access) and records an audit event. The org id is the UUID or the `org_` prefixed form.
// The audit row is written without a chain position (seq NULL); the audit chain (P6-E4) treats
// it as unchained.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"
)

const orgUsage = `usage: wtctl org allowlist clear --org <org_...|uuid>
  env: WT_PG_URL (needs database access; disables every IP allowlist scope of the org)`

func orgMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) < 2 || args[0] != "allowlist" || args[1] != "clear" {
		return errors.New(orgUsage)
	}
	fs := flag.NewFlagSet("org allowlist clear", flag.ContinueOnError)
	org := fs.String("org", "", "org id")
	if err := fs.Parse(args[2:]); err != nil {
		return err
	}
	id := strings.TrimPrefix(*org, "org_")
	if id == "" || os.Getenv("WT_PG_URL") == "" {
		return errors.New(orgUsage)
	}
	conn, err := pgx.Connect(ctx, os.Getenv("WT_PG_URL"))
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	n, err := clearAllowlists(ctx, conn, id)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "cleared %d allowlist scope(s) for org %s\n", n, *org)
	return nil
}

// clearAllowlists disables and empties every scope and audits the action in one transaction.
func clearAllowlists(ctx context.Context, conn *pgx.Conn, orgID string) (int64, error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tag, err := tx.Exec(ctx,
		`UPDATE ip_allowlists SET enabled = false, cidrs = '{}' WHERE org_id = $1::uuid`, orgID)
	if err != nil {
		return 0, err
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO audit_events (id, org_id, actor_type, actor_id, action, target_type, target_id, metadata)
		 VALUES (gen_random_uuid(), $1::uuid, 'system', 'wtctl', 'ip_allowlist.clear', 'org', $1::text, '{"break_glass":true}')`, orgID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), tx.Commit(ctx)
}
