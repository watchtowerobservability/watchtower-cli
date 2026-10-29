package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const restoreUsage = "usage: wtctl restore --from s3://bucket/prefix|file:///dir [--id <backup id>] [--pg-only|--ch-only] --into-empty [--force] [--no-wait] [--purge-timeout 10m]"

// kept by the purge on purpose (mirrors services/janitor PG_KEEP), so not checked for tombstoned projects.
var verifyKept = map[string]bool{"audit_events": true, "deletion_requests": true, "deletion_steps": true, "legal_holds": true, "projects": true}

// refuseNonEmpty is the --into-empty guard: any existing table in the target blocks a restore unless forced.
func refuseNonEmpty(pgTables map[string]int64, chEmpty, force bool) error {
	if force {
		return nil
	}
	if len(pgTables) > 0 {
		return fmt.Errorf("target Postgres is not empty (%d tables); restore into an empty database or pass --force", len(pgTables))
	}
	if !chEmpty {
		return errors.New("target ClickHouse database is not empty; restore into an empty database or pass --force")
	}
	return nil
}

func restoreMain(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	from := fs.String("from", "", "backup destination")
	id := fs.String("id", "", "backup id (default newest)")
	pgOnly := fs.Bool("pg-only", false, "restore Postgres only")
	chOnly := fs.Bool("ch-only", false, "restore ClickHouse only")
	empty := fs.Bool("into-empty", false, "required: confirm the target is a fresh deployment")
	force := fs.Bool("force", false, "restore over a non-empty target (pg_restore --clean)")
	noWait := fs.Bool("no-wait", false, "queue the ledger re-application and return without waiting for the janitor")
	timeout := fs.Duration("purge-timeout", 10*time.Minute, "how long to wait for the janitor to finish re-purging")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*empty {
		return errors.New("--into-empty is required\n" + restoreUsage)
	}
	if *pgOnly && *chOnly {
		return errors.New("--pg-only and --ch-only are exclusive")
	}
	d, err := openDest(*from)
	if err != nil {
		return err
	}
	m, err := pickBackup(ctx, d, *id)
	if err != nil {
		return err
	}
	doPG, doCH := !*chOnly, !*pgOnly && m.CHBackup != "" && os.Getenv("WT_CH_URL") != ""
	pgURL := os.Getenv("WT_PG_URL")
	if err := guardTarget(ctx, pgURL, doPG, doCH, *force); err != nil {
		return err
	}
	secret := os.Getenv("WT_BACKUP_KEY")
	if doPG {
		sealed, err := d.Get(ctx, path.Join(m.ID, "postgres.dump.enc"))
		if err != nil {
			return err
		}
		dump, err := openObject(secret, "postgres.dump.enc", sealed)
		if err != nil {
			return err
		}
		if err := pgRestoreInto(ctx, dump, pgURL, *force); err != nil {
			return err
		}
		fmt.Fprintln(out, "postgres restored")
	}
	if doCH {
		if err := chRestore(ctx, d, m); err != nil {
			return err
		}
		fmt.Fprintln(out, "clickhouse restored")
	}
	if doPG {
		if err := reapplyAndVerify(ctx, out, !*noWait, *timeout); err != nil {
			return err
		}
	}
	if offs, ok := m.Kafka["consumer_group_offsets"]; ok {
		fmt.Fprintf(out, "advice: Kafka offsets at backup time were %v; replay from Kafka retention rather than rewinding\n", offs)
	}
	return auditBackup(ctx, "backup.restore", m.ID)
}

func guardTarget(ctx context.Context, pgURL string, doPG, doCH, force bool) error {
	tables := map[string]int64{}
	if doPG {
		c, err := pgConnect(ctx, pgURL)
		if err != nil {
			return err
		}
		defer c.Close(ctx)
		if tables, err = pgRowCounts(ctx, c); err != nil {
			return err
		}
	}
	chEmpty := true
	if doCH {
		var err error
		if chEmpty, err = chDatabaseEmpty(ctx); err != nil {
			return err
		}
	}
	return refuseNonEmpty(tables, chEmpty, force)
}

// reapplyLedger puts every project purge that had started or finished back in the janitor's queue,
// marking its steps `reapplied` (not `done`, so the janitor runs them again). Returns request ids and projects.
func reapplyLedger(ctx context.Context, c *pgx.Conn) (reqs []string, projects []string, err error) {
	tx, err := c.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	const open = "kind = 'project' AND project_id IS NOT NULL AND state IN ('completed','running','verifying')"
	if _, err := tx.Exec(ctx, "UPDATE deletion_steps SET state = 'reapplied', updated_at = now() WHERE request_id IN (SELECT id FROM deletion_requests WHERE "+open+")"); err != nil {
		return nil, nil, err
	}
	rows, err := tx.Query(ctx, "UPDATE deletion_requests SET state = 'queued', completed_at = NULL, ledger_hash = NULL, not_before = NULL WHERE "+open+" RETURNING id::text, project_id::text")
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var r, p string
		if err := rows.Scan(&r, &p); err != nil {
			return nil, nil, err
		}
		reqs, projects = append(reqs, r), append(projects, p)
	}
	rows.Close()
	if rows.Err() != nil {
		return nil, nil, rows.Err()
	}
	return reqs, projects, tx.Commit(ctx)
}

func reapplyAndVerify(ctx context.Context, out io.Writer, wait bool, timeout time.Duration) error {
	c, err := pgConnect(ctx, os.Getenv("WT_PG_URL"))
	if err != nil {
		return err
	}
	defer c.Close(ctx)
	reqs, projects, err := reapplyLedger(ctx, c)
	if err != nil {
		return fmt.Errorf("re-apply deletion ledger: %w", err)
	}
	fmt.Fprintf(out, "deletion ledger: %d purge requests re-queued\n", len(reqs))
	if len(reqs) == 0 {
		return nil
	}
	if !wait {
		fmt.Fprintln(out, "re-queued purges run when wt-janitor ticks; tombstoned projects must then have 0 rows (not yet verified)")
		return nil
	}
	deadline := time.Now().Add(timeout)
	for {
		var pending int
		if err := c.QueryRow(ctx, "SELECT count(*) FROM deletion_requests WHERE id::text = ANY($1) AND state <> 'completed'", reqs).Scan(&pending); err != nil {
			return err
		}
		if pending == 0 {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("janitor has not finished re-purging %d requests within %s (is wt-janitor running?)", pending, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return verifyTombstoned(ctx, c, projects, out)
}

// verifyTombstoned requires zero rows for the given projects in every Postgres table with a project_id
// column (minus the kept ones) and every ClickHouse table with a project_id column.
func verifyTombstoned(ctx context.Context, c *pgx.Conn, projects []string, out io.Writer) error {
	rows, err := c.Query(ctx, `SELECT c.table_name FROM information_schema.columns c
		JOIN information_schema.tables t USING (table_schema, table_name)
		WHERE c.table_schema='public' AND c.column_name='project_id' AND t.table_type='BASE TABLE'`)
	if err != nil {
		return err
	}
	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return err
		}
		if !verifyKept[n] {
			tables = append(tables, n)
		}
	}
	rows.Close()
	var bad []string
	for _, t := range tables {
		var n int64
		if err := c.QueryRow(ctx, "SELECT count(*) FROM "+pgx.Identifier{"public", t}.Sanitize()+" WHERE project_id::text = ANY($1)", projects).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			bad = append(bad, fmt.Sprintf("postgres %s: %d", t, n))
		}
	}
	if os.Getenv("WT_CH_URL") != "" {
		bad = append(bad, chTombstoneRows(ctx, projects)...)
	}
	if len(bad) > 0 {
		return fmt.Errorf("verify failed, tombstoned projects still have rows: %s", strings.Join(bad, "; "))
	}
	fmt.Fprintf(out, "verify ok: %d tombstoned projects have 0 rows\n", len(projects))
	return nil
}

func chTombstoneRows(ctx context.Context, projects []string) []string {
	var q []string
	for _, p := range projects {
		q = append(q, sqlStr(p))
	}
	out, err := chExec(ctx, "SELECT table FROM system.columns WHERE database = "+sqlStr(chDatabase())+" AND name = 'project_id' FORMAT TSV")
	if err != nil {
		return []string{"clickhouse: " + err.Error()}
	}
	var bad []string
	for _, t := range strings.Fields(out) {
		n, err := chExec(ctx, "SELECT count() FROM `"+chDatabase()+"`.`"+t+"` WHERE toString(project_id) IN ("+strings.Join(q, ",")+") FORMAT TSV")
		if err != nil {
			bad = append(bad, "clickhouse "+t+": "+err.Error())
		} else if strings.TrimSpace(n) != "0" {
			bad = append(bad, "clickhouse "+t+": "+strings.TrimSpace(n))
		}
	}
	return bad
}
