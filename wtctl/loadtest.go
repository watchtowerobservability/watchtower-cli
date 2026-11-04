package main

// Operator controls of load testing (G8), straight in Postgres (needs WT_PG_URL):
//
//	wtctl loadtest kill   [--org <id>] --reason <text>   stop every run in scope now, admit none
//	wtctl loadtest resume [--org <id>] --reason <text>
//	wtctl loadtest caps   [--org <id>] [--concurrent N] [--rps N] --reason <text>   (-1 clears a cap)
//	wtctl loadtest status
//	wtctl loadtest log    [--limit N]
//
// run, inspect and archive work locally without Postgres: see loadtest_cli.go.
// Without --org the scope is global. The uptime coordinators read load_test_caps on every
// tick: a kill turns running runs into `aborting` (their shards stop within a beat) and queued
// runs into `aborted`. Every change is written to load_test_operator_audit with who (--by, else
// $WT_OPERATOR, else the OS user), when and why; org-scoped ones also to audit_events (unchained,
// as other break-glass rows).

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const loadtestUsage = `usage: wtctl loadtest run|inspect|archive <script> (local, see loadtest_cli.go)
       wtctl loadtest kill|resume|caps|status|log [--org <org_...|uuid>] [--reason <text>] [--by <operator>] [--concurrent N] [--rps N] [--limit N]
  env: WT_PG_URL (needs database access)`

func loadtestMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) > 0 && (args[0] == "run" || args[0] == "inspect" || args[0] == "archive") {
		return loadtestCLI(ctx, args, out)
	}
	if len(args) < 1 || os.Getenv("WT_PG_URL") == "" {
		return errors.New(loadtestUsage)
	}
	fs := flag.NewFlagSet("loadtest "+args[0], flag.ContinueOnError)
	org := fs.String("org", "", "org id (default: global)")
	reason := fs.String("reason", "", "why (required for every change)")
	by := fs.String("by", operatorName(), "who is making the change")
	limit := fs.Int("limit", 50, "log: rows to show")
	conc := fs.Int("concurrent", 0, "max concurrent runs (-1 clears)")
	rps := fs.Int("rps", 0, "max total requests/s (-1 clears)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	scope := "global"
	if *org != "" {
		scope = strings.TrimPrefix(*org, "org_")
	}
	conn, err := pgx.Connect(ctx, os.Getenv("WT_PG_URL"))
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	op := capsOp{scope: scope, actor: *by, reason: *reason}
	switch args[0] {
	case "kill":
		op.action = "loadtest.kill"
		err = op.apply(ctx, conn,
			`INSERT INTO load_test_caps (scope, killed, reason, updated_by) VALUES ($1, true, $3, $2)
			 ON CONFLICT (scope) DO UPDATE SET killed = true, reason = $3, updated_by = $2, updated_at = now()`, scope, op.actor, op.reason)
	case "resume":
		op.action = "loadtest.resume"
		err = op.apply(ctx, conn,
			`UPDATE load_test_caps SET killed = false, reason = NULL, updated_by = $2, updated_at = now() WHERE scope = $1`, scope, op.actor)
	case "caps":
		op.action = "loadtest.caps"
		err = op.apply(ctx, conn,
			`INSERT INTO load_test_caps (scope, max_concurrent, max_rps, updated_by)
			 VALUES ($1, CASE WHEN $2 > 0 THEN $2 END, CASE WHEN $3 > 0 THEN $3 END, $4)
			 ON CONFLICT (scope) DO UPDATE SET
			   max_concurrent = CASE WHEN $2 < 0 THEN NULL WHEN $2 > 0 THEN $2 ELSE load_test_caps.max_concurrent END,
			   max_rps = CASE WHEN $3 < 0 THEN NULL WHEN $3 > 0 THEN $3 ELSE load_test_caps.max_rps END,
			   updated_by = $4, updated_at = now()`, scope, *conc, *rps, op.actor)
	case "status":
		return capsStatus(ctx, conn, out)
	case "log":
		return capsLog(ctx, conn, out, *limit)
	default:
		return errors.New(loadtestUsage)
	}
	if err == nil {
		fmt.Fprintf(out, "loadtest %s applied to %s\n", args[0], scope)
	}
	return err
}

// operatorName is the default actor: $WT_OPERATOR, else the OS user.
func operatorName() string {
	if n := os.Getenv("WT_OPERATOR"); n != "" {
		return n
	}
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}

// capsOp is one operator change of load_test_caps.
type capsOp struct{ scope, action, actor, reason string }

const capsRow = `SELECT to_jsonb(c) FROM load_test_caps c WHERE scope = $1`

// apply makes the change and its audit rows in one transaction: no change without a record.
func (o capsOp) apply(ctx context.Context, conn *pgx.Conn, q string, args ...any) error {
	if o.reason == "" || o.actor == "" {
		return errors.New("every load test control change needs --reason and an operator (--by or WT_OPERATOR)")
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var before, after map[string]any
	if err := tx.QueryRow(ctx, capsRow, o.scope).Scan(&before); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if _, err := tx.Exec(ctx, q, args...); err != nil {
		return err
	}
	if err := tx.QueryRow(ctx, capsRow, o.scope).Scan(&after); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO load_test_operator_audit (actor, action, scope, reason, before, after)
		VALUES ($1, $2, $3, $4, $5, $6)`, o.actor, o.action, o.scope, o.reason, before, after); err != nil {
		return err
	}
	if o.scope != "global" {
		meta := map[string]any{"break_glass": true, "operator": o.actor, "reason": o.reason, "before": before, "after": after}
		if _, err := tx.Exec(ctx, `INSERT INTO audit_events (id, org_id, actor_type, actor_id, action, target_type, target_id, metadata)
			VALUES (gen_random_uuid(), $1::uuid, 'system', 'wtctl', $2, 'org', $1::text, $3)`, o.scope, o.action, meta); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func capsLog(ctx context.Context, conn *pgx.Conn, out io.Writer, limit int) error {
	rows, err := conn.Query(ctx, `SELECT at, actor, action, scope, reason FROM load_test_operator_audit ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return err
	}
	defer rows.Close()
	fmt.Fprintln(out, "at\tactor\taction\tscope\treason")
	for rows.Next() {
		var at time.Time
		var actor, action, scope, why string
		if err := rows.Scan(&at, &actor, &action, &scope, &why); err != nil {
			return err
		}
		fmt.Fprintf(out, "%s\t%s\t%s\t%s\t%s\n", at.UTC().Format(time.RFC3339), actor, action, scope, why)
	}
	return rows.Err()
}

func capsStatus(ctx context.Context, conn *pgx.Conn, out io.Writer) error {
	rows, err := conn.Query(ctx, `SELECT scope, coalesce(max_concurrent::text, '-'), coalesce(max_rps::text, '-'), killed,
		coalesce(reason, '') FROM load_test_caps ORDER BY scope = 'global' DESC, scope`)
	if err != nil {
		return err
	}
	defer rows.Close()
	fmt.Fprintln(out, "scope\tconcurrent\trps\tkilled\treason")
	for rows.Next() {
		var scope, c, r, why string
		var killed bool
		if err := rows.Scan(&scope, &c, &r, &killed, &why); err != nil {
			return err
		}
		fmt.Fprintf(out, "%s\t%s\t%s\t%v\t%s\n", scope, c, r, killed, why)
	}
	return rows.Err()
}
