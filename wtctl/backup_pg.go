package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
)

func pgDumpBin() string { return envOr("WT_PG_DUMP", "pg_dump") }

// pgWithDB swaps the database name of a Postgres URL.
func pgWithDB(raw, db string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	u.Path = "/" + db
	return u.String(), nil
}

func pgConnect(ctx context.Context, raw string) (*pgx.Conn, error) {
	if raw == "" {
		return nil, errors.New("WT_PG_URL is not set")
	}
	return pgx.Connect(ctx, raw)
}

// pgRowCounts counts rows of every public table in one snapshot transaction.
func pgRowCounts(ctx context.Context, c *pgx.Conn) (map[string]int64, error) {
	tx, err := c.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := tx.Query(ctx, "SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE' ORDER BY 1")
	if err != nil {
		return nil, err
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	rows.Close()
	out := map[string]int64{}
	for _, n := range names {
		var cnt int64
		// n comes from the catalog; identifier-quoted.
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+pgx.Identifier{"public", n}.Sanitize()).Scan(&cnt); err != nil {
			return nil, err
		}
		out[n] = cnt
	}
	return out, nil
}

// pgSchemaVersion is the newest applied migration, "" when unknown.
func pgSchemaVersion(ctx context.Context, c *pgx.Conn) string {
	var v int64
	if err := c.QueryRow(ctx, "SELECT max(version) FROM _sqlx_migrations").Scan(&v); err != nil {
		return ""
	}
	return fmt.Sprint(v)
}

// ledgerHash fingerprints the deletion ledger so a restore can tell whether it is behind.
func ledgerHash(ctx context.Context, c *pgx.Conn) string {
	var s string
	err := c.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(jsonb_build_object('id',id,'kind',kind,'project',project_id,'state',state)
		ORDER BY id)::text,'[]') FROM deletion_requests`).Scan(&s)
	if err != nil {
		return ""
	}
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func runCmd(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s: %w: %s", filepath.Base(name), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// pgDump runs pg_dump --format=custom into a temp file and returns its bytes.
func pgDump(ctx context.Context, pgURL string) ([]byte, error) {
	f, err := os.CreateTemp("", "wt-pgdump-*")
	if err != nil {
		return nil, err
	}
	name := f.Name()
	_ = f.Close()
	defer os.Remove(name)
	if _, err := runCmd(ctx, pgDumpBin(), "--format=custom", "--no-owner", "--file="+name, "--dbname="+pgURL); err != nil {
		return nil, err
	}
	return os.ReadFile(name)
}

// pgRestoreInto restores a custom-format dump; force adds --clean --if-exists.
func pgRestoreInto(ctx context.Context, dump []byte, pgURL string, force bool) error {
	f, err := os.CreateTemp("", "wt-pgrestore-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(dump); err != nil {
		return err
	}
	_ = f.Close()
	args := []string{"--no-owner", "--exit-on-error", "--dbname=" + pgURL}
	if force {
		args = append(args, "--clean", "--if-exists")
	}
	_, err = runCmd(ctx, envOr("WT_PG_RESTORE", "pg_restore"), append(args, f.Name())...)
	return err
}

var unsafeID = regexp.MustCompile(`[^a-z0-9_]`)

// scratchDBName is wt_restore_check_<id>, restricted to identifier characters.
func scratchDBName(id string) string {
	return "wt_restore_check_" + unsafeID.ReplaceAllString(strings.ToLower(id), "_")
}

// kafkaOffsets records the consumer group offsets as advice (best effort).
func kafkaOffsets(ctx context.Context) map[string]any {
	brokers, group := os.Getenv("WT_KAFKA"), envOr("WT_KAFKA_GROUP", "wt-worker")
	out := map[string]any{"group": group}
	if brokers == "" {
		return out
	}
	cl, err := kgo.NewClient(kgo.SeedBrokers(strings.Split(brokers, ",")...))
	if err != nil {
		out["error"] = err.Error()
		return out
	}
	defer cl.Close()
	resp, err := kadm.NewClient(cl).FetchOffsets(ctx, group)
	if err != nil {
		out["error"] = err.Error()
		return out
	}
	offs := map[string]map[int32]int64{}
	resp.Each(func(o kadm.OffsetResponse) {
		if offs[o.Topic] == nil {
			offs[o.Topic] = map[int32]int64{}
		}
		offs[o.Topic][o.Partition] = o.At
	})
	out["consumer_group_offsets"] = offs
	return out
}

func createBackup(ctx context.Context, d Dest, secret string, incremental, wait bool) (Manifest, error) {
	if secret == "" {
		return Manifest{}, errors.New("WT_BACKUP_KEY is not set")
	}
	pgURL := os.Getenv("WT_PG_URL")
	c, err := pgConnect(ctx, pgURL)
	if err != nil {
		return Manifest{}, err
	}
	defer c.Close(ctx)
	now := time.Now().UTC()
	m := Manifest{ID: newBackupID(now), CreatedAt: now, Version: 1, SchemaVersions: map[string]string{"pg": pgSchemaVersion(ctx, c)}}
	dump, err := pgDump(ctx, pgURL)
	if err != nil {
		return m, err
	}
	obj, err := putObject(ctx, d, m.ID, secret, "postgres.dump.enc", dump)
	if err != nil {
		return m, err
	}
	m.Objects = append(m.Objects, obj)
	if m.PGRows, err = pgRowCounts(ctx, c); err != nil {
		return m, err
	}
	m.LedgerHash = ledgerHash(ctx, c)
	m.Kafka = kafkaOffsets(ctx)
	if os.Getenv("WT_CH_URL") != "" {
		if err := chBackup(ctx, d, &m, incremental, wait); err != nil {
			return m, err
		}
	}
	// The manifest goes last: until it exists the backup does not exist.
	return m, writeManifest(ctx, d, m)
}

// verifyBackup re-hashes the objects and test-restores the dump into wt_restore_check_<id>.
func verifyBackup(ctx context.Context, d Dest, secret string, m Manifest) error {
	if err := verifyObjects(ctx, d, m); err != nil {
		return err
	}
	sealed, err := d.Get(ctx, path.Join(m.ID, "postgres.dump.enc"))
	if err != nil {
		return err
	}
	dump, err := openObject(secret, "postgres.dump.enc", sealed)
	if err != nil {
		return err
	}
	pgURL := os.Getenv("WT_PG_URL")
	admin, err := pgConnect(ctx, pgURL)
	if err != nil {
		return err
	}
	defer admin.Close(ctx)
	db := scratchDBName(m.ID)
	q := pgx.Identifier{db}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+q); err != nil {
		return err
	}
	defer func() { _, _ = admin.Exec(context.WithoutCancel(ctx), "DROP DATABASE IF EXISTS "+q+" WITH (FORCE)") }()
	scratchURL, err := pgWithDB(pgURL, db)
	if err != nil {
		return err
	}
	if err := pgRestoreInto(ctx, dump, scratchURL, false); err != nil {
		return err
	}
	sc, err := pgConnect(ctx, scratchURL)
	if err != nil {
		return err
	}
	defer sc.Close(ctx)
	got, err := pgRowCounts(ctx, sc)
	if err != nil {
		return err
	}
	return compareCounts(m.PGRows, got)
}

func compareCounts(want, got map[string]int64) error {
	var bad []string
	for t, n := range want {
		if got[t] != n {
			bad = append(bad, fmt.Sprintf("%s: manifest %d, restored %d", t, n, got[t]))
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("row counts differ: %s", strings.Join(bad, "; "))
	}
	return nil
}

// auditBackup appends backup.<action> to audit_events (first organization; the ledger is cluster-wide).
// Best effort: a missing database or organization never fails the backup.
func auditBackup(ctx context.Context, action, id string) error {
	c, err := pgConnect(ctx, os.Getenv("WT_PG_URL"))
	if err != nil {
		return nil
	}
	defer c.Close(ctx)
	_, _ = c.Exec(ctx, `INSERT INTO audit_events (id, org_id, actor_type, actor_id, action, target_type, target_id)
		SELECT gen_random_uuid(), id, 'system', 'wtctl', $1, 'backup', $2 FROM organizations ORDER BY created_at LIMIT 1`, action, id)
	return nil
}
