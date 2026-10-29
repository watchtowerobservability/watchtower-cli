package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
)

const upgradeUsage = `usage: wtctl upgrade preflight|plan|apply|verify [flags]
  preflight  free disk, Kafka lag, running migrations, backup age (<24h), compat matrix
  plan       preflight plus pending migrations and the rollout order
  apply      preflight, run --migrate-cmd (expand only), check the schema, print the rollout order
  verify     GET /v1/system/version on every --replicas URL; fail on mixed versions or schema
  env: WT_PG_URL, WT_CH_URL, WT_KAFKA, WT_KAFKA_GROUP, WT_MIGRATE_CMD`

// rolloutOrder: expand-only migrations first, then consumers before producers so the edge
// never emits data a not-yet-upgraded consumer cannot read. K3 performs it in-cluster.
var rolloutOrder = []string{"janitor", "worker", "notifier", "api", "gateway"}

type compatEntry struct {
	Release string `json:"release"`
	PGMin   int    `json:"schema_pg_min"`
	PGMax   int    `json:"schema_pg_max"`
	CHMin   int    `json:"schema_ch_min"`
	CHMax   int    `json:"schema_ch_max"`
}

func (e compatEntry) contains(pg, ch int) bool {
	return pg >= e.PGMin && pg <= e.PGMax && ch >= e.CHMin && ch <= e.CHMax
}

func loadCompat(path string) ([]compatEntry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m []compatEntry
	if err := json.Unmarshal(b, &m); err != nil || len(m) == 0 {
		return nil, fmt.Errorf("%s: want a non-empty JSON array (%v)", path, err)
	}
	return m, nil
}

// upgradeEnv holds the probes; tests replace them, the CLI wires the real ones.
type upgradeEnv struct {
	Now               time.Time
	NewestBackup      func(ctx context.Context) (time.Time, error) // zero time = none
	KafkaLag          func(ctx context.Context) (int64, error)
	FreeDisk          func(ctx context.Context) (uint64, error)
	RunningMigrations func(ctx context.Context) (int, error)
	Schema            func(ctx context.Context) (pg, ch int, err error)
	Compat            []compatEntry
}

type upgradeOpts struct {
	MinFreeBytes  uint64
	MaxLag        int64
	MaxBackupAge  time.Duration
	NoBackupCheck bool
}

type checkResult struct {
	Name   string
	OK     bool
	Detail string
}

func preflight(ctx context.Context, e upgradeEnv, o upgradeOpts) []checkResult {
	var out []checkResult
	add := func(name string, ok bool, detail string) { out = append(out, checkResult{name, ok, detail}) }
	if e.FreeDisk != nil {
		if free, err := e.FreeDisk(ctx); err != nil {
			add("disk", false, err.Error())
		} else {
			add("disk", free >= o.MinFreeBytes, fmt.Sprintf("%d GiB free, need %d", free>>30, o.MinFreeBytes>>30))
		}
	}
	if e.KafkaLag != nil {
		if lag, err := e.KafkaLag(ctx); err != nil {
			add("kafka-lag", false, err.Error())
		} else {
			add("kafka-lag", lag <= o.MaxLag, fmt.Sprintf("lag %d, max %d", lag, o.MaxLag))
		}
	}
	if e.RunningMigrations != nil {
		if n, err := e.RunningMigrations(ctx); err != nil {
			add("migrations-idle", false, err.Error())
		} else {
			add("migrations-idle", n == 0, fmt.Sprintf("%d running", n))
		}
	}
	switch {
	case o.NoBackupCheck:
		add("backup", true, "skipped (--no-backup-check)")
	case e.NewestBackup == nil:
		add("backup", false, "no backup destination (--dest) to check; pass --no-backup-check to override")
	default:
		t, err := e.NewestBackup(ctx)
		switch {
		case err != nil:
			add("backup", false, err.Error())
		case t.IsZero():
			add("backup", false, "no backup found")
		default:
			age := e.Now.Sub(t)
			add("backup", age <= o.MaxBackupAge, fmt.Sprintf("newest %s old, max %s", age.Round(time.Minute), o.MaxBackupAge))
		}
	}
	if e.Schema != nil {
		pg, ch, err := e.Schema(ctx)
		switch {
		case err != nil:
			add("compat", false, err.Error())
		default:
			target := e.Compat[len(e.Compat)-1]
			add("compat", target.contains(pg, ch), fmt.Sprintf("live pg %d ch %d; release %s supports pg %d..%d ch %d..%d",
				pg, ch, target.Release, target.PGMin, target.PGMax, target.CHMin, target.CHMax))
		}
	}
	return out
}

func printChecks(out io.Writer, cs []checkResult) error {
	failed := 0
	for _, c := range cs {
		mark := "ok  "
		if !c.OK {
			mark, failed = "FAIL", failed+1
		}
		fmt.Fprintf(out, "%s %-16s %s\n", mark, c.Name, c.Detail)
	}
	if failed > 0 {
		return fmt.Errorf("preflight: %d check(s) failed", failed)
	}
	return nil
}

// versionDoc is the subset of GET /v1/system/version that verify compares.
type versionDoc struct {
	BuildSHA string `json:"build_sha"`
	Schema   struct {
		PG *int `json:"pg"`
		CH *int `json:"ch"`
	} `json:"schema"`
}

// verifyReplicas fetches every replica's version and fails on mixed builds or a schema
// outside the newest compat range. fetch is injected for tests.
func verifyReplicas(ctx context.Context, urls []string, compat []compatEntry, fetch func(context.Context, string) (versionDoc, error)) (string, error) {
	if len(urls) == 0 {
		return "", errors.New("verify: --replicas is empty")
	}
	shas := map[string][]string{}
	target := compat[len(compat)-1]
	var problems []string
	for _, u := range urls {
		d, err := fetch(ctx, u)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", u, err))
			continue
		}
		shas[d.BuildSHA] = append(shas[d.BuildSHA], u)
		if d.Schema.PG != nil && (*d.Schema.PG < target.PGMin || *d.Schema.PG > target.PGMax) ||
			d.Schema.CH != nil && (*d.Schema.CH < target.CHMin || *d.Schema.CH > target.CHMax) {
			problems = append(problems, fmt.Sprintf("%s: schema outside release %s range", u, target.Release))
		}
	}
	if len(shas) > 1 {
		var parts []string
		for sha, us := range shas {
			parts = append(parts, fmt.Sprintf("%s=%s", sha, strings.Join(us, ",")))
		}
		sort.Strings(parts)
		problems = append(problems, "mixed versions: "+strings.Join(parts, " "))
	}
	if len(problems) > 0 {
		return "", errors.New(strings.Join(problems, "; "))
	}
	for sha := range shas {
		return fmt.Sprintf("%d replicas on build %s", len(urls), sha), nil
	}
	return "", nil
}

func httpVersion(ctx context.Context, base string) (versionDoc, error) {
	var d versionDoc
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/v1/system/version", nil)
	if err != nil {
		return d, err
	}
	resp, err := guardedClient(10 * time.Second).Do(req)
	if err != nil {
		return d, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return d, fmt.Errorf("status %d", resp.StatusCode)
	}
	return d, json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&d)
}

var migNum = regexp.MustCompile(`^(\d{4})_`)

// pendingMigrations counts migration files numbered above the live version.
func pendingMigrations(dir, dialect string, live int) int {
	files, _ := filepath.Glob(filepath.Join(dir, dialect, "*.sql"))
	n := 0
	for _, f := range files {
		if m := migNum.FindStringSubmatch(filepath.Base(f)); m != nil {
			if v, _ := strconv.Atoi(m[1]); v > live {
				n++
			}
		}
	}
	return n
}

func realEnv(ctx context.Context, dest, group string) upgradeEnv {
	e := upgradeEnv{Now: time.Now()}
	if dest != "" {
		e.NewestBackup = func(ctx context.Context) (time.Time, error) {
			d, err := openDest(dest)
			if err != nil {
				return time.Time{}, err
			}
			ms, err := listManifests(ctx, d)
			if err != nil || len(ms) == 0 {
				return time.Time{}, err
			}
			return ms[len(ms)-1].CreatedAt, nil
		}
	}
	pgConn := func(ctx context.Context) (*pgx.Conn, error) { return pgx.Connect(ctx, os.Getenv("WT_PG_URL")) }
	chInt := func(ctx context.Context, sql string) (int64, error) {
		s, err := chExec(ctx, sql)
		if err != nil {
			return 0, err
		}
		return strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	}
	if os.Getenv("WT_CH_URL") != "" {
		e.FreeDisk = func(ctx context.Context) (uint64, error) {
			n, err := chInt(ctx, "SELECT toInt64(min(free_space)) FROM system.disks FORMAT TSV")
			return uint64(max(n, 0)), err
		}
	}
	if os.Getenv("WT_PG_URL") != "" {
		e.RunningMigrations = func(ctx context.Context) (int, error) {
			c, err := pgConn(ctx)
			if err != nil {
				return 0, err
			}
			defer c.Close(ctx)
			var n int
			err = c.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE pid <> pg_backend_pid()
				AND state = 'active' AND query ILIKE '%_sqlx_migrations%'`).Scan(&n)
			return n, err
		}
	}
	if os.Getenv("WT_PG_URL") != "" && os.Getenv("WT_CH_URL") != "" {
		e.Schema = func(ctx context.Context) (int, int, error) {
			c, err := pgConn(ctx)
			if err != nil {
				return 0, 0, err
			}
			defer c.Close(ctx)
			var pg int
			if err := c.QueryRow(ctx, `SELECT COALESCE(max(version), 0)::int FROM _sqlx_migrations WHERE success`).Scan(&pg); err != nil {
				return 0, 0, err
			}
			s, err := chExec(ctx, "SELECT max(version) FROM wt_schema_migrations FORMAT TSV")
			if err != nil || len(strings.TrimSpace(s)) < 4 {
				return 0, 0, fmt.Errorf("clickhouse schema version: %v", err)
			}
			ch, err := strconv.Atoi(strings.TrimSpace(s)[:4])
			return pg, ch, err
		}
	}
	if brokers := os.Getenv("WT_KAFKA"); brokers != "" && group != "" {
		e.KafkaLag = func(ctx context.Context) (int64, error) {
			cl, err := kgo.NewClient(kgo.SeedBrokers(strings.Split(brokers, ",")...))
			if err != nil {
				return 0, err
			}
			defer cl.Close()
			ls, err := kadm.NewClient(cl).Lag(ctx, group)
			if err != nil {
				return 0, err
			}
			l, ok := ls[group]
			if !ok {
				return 0, fmt.Errorf("consumer group %q not found", group)
			}
			if err := l.Error(); err != nil {
				return 0, err
			}
			return l.Lag.Total(), nil
		}
	}
	return e
}

func upgradeMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) < 1 {
		return errors.New(upgradeUsage)
	}
	fs := flag.NewFlagSet("upgrade "+args[0], flag.ContinueOnError)
	compatPath := fs.String("compat", "infra/compat.json", "compat matrix")
	migDir := fs.String("migrations", "infra/migrations", "migration files (for the pending count)")
	dest := fs.String("dest", os.Getenv("WT_BACKUP_DEST"), "backup destination, s3://bucket/prefix or file:///dir")
	group := fs.String("kafka-group", os.Getenv("WT_KAFKA_GROUP"), "consumer group whose lag is checked")
	minFree := fs.Uint64("min-free-gb", 20, "minimum free disk on the ClickHouse server")
	maxLag := fs.Int64("max-lag", 100000, "maximum Kafka consumer lag (messages)")
	noBackup := fs.Bool("no-backup-check", false, "skip the backup-newer-than-24h check")
	migrateCmd := fs.String("migrate-cmd", os.Getenv("WT_MIGRATE_CMD"), "apply: command that runs the expand migrations (e.g. the API with WT_MIGRATE=1)")
	replicas := fs.String("replicas", "", "verify: comma-separated replica base URLs")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	compat, err := loadCompat(*compatPath)
	if err != nil {
		return err
	}
	if args[0] == "verify" {
		msg, err := verifyReplicas(ctx, strings.Split(*replicas, ","), compat, httpVersion)
		if err == nil {
			fmt.Fprintln(out, msg)
		}
		return err
	}
	if args[0] != "preflight" && args[0] != "plan" && args[0] != "apply" {
		return errors.New(upgradeUsage)
	}
	env := realEnv(ctx, *dest, *group)
	env.Compat = compat
	opts := upgradeOpts{MinFreeBytes: *minFree << 30, MaxLag: *maxLag, MaxBackupAge: 24 * time.Hour, NoBackupCheck: *noBackup}
	if err := printChecks(out, preflight(ctx, env, opts)); err != nil {
		return err
	}
	if args[0] == "preflight" {
		return nil
	}
	if env.Schema == nil {
		return errors.New("plan/apply need WT_PG_URL and WT_CH_URL")
	}
	pg, ch, err := env.Schema(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "pending: postgres %d, clickhouse %d\n", pendingMigrations(*migDir, "postgres", pg), pendingMigrations(*migDir, "clickhouse", ch))
	if args[0] == "apply" {
		f := strings.Fields(*migrateCmd)
		if len(f) == 0 {
			return errors.New("apply: --migrate-cmd (or WT_MIGRATE_CMD) is required")
		}
		cmd := exec.CommandContext(ctx, f[0], f[1:]...)
		cmd.Stdout, cmd.Stderr = out, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		pg, ch, err = env.Schema(ctx)
		if err != nil {
			return err
		}
		if t := compat[len(compat)-1]; !t.contains(pg, ch) {
			return fmt.Errorf("after migrating, pg %d ch %d is outside release %s range", pg, ch, t.Release)
		}
		fmt.Fprintf(out, "migrated to pg %d ch %d (expand only; binaries may roll back freely)\n", pg, ch)
	}
	fmt.Fprintf(out, "rollout order: %s\n", strings.Join(rolloutOrder, " -> "))
	return nil
}
