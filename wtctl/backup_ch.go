package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
	"github.com/watchtowerobservability/watchtower-cli/internal/netguard"
)

var chHTTP = netguard.Guarded("wtctl", 6*time.Hour) // BACKUP runs synchronously

func chDatabase() string { return envOr("WT_CH_DATABASE", "default") }

// chExec posts one statement to WT_CH_URL and returns the body.
func chExec(ctx context.Context, sql string) (string, error) {
	raw := os.Getenv("WT_CH_URL")
	if raw == "" {
		return "", errors.New("WT_CH_URL is not set")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(sql))
	if err != nil {
		return "", err
	}
	resp, err := chHTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("clickhouse: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return string(b), nil
}

func sqlStr(s string) string { return "'" + strings.NewReplacer(`\`, `\\`, "'", `\'`).Replace(s) + "'" }

// chTarget renders the BACKUP/RESTORE location for one backup part (credentials included; never log it).
// file:// destinations use the server disk `backups`, which the server config must allow.
func chTarget(d Dest, id, part string) (location, withSecret string) {
	if s, ok := d.(*s3Dest); ok {
		u := fmt.Sprintf("%s/%s/%s", s.endpoint, s.bucket, path.Join(s.prefix, id, part))
		return "S3(" + sqlStr(u) + ")", "S3(" + sqlStr(u) + ", " + sqlStr(s.creds.AccessKeyID) + ", " + sqlStr(s.creds.SecretAccessKey) + ")"
	}
	loc := "Disk('backups', " + sqlStr(id+"-"+part+".zip") + ")"
	return loc, loc
}

// withSecrets re-renders a stored location (without credentials) for execution.
func withSecrets(d Dest, loc string) string {
	s, ok := d.(*s3Dest)
	if !ok || !strings.HasPrefix(loc, "S3(") {
		return loc
	}
	return strings.TrimSuffix(loc, ")") + ", " + sqlStr(s.creds.AccessKeyID) + ", " + sqlStr(s.creds.SecretAccessKey) + ")"
}

// controlTables are always backed up in full, even for incremental runs.
func controlTables() []string {
	return strings.Split(envOr("WT_CH_CONTROL_TABLES", "wt_schema_migrations"), ",")
}

func chBackup(ctx context.Context, d Dest, m *Manifest, incremental, wait bool) error {
	db := chDatabase()
	if v, err := chExec(ctx, "SELECT max(version) FROM "+db+".wt_schema_migrations FORMAT TSV"); err == nil {
		m.SchemaVersions["ch"] = strings.TrimSpace(v)
	}
	async := ""
	if !wait {
		async = " ASYNC"
	}
	// Control tables: always full.
	var tabs []string
	for _, t := range controlTables() {
		tabs = append(tabs, "TABLE "+db+"."+strings.TrimSpace(t))
	}
	ctlLoc, ctlExec := chTarget(d, m.ID, "ch-control")
	if _, err := chExec(ctx, "BACKUP "+strings.Join(tabs, ", ")+" TO "+ctlExec+async); err != nil {
		return err
	}
	loc, exec := chTarget(d, m.ID, "ch")
	sql := "BACKUP DATABASE " + db + " TO " + exec
	var settings []string
	if incremental {
		prev, err := newestCHBackup(ctx, d)
		if err != nil {
			return err
		}
		if prev != nil {
			settings = append(settings, "base_backup = "+withSecrets(d, prev.CHBackup))
			m.Incremental, m.Base = true, prev.ID
		}
	}
	if len(settings) > 0 {
		sql += " SETTINGS " + strings.Join(settings, ", ")
	}
	if _, err := chExec(ctx, sql+async); err != nil {
		return err
	}
	m.CHBackup = loc
	// shortcut: server-side backups carry no client sha256 or size; ClickHouse checksums them on RESTORE.
	m.Objects = append(m.Objects, Object{Name: "clickhouse/" + db}, Object{Name: "clickhouse-control/" + ctlLoc})
	return nil
}

func newestCHBackup(ctx context.Context, d Dest) (*Manifest, error) {
	ms, err := listManifests(ctx, d)
	if err != nil {
		return nil, err
	}
	for i := len(ms) - 1; i >= 0; i-- {
		if ms[i].CHBackup != "" {
			return &ms[i], nil
		}
	}
	return nil, nil
}

func chRestore(ctx context.Context, d Dest, m Manifest) error {
	if m.CHBackup == "" {
		return errors.New("backup has no ClickHouse part")
	}
	_, err := chExec(ctx, "RESTORE DATABASE "+chDatabase()+" FROM "+withSecrets(d, m.CHBackup))
	return err
}

// chDatabaseEmpty reports whether the target database has no tables.
func chDatabaseEmpty(ctx context.Context) (bool, error) {
	out, err := chExec(ctx, "SELECT count() FROM system.tables WHERE database = "+sqlStr(chDatabase())+" FORMAT TSV")
	return strings.TrimSpace(out) == "0", err
}
