package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

func okEnv(now time.Time, backup time.Time) upgradeEnv {
	return upgradeEnv{
		Now:               now,
		NewestBackup:      func(context.Context) (time.Time, error) { return backup, nil },
		KafkaLag:          func(context.Context) (int64, error) { return 10, nil },
		FreeDisk:          func(context.Context) (uint64, error) { return 100 << 30, nil },
		RunningMigrations: func(context.Context) (int, error) { return 0, nil },
		Schema:            func(context.Context) (int, int, error) { return 89, 47, nil },
		Compat:            []compatEntry{{Release: "0.6.0", PGMin: 1, PGMax: 89, CHMin: 1, CHMax: 49}},
	}
}

func failed(cs []checkResult) map[string]bool {
	m := map[string]bool{}
	for _, c := range cs {
		if !c.OK {
			m[c.Name] = true
		}
	}
	return m
}

func TestPreflightFailsOnStaleBackup(t *testing.T) {
	now := time.Now()
	o := upgradeOpts{MinFreeBytes: 20 << 30, MaxLag: 1000, MaxBackupAge: 24 * time.Hour}
	if f := failed(preflight(context.Background(), okEnv(now, now.Add(-2*time.Hour)), o)); len(f) != 0 {
		t.Fatalf("fresh backup should pass: %v", f)
	}
	if f := failed(preflight(context.Background(), okEnv(now, now.Add(-25*time.Hour)), o)); !f["backup"] || len(f) != 1 {
		t.Fatalf("stale backup must fail only the backup check: %v", f)
	}
	o.NoBackupCheck = true
	if f := failed(preflight(context.Background(), okEnv(now, now.Add(-25*time.Hour)), o)); len(f) != 0 {
		t.Fatalf("--no-backup-check overrides: %v", f)
	}
}

func TestPreflightFailsOutsideCompatRange(t *testing.T) {
	e := okEnv(time.Now(), time.Now())
	e.Schema = func(context.Context) (int, int, error) { return 90, 47, nil }
	e.KafkaLag = func(context.Context) (int64, error) { return 5000, nil }
	f := failed(preflight(context.Background(), e, upgradeOpts{MaxLag: 1000, MaxBackupAge: time.Hour}))
	if !f["compat"] || !f["kafka-lag"] {
		t.Fatalf("got %v", f)
	}
}

func TestVerifyDetectsMixedVersions(t *testing.T) {
	one, nine := 1, 89
	docs := map[string]versionDoc{}
	mk := func(sha string, pg int) versionDoc {
		d := versionDoc{BuildSHA: sha}
		d.Schema.PG, d.Schema.CH = &pg, &one
		return d
	}
	docs["http://a"], docs["http://b"] = mk("abc", nine), mk("abc", nine)
	fetch := func(_ context.Context, u string) (versionDoc, error) { return docs[u], nil }
	compat := []compatEntry{{Release: "0.6.0", PGMin: 1, PGMax: 89, CHMin: 1, CHMax: 49}}
	if _, err := verifyReplicas(context.Background(), []string{"http://a", "http://b"}, compat, fetch); err != nil {
		t.Fatalf("same build passes: %v", err)
	}
	docs["http://b"] = mk("def", nine)
	_, err := verifyReplicas(context.Background(), []string{"http://a", "http://b"}, compat, fetch)
	if err == nil || !strings.Contains(err.Error(), "mixed versions") {
		t.Fatalf("want mixed versions, got %v", err)
	}
	docs["http://b"] = mk("abc", 120)
	if _, err := verifyReplicas(context.Background(), []string{"http://a", "http://b"}, compat, fetch); err == nil {
		t.Fatal("schema outside range must fail")
	}
}
