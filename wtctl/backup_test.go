package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

type recordingDest struct {
	Dest
	puts []string
}

func (r *recordingDest) Put(ctx context.Context, key string, data []byte) error {
	r.puts = append(r.puts, key)
	return r.Dest.Put(ctx, key, data)
}

func TestManifestWrittenLast(t *testing.T) {
	ctx := context.Background()
	rd := &recordingDest{Dest: fileDest{dir: t.TempDir()}}
	m := Manifest{ID: "b1", CreatedAt: time.Now()}
	o, err := putObject(ctx, rd, m.ID, "k", "postgres.dump.enc", []byte("dump"))
	if err != nil {
		t.Fatal(err)
	}
	m.Objects = append(m.Objects, o)
	if ms, _ := listManifests(ctx, rd); len(ms) != 0 {
		t.Fatalf("a backup without a manifest must not exist, got %d", len(ms))
	}
	if err := writeManifest(ctx, rd, m); err != nil {
		t.Fatal(err)
	}
	if last := rd.puts[len(rd.puts)-1]; last != "b1/manifest.json" {
		t.Fatalf("manifest must be written last, got %v", rd.puts)
	}
	if ms, _ := listManifests(ctx, rd); len(ms) != 1 {
		t.Fatalf("manifest should make the backup exist, got %d", len(ms))
	}
}

func TestEncryptedObjectsDecryptOnlyWithKey(t *testing.T) {
	plain := []byte("select secret from customers")
	sealed, err := sealObject("key-one", "postgres.dump.enc", plain)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sealed), "secret") {
		t.Fatal("ciphertext leaks plaintext")
	}
	got, err := openObject("key-one", "postgres.dump.enc", sealed)
	if err != nil || string(got) != string(plain) {
		t.Fatalf("roundtrip: %q %v", got, err)
	}
	if _, err := openObject("key-two", "postgres.dump.enc", sealed); err == nil {
		t.Fatal("wrong key must not decrypt")
	}
	if _, err := openObject("key-one", "other.enc", sealed); err == nil {
		t.Fatal("object name is bound into the key")
	}
	if _, err := sealObject("", "x", plain); err == nil {
		t.Fatal("missing WT_BACKUP_KEY must fail")
	}
	again, _ := sealObject("key-one", "postgres.dump.enc", plain)
	if sha(again) == sha(sealed) {
		t.Fatal("nonce must be per object")
	}
}

func TestPruneKeepsWindow(t *testing.T) {
	ctx := context.Background()
	d := fileDest{dir: t.TempDir()}
	now := time.Now()
	for id, age := range map[string]time.Duration{"old": 40 * 24 * time.Hour, "edge": 30 * 24 * time.Hour, "new": time.Hour} {
		if _, err := putObject(ctx, d, id, "k", "postgres.dump.enc", []byte(id)); err != nil {
			t.Fatal(err)
		}
		if err := writeManifest(ctx, d, Manifest{ID: id, CreatedAt: now.Add(-age)}); err != nil {
			t.Fatal(err)
		}
	}
	gone, err := pruneBackups(ctx, d, now, 35*24*time.Hour)
	if err != nil || len(gone) != 1 || gone[0] != "old" {
		t.Fatalf("pruned %v %v", gone, err)
	}
	if keys, _ := d.List(ctx, "old/"); len(keys) != 0 {
		t.Fatalf("old objects remain: %v", keys)
	}
	if ms, _ := listManifests(ctx, d); len(ms) != 2 {
		t.Fatalf("want 2 kept, got %d", len(ms))
	}
	// The newest backup survives even when everything is past the window.
	if got := pruneSet([]Manifest{{ID: "a", CreatedAt: now.Add(-90 * 24 * time.Hour)}}, now, 35*24*time.Hour); len(got) != 0 {
		t.Fatalf("last backup must be kept: %v", got)
	}
}

func TestRestoreRefusesNonEmpty(t *testing.T) {
	if err := refuseNonEmpty(map[string]int64{"projects": 3}, true, false); err == nil {
		t.Fatal("non-empty postgres must be refused")
	}
	if err := refuseNonEmpty(nil, false, false); err == nil {
		t.Fatal("non-empty clickhouse must be refused")
	}
	if err := refuseNonEmpty(map[string]int64{"projects": 3}, false, true); err != nil {
		t.Fatalf("--force overrides: %v", err)
	}
	if err := refuseNonEmpty(nil, true, false); err != nil {
		t.Fatalf("empty target is fine: %v", err)
	}
}

func TestVerifyObjectsDetectsCorruption(t *testing.T) {
	ctx := context.Background()
	d := fileDest{dir: t.TempDir()}
	o, _ := putObject(ctx, d, "b", "k", "postgres.dump.enc", []byte("x"))
	m := Manifest{ID: "b", Objects: []Object{o}}
	if err := verifyObjects(ctx, d, m); err != nil {
		t.Fatal(err)
	}
	_ = d.Put(ctx, "b/postgres.dump.enc", []byte("tampered"))
	if err := verifyObjects(ctx, d, m); err == nil {
		t.Fatal("corrupt object must fail verification")
	}
}

func TestScratchDBNameIsIdentifierSafe(t *testing.T) {
	if got := scratchDBName("20261030T010203Z-AB12"); got != "wt_restore_check_20261030t010203z_ab12" {
		t.Fatal(got)
	}
}
