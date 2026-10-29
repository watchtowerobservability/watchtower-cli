package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const backupUsage = "usage: wtctl backup create --dest s3://bucket/prefix|file:///dir [--incremental] [--wait]\n" +
	"       wtctl backup list|prune --dest <dest> [--keep-days 35]\n" +
	"       wtctl backup verify --dest <dest> [--id <backup id>]\n" +
	"       env: WT_PG_URL, WT_CH_URL, WT_CH_DATABASE, WT_BACKUP_KEY, WT_PG_DUMP, WT_KAFKA, WT_KAFKA_GROUP"

// Object is one stored file of a backup.
type Object struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// Manifest describes a backup. It is written last: a backup without one does not exist.
type Manifest struct {
	ID             string            `json:"id"`
	CreatedAt      time.Time         `json:"created_at"`
	Version        int               `json:"version"`
	SchemaVersions map[string]string `json:"schema_versions"`
	Objects        []Object          `json:"objects"`
	Kafka          map[string]any    `json:"kafka"`
	LedgerHash     string            `json:"deletion_ledger_hash"`
	PGRows         map[string]int64  `json:"pg_rows,omitempty"`
	CHBackup       string            `json:"ch_backup,omitempty"`
	Incremental    bool              `json:"incremental,omitempty"`
	Base           string            `json:"base,omitempty"`
}

// Dest is where backups live: keys are slash paths relative to the destination prefix.
type Dest interface {
	Put(ctx context.Context, key string, data []byte) error
	Get(ctx context.Context, key string) ([]byte, error)
	List(ctx context.Context, prefix string) ([]string, error)
	Delete(ctx context.Context, key string) error
	// URL is the destination as given, used to build the ClickHouse BACKUP target.
	URL() string
}

type fileDest struct{ dir string }

func (d fileDest) URL() string { return "file://" + d.dir }

func (d fileDest) Put(_ context.Context, key string, data []byte) error {
	p := filepath.Join(d.dir, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o600)
}

func (d fileDest) Get(_ context.Context, key string) ([]byte, error) {
	return os.ReadFile(filepath.Join(d.dir, filepath.FromSlash(key)))
}

func (d fileDest) Delete(_ context.Context, key string) error {
	return os.Remove(filepath.Join(d.dir, filepath.FromSlash(key)))
}

func (d fileDest) List(_ context.Context, prefix string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(d.dir, func(p string, e os.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if e.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(d.dir, p)
		if k := filepath.ToSlash(rel); strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

func openDest(raw string) (Dest, error) {
	switch {
	case strings.HasPrefix(raw, "file://"):
		return fileDest{dir: strings.TrimPrefix(raw, "file://")}, nil
	case strings.HasPrefix(raw, "s3://"):
		return newS3Dest(raw)
	}
	return nil, errors.New("--dest must be s3://bucket/prefix or file:///dir")
}

// objectKey derives the per-object AES-256 key from WT_BACKUP_KEY (HKDF-SHA256).
func objectKey(secret, name string) ([]byte, error) {
	if secret == "" {
		return nil, errors.New("WT_BACKUP_KEY is not set")
	}
	return hkdf.Key(sha256.New, []byte(secret), nil, "wt-backup/"+name, 32)
}

func newGCM(secret, name string) (cipher.AEAD, error) {
	key, err := objectKey(secret, name)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// sealObject gzips then encrypts with AES-256-GCM; output is nonce || ciphertext.
// shortcut: whole object in memory; stream in chunks if dumps outgrow RAM.
func sealObject(secret, name string, plain []byte) ([]byte, error) {
	gcm, err := newGCM(secret, name)
	if err != nil {
		return nil, err
	}
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	if _, err := zw.Write(plain); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, z.Bytes(), []byte(name)), nil
}

func openObject(secret, name string, sealed []byte) ([]byte, error) {
	gcm, err := newGCM(secret, name)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("backup object truncated")
	}
	zipped, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], []byte(name))
	if err != nil {
		return nil, fmt.Errorf("decrypt %s: wrong WT_BACKUP_KEY or corrupt object", name)
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(zr)
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// putObject stores one encrypted object and returns its manifest entry.
func putObject(ctx context.Context, d Dest, id, secret, name string, plain []byte) (Object, error) {
	sealed, err := sealObject(secret, name, plain)
	if err != nil {
		return Object{}, err
	}
	if err := d.Put(ctx, path.Join(id, name), sealed); err != nil {
		return Object{}, err
	}
	return Object{Name: name, SHA256: sha(sealed), Bytes: int64(len(sealed))}, nil
}

// writeManifest is always the last write of a backup.
func writeManifest(ctx context.Context, d Dest, m Manifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return d.Put(ctx, path.Join(m.ID, "manifest.json"), b)
}

func readManifest(ctx context.Context, d Dest, id string) (Manifest, error) {
	var m Manifest
	b, err := d.Get(ctx, path.Join(id, "manifest.json"))
	if err != nil {
		return m, fmt.Errorf("backup %s has no manifest (it does not exist): %w", id, err)
	}
	return m, json.Unmarshal(b, &m)
}

// listManifests returns every backup that has a manifest, oldest first.
func listManifests(ctx context.Context, d Dest) ([]Manifest, error) {
	keys, err := d.List(ctx, "")
	if err != nil {
		return nil, err
	}
	var out []Manifest
	for _, k := range keys {
		if id, ok := strings.CutSuffix(k, "/manifest.json"); ok && !strings.Contains(id, "/") {
			m, err := readManifest(ctx, d, id)
			if err != nil {
				return nil, err
			}
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// pruneSet picks the backups older than the window; the newest backup is always kept.
func pruneSet(ms []Manifest, now time.Time, window time.Duration) []Manifest {
	var out []Manifest
	for i, m := range ms {
		if i < len(ms)-1 && now.Sub(m.CreatedAt) > window {
			out = append(out, m)
		}
	}
	return out
}

func pruneBackups(ctx context.Context, d Dest, now time.Time, window time.Duration) ([]string, error) {
	ms, err := listManifests(ctx, d)
	if err != nil {
		return nil, err
	}
	var gone []string
	for _, m := range pruneSet(ms, now, window) {
		keys, err := d.List(ctx, m.ID+"/")
		if err != nil {
			return gone, err
		}
		// Manifest first: a half-deleted backup then no longer exists.
		sort.SliceStable(keys, func(i, j int) bool {
			return strings.HasSuffix(keys[i], "/manifest.json") && !strings.HasSuffix(keys[j], "/manifest.json")
		})
		for _, k := range keys {
			if err := d.Delete(ctx, k); err != nil {
				return gone, err
			}
		}
		gone = append(gone, m.ID)
	}
	return gone, nil
}

// verifyObjects re-hashes every stored object against the manifest.
func verifyObjects(ctx context.Context, d Dest, m Manifest) error {
	for _, o := range m.Objects {
		if o.SHA256 == "" {
			continue // server-side ClickHouse backup: the server verifies it on restore
		}
		b, err := d.Get(ctx, path.Join(m.ID, o.Name))
		if err != nil {
			return fmt.Errorf("object %s: %w", o.Name, err)
		}
		if got := sha(b); got != o.SHA256 {
			return fmt.Errorf("object %s is corrupt: sha256 %s, manifest %s", o.Name, got, o.SHA256)
		}
	}
	return nil
}

func backupMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) < 1 {
		return errors.New(backupUsage)
	}
	fs := flag.NewFlagSet("backup "+args[0], flag.ContinueOnError)
	destURL := fs.String("dest", "", "s3://bucket/prefix or file:///dir")
	incr := fs.Bool("incremental", false, "ClickHouse incremental against the newest backup (control tables stay full)")
	wait := fs.Bool("wait", true, "wait for the ClickHouse backup to finish")
	id := fs.String("id", "", "verify: backup id (default newest)")
	keep := fs.Int("keep-days", 35, "prune: retention in days")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	d, err := openDest(*destURL)
	if err != nil {
		return err
	}
	secret := os.Getenv("WT_BACKUP_KEY")
	switch args[0] {
	case "create":
		m, err := createBackup(ctx, d, secret, *incr, *wait)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "backup %s created (%d objects)\n", m.ID, len(m.Objects))
		return auditBackup(ctx, "backup.create", m.ID)
	case "list":
		ms, err := listManifests(ctx, d)
		if err != nil {
			return err
		}
		for _, m := range ms {
			fmt.Fprintf(out, "%s\t%s\t%d objects\n", m.ID, m.CreatedAt.Format(time.RFC3339), len(m.Objects))
		}
		return nil
	case "prune":
		gone, err := pruneBackups(ctx, d, time.Now(), time.Duration(*keep)*24*time.Hour)
		fmt.Fprintf(out, "pruned %d backups\n", len(gone))
		return err
	case "verify":
		m, err := pickBackup(ctx, d, *id)
		if err != nil {
			return err
		}
		if err := verifyBackup(ctx, d, secret, m); err != nil {
			return err
		}
		fmt.Fprintf(out, "backup %s verified\n", m.ID)
		return auditBackup(ctx, "backup.verify", m.ID)
	}
	return errors.New(backupUsage)
}

func pickBackup(ctx context.Context, d Dest, id string) (Manifest, error) {
	if id != "" {
		return readManifest(ctx, d, id)
	}
	ms, err := listManifests(ctx, d)
	if err != nil || len(ms) == 0 {
		return Manifest{}, errors.Join(err, errors.New("no backups found"))
	}
	return ms[len(ms)-1], nil
}

func newBackupID(now time.Time) string {
	r := make([]byte, 3)
	_, _ = rand.Read(r)
	return now.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(r)
}
