package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-cli/pluginsdk"
)

const pluginUsage = `usage: wtctl plugin keygen --out publisher.seed
       wtctl plugin pack --dir build/ --key publisher.seed --out influxdb.tar.gz
       wtctl plugin push --file influxdb.tar.gz --api <url> --key <key> --org <org_...>`

// pluginMain packs a plugin directory (plugin.yaml plus the plugin or plugin.exe executable) into
// the signed tarball the plugins API and go/pluginrunner verify: a detached Ed25519 signature over
// the tarball's SHA-256, base64 in <out>.sig.
func pluginMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(pluginUsage)
	}
	fl := flag.NewFlagSet("plugin "+args[0], flag.ContinueOnError)
	dir := fl.String("dir", "", "directory to pack (pack)")
	seedFile := fl.String("key", "", "base64url Ed25519 seed file (keygen, pack); API key (push)")
	outFile := fl.String("out", "", "output file (keygen, pack)")
	file := fl.String("file", "", "tarball to upload (push)")
	api := fl.String("api", "", "API base URL (push)")
	org := fl.String("org", "", "org id (push)")
	if err := fl.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "keygen":
		if *outFile == "" {
			return errors.New(pluginUsage)
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		seed := base64.RawURLEncoding.EncodeToString(priv.Seed())
		// O_EXCL: never overwrite an existing publisher key.
		f, err := os.OpenFile(*outFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if _, err := f.WriteString(seed + "\n"); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "public_key (add to plugin-trust publisher_keys): %s\n", base64.StdEncoding.EncodeToString(pub))
		return err
	case "pack":
		if *dir == "" || *seedFile == "" || *outFile == "" {
			return errors.New(pluginUsage)
		}
		raw, err := os.ReadFile(*seedFile)
		if err != nil {
			return err
		}
		seed, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(seed) != ed25519.SeedSize {
			return errors.New("--key must hold a base64url 32-byte Ed25519 seed")
		}
		tarball, err := packPlugin(*dir)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(tarball)
		sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), sum[:])
		if err := os.WriteFile(*outFile, tarball, 0o644); err != nil {
			return err
		}
		if err := os.WriteFile(*outFile+".sig", []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644); err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "%s sha256 %s, signature %s.sig\n", *outFile, hex.EncodeToString(sum[:]), *outFile)
		return err
	case "push":
		if *file == "" || *api == "" || *seedFile == "" || *org == "" {
			return errors.New(pluginUsage)
		}
		return pushPlugin(ctx, *file, strings.TrimRight(*api, "/"), *seedFile, *org, out)
	}
	return errors.New(pluginUsage)
}

// packPlugin tars and gzips every regular file under dir, sorted, with fixed times so the same
// inputs give the same bytes. The manifest must validate and the executable must be present.
func packPlugin(dir string) ([]byte, error) {
	m, err := os.ReadFile(filepath.Join(dir, "plugin.yaml"))
	if err != nil {
		return nil, fmt.Errorf("plugin.yaml: %w", err)
	}
	if _, err := pluginsdk.ParseManifest(m); err != nil {
		return nil, err
	}
	var files []string
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			rel, err := filepath.Rel(dir, p)
			if err != nil {
				return err
			}
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	hasBin := false
	for _, f := range files {
		hasBin = hasBin || f == "plugin" || f == "plugin.exe"
	}
	if !hasBin {
		return nil, errors.New("the directory has no plugin or plugin.exe executable")
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(f)))
		if err != nil {
			return nil, err
		}
		h := &tar.Header{Name: f, Mode: 0o755, Size: int64(len(b)), ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(h); err != nil {
			return nil, err
		}
		if _, err := tw.Write(b); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// manifestOf reads plugin.yaml back out of a packed tarball, as the JSON the API takes.
func manifestOf(tarball []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(tarball))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err != nil {
			return nil, errors.New("tarball has no plugin.yaml")
		}
		if h.Name == "plugin.yaml" {
			b, err := io.ReadAll(io.LimitReader(tr, 16<<10))
			if err != nil {
				return nil, err
			}
			m, err := pluginsdk.ParseManifest(b)
			if err != nil {
				return nil, err
			}
			return json.Marshal(m)
		}
	}
}

func pushPlugin(ctx context.Context, file, api, key, org string, out io.Writer) error {
	tarball, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	m, err := manifestOf(tarball)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, api+"/v1/orgs/"+url.PathEscape(org)+"/plugins", bytes.NewReader(tarball))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/gzip")
	req.Header.Set("x-plugin-manifest", base64.StdEncoding.EncodeToString(m))
	// An unsigned upload is accepted only when the org's trust policy allows it.
	if sig, err := os.ReadFile(file + ".sig"); err == nil {
		req.Header.Set("x-plugin-signature", strings.TrimSpace(string(sig)))
	}
	resp, err := guardedClient(5 * time.Minute).Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("upload: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	_, err = out.Write(append(body, '\n'))
	return err
}
