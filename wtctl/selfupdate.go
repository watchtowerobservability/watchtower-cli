package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// `wtctl self-update` (SDK-006, W15): replaces the running binary with `wtctl_<os>_<arch>[.exe]`
// (the asset names of the watchtower-cli GitHub release) from a release location, after checking
// it against that location's SHA256SUMS. The location is https (http only for localhost), from
// --url, else $WTCTL_UPDATE_URL, else the latest GitHub release.

const selfUpdateUsage = `usage: wtctl self-update [--url <release URL> | $WTCTL_UPDATE_URL] [--check]   (default: the latest GitHub release)`

const maxBinary = 256 << 20

func selfUpdateMain(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("self-update", flag.ContinueOnError)
	def := os.Getenv("WTCTL_UPDATE_URL")
	if def == "" {
		def = defaultUpdateURL
	}
	base := fs.String("url", def, "release location holding SHA256SUMS and the binaries")
	check := fs.Bool("check", false, "only print the checksum the update would install")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *base == "" {
		return errors.New(selfUpdateUsage)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	return selfUpdate(ctx, *base, exe, *check, out)
}

func updateAsset() string {
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	return fmt.Sprintf("wtctl_%s_%s%s", runtime.GOOS, runtime.GOARCH, ext)
}

func selfUpdate(ctx context.Context, base, target string, check bool, out io.Writer) error {
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || u.Host == "" {
		return errors.New("--url must be an absolute URL")
	}
	local := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return errors.New("--url must be https")
	}
	asset := updateAsset()
	sums, err := fetch(ctx, u.String()+"/SHA256SUMS", 1<<20)
	if err != nil {
		return err
	}
	want := sumFor(sums, asset)
	if want == "" {
		return fmt.Errorf("SHA256SUMS has no entry for %s", asset)
	}
	if check {
		_, err := fmt.Fprintf(out, "%s %s\n", want, asset)
		return err
	}
	bin, err := fetch(ctx, u.String()+"/"+asset, maxBinary)
	if err != nil {
		return err
	}
	got := sha256.Sum256(bin)
	if hex.EncodeToString(got[:]) != want {
		return fmt.Errorf("%s does not match its SHA256SUMS entry; nothing was replaced", asset)
	}
	if err := replaceBinary(target, bin); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "updated %s (%s)\n", target, want[:12])
	return err
}

// sumFor finds `<hex>  <name>` (or `<hex> *<name>`) in a SHA256SUMS file.
func sumFor(sums []byte, name string) string {
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name && len(f[0]) == 64 {
			if _, err := hex.DecodeString(f[0]); err == nil {
				return strings.ToLower(f[0])
			}
		}
	}
	return ""
}

func fetch(ctx context.Context, u string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := guardedClient(5 * time.Minute).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("GET %s: larger than %d bytes", u, limit)
	}
	return b, nil
}

// replaceBinary writes next to the target and renames over it, so a failed write leaves the old
// binary. Windows cannot replace a running executable, so it is moved aside to <name>.old first.
func replaceBinary(target string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(target), ".wtctl-update-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		old := target + ".old"
		_ = os.Remove(old)
		if err := os.Rename(target, old); err != nil {
			return err
		}
	}
	return os.Rename(tmp.Name(), target)
}
