package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"github.com/watchtowerobservability/watchtower-cli/internal/netguard"
)

// maxArtifactBytes matches the API limit per file (after decompression).
const maxArtifactBytes = 100 << 20

// artifactOpts is where and as whom files are uploaded.
type artifactOpts struct {
	api, key, project, release string
}

func (o *artifactOpts) flags(fs *flag.FlagSet) {
	fs.StringVar(&o.api, "api", "", "API base URL")
	fs.StringVar(&o.key, "key", os.Getenv("WT_API_KEY"), "API key (project admin); default $WT_API_KEY")
	fs.StringVar(&o.project, "project", "", "project id")
	fs.StringVar(&o.release, "release", "", "release version (must exist)")
}

func (o *artifactOpts) check() error {
	if o.api == "" || o.key == "" || o.project == "" {
		return errors.New("--api, --key and --project are required")
	}
	return nil
}

// uploadArtifact sends one file gzip-compressed. name is a slash-separated relative path.
func uploadArtifact(ctx context.Context, o artifactOpts, kind, name string, data []byte) error {
	if len(data) > maxArtifactBytes {
		return fmt.Errorf("%s: larger than %d MiB", name, maxArtifactBytes>>20)
	}
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	if _, err := zw.Write(data); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	q := url.Values{"kind": {kind}, "name": {name}}
	if o.release != "" {
		q.Set("release", o.release)
	}
	u := strings.TrimRight(o.api, "/") + "/v1/projects/" + url.PathEscape(o.project) + "/artifacts?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, &z)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+o.key)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := netguard.Guarded("wtctl", 0).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s: %s: %s", name, resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

// findFiles lists regular files under root (symlinks are skipped, so nothing outside root is read)
// whose names match keep, as slash-separated paths relative to root.
func findFiles(root string, keep func(name string) bool) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() || !keep(d.Name()) {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	return out, err
}

// sourcemapsUpload uploads every *.map under dir as a source map named by its relative path.
func sourcemapsUpload(ctx context.Context, o artifactOpts, dir string, out io.Writer) error {
	names, err := findFiles(dir, func(n string) bool { return strings.HasSuffix(n, ".map") })
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return errors.New("no .map files under " + dir)
	}
	for _, n := range names {
		data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(n)))
		if err != nil {
			return err
		}
		if err := uploadArtifact(ctx, o, "sourcemap", n, data); err != nil {
			return err
		}
		fmt.Fprintf(out, "uploaded %s\n", n)
	}
	return nil
}

func sourcemapsMain(ctx context.Context, args []string, out io.Writer) error {
	const usage = "usage: wtctl sourcemaps upload <dir> --api <url> --key <key> --project <prj_...> [--release <version>]"
	if len(args) < 2 || args[0] != "upload" || strings.HasPrefix(args[1], "-") {
		return errors.New(usage)
	}
	var o artifactOpts
	fs := flag.NewFlagSet("sourcemaps upload", flag.ContinueOnError)
	o.flags(fs)
	if err := fs.Parse(args[2:]); err != nil {
		return err
	}
	if err := o.check(); err != nil {
		return err
	}
	return sourcemapsUpload(ctx, o, args[1], out)
}
