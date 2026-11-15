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
	"sort"
	"strings"
	"sync"
)

// maxArtifactBytes matches the API limit per file (after decompression).
const maxArtifactBytes = 100 << 20

// presignOver is the size above which a file goes straight to the object store through a presigned
// link, when the server offers one, instead of through the API.
var presignOver = 50 << 20

// artifactClient is one client for every upload of a run, so the connection (and its TLS session)
// is reused (keep-alive) instead of dialled again per file.
var artifactClient = sync.OnceValue(func() *http.Client { return guardedClient(0) })

// artifactOpts is where and as whom files are uploaded.
type artifactOpts struct {
	api, key, project, release, dist string
	concurrency                      int  // parallel uploads; 0 = 4
	bundle                           bool // try POST /artifacts/bundle first (one tar.gz for every map)
	del                              bool // delete each .map from disk once it is stored
}

func (o *artifactOpts) flags(fs *flag.FlagSet) {
	fs.StringVar(&o.api, "api", apiEnv(), "API base URL; default $WT_API_URL")
	fs.StringVar(&o.key, "key", os.Getenv("WT_API_KEY"), "API key (project admin); default $WT_API_KEY")
	fs.StringVar(&o.project, "project", os.Getenv("WT_PROJECT"), "project id; default $WT_PROJECT")
	fs.StringVar(&o.release, "release", "", "release version (created if missing, see --create-release)")
	fs.StringVar(&o.dist, "dist", "", "build of the release (Sentry dist); events with that dist prefer these files")
}

func (o *artifactOpts) check() error {
	if o.api == "" || o.key == "" || o.project == "" {
		return errors.New("--api, --key and --project are required")
	}
	return nil
}

// uploadArtifact sends one file. name is a slash-separated relative path. Files over presignOver
// try a presigned object-store link first and fall back to the API when the server has none.
func uploadArtifact(ctx context.Context, o artifactOpts, kind, name string, data []byte) error {
	if len(data) > maxArtifactBytes {
		return fmt.Errorf("%s: larger than %d MiB", name, maxArtifactBytes>>20)
	}
	q := url.Values{"kind": {kind}, "name": {name}}
	if o.release != "" {
		q.Set("release", o.release)
	}
	if o.dist != "" {
		q.Set("dist", o.dist)
	}
	base := strings.TrimRight(o.api, "/") + "/v1/projects/" + url.PathEscape(o.project) + "/artifacts"
	if len(data) > presignOver {
		if done, err := uploadPresigned(ctx, o, base, q, name, data); done {
			return err
		}
	}
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	if _, err := zw.Write(data); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return withRetry(ctx, name, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"?"+q.Encode(), bytes.NewReader(z.Bytes()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+o.key)
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Content-Encoding", "gzip")
		return req, nil
	})
}

// doArtifact sends req and turns a non-2xx answer into an error naming the file.
func doArtifact(req *http.Request, name string) error {
	resp, err := artifactClient().Do(req)
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

// uploadPresigned asks for a presigned PUT link, sends the raw bytes to it and tells the API to
// register them. done is false when the server has no link to give (the caller then uploads
// through the API); once the PUT has started, any failure is final.
func uploadPresigned(ctx context.Context, o artifactOpts, base string, q url.Values, name string, data []byte) (done bool, err error) {
	var link struct {
		UploadID string `json:"upload_id"`
		URL      string `json:"url"`
	}
	if err := call(ctx, http.MethodPost, base+"/upload-url", o.key, nil, &link); err != nil || link.URL == "" {
		return false, nil
	}
	put, err := http.NewRequestWithContext(ctx, http.MethodPut, link.URL, bytes.NewReader(data))
	if err != nil {
		return true, err
	}
	if err := doArtifact(put, name); err != nil {
		return true, err
	}
	q.Set("upload_id", link.UploadID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/complete?"+q.Encode(), nil)
	if err != nil {
		return true, err
	}
	req.Header.Set("Authorization", "Bearer "+o.key)
	return true, doArtifact(req, name)
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

// sourcemapsUpload uploads every *.map under dir as a source map named by its relative path:
// as one bundle when o.bundle and the server has the endpoint, else file by file in parallel.
// It reports a count and fails when any file failed.
func sourcemapsUpload(ctx context.Context, o artifactOpts, dir string, out io.Writer) error {
	names, err := findFiles(dir, func(n string) bool { return strings.HasSuffix(n, ".map") })
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return errors.New("no .map files under " + dir)
	}
	ok := map[string]bool{}
	var failed []string
	if o.bundle {
		if res, err := uploadBundle(ctx, o, dir, names); err == nil {
			fmt.Fprintf(out, "bundle: %d uploaded, %d unchanged, %d failed\n", res.Uploaded, res.Skipped, res.Failed)
			for _, e := range res.Errors {
				fmt.Fprintln(out, "failed:", e)
			}
			if res.Failed > 0 {
				return fmt.Errorf("%d of %d source maps failed", res.Failed, len(names))
			}
			for _, n := range names {
				ok[n] = true
			}
			return o.removeLocal(dir, ok)
		} else if !errors.Is(err, errNoBundle) {
			return err
		}
	}
	n := o.concurrency
	if n <= 0 {
		n = 4
	}
	var mu sync.Mutex
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	for _, name := range names {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
			if err == nil {
				err = uploadArtifact(ctx, o, "sourcemap", name, data)
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed = append(failed, err.Error())
				return
			}
			ok[name] = true
			fmt.Fprintf(out, "uploaded %s\n", name)
		}()
	}
	wg.Wait()
	if len(failed) > 0 {
		sort.Strings(failed)
		fmt.Fprintf(out, "%d uploaded, %d failed\n", len(ok), len(failed))
		return fmt.Errorf("%d of %d source maps failed: %s", len(failed), len(names), strings.Join(failed, "; "))
	}
	fmt.Fprintf(out, "%d uploaded, 0 failed\n", len(ok))
	return o.removeLocal(dir, ok)
}

func (o artifactOpts) removeLocal(dir string, names map[string]bool) error {
	if !o.del {
		return nil
	}
	for n := range names {
		if err := os.Remove(filepath.Join(dir, filepath.FromSlash(n))); err != nil {
			return err
		}
	}
	return nil
}

func sourcemapsMain(ctx context.Context, args []string, out io.Writer) error {
	const usage = "usage: wtctl sourcemaps upload <dir> --api <url> --key <key> --project <prj_...> [--release <version>] [--create-release=false] [--dist <dist>] [--concurrency 4] [--delete]\n       wtctl sourcemaps verify --release <v> --url <script-url> --line <n> --column <c>  (--api and --project default to $WT_API_URL, $WT_PROJECT)"
	if len(args) > 0 && args[0] == "verify" {
		return sourcemapsVerify(ctx, args[1:], out)
	}
	if len(args) < 2 || args[0] != "upload" || strings.HasPrefix(args[1], "-") {
		return errors.New(usage)
	}
	var o artifactOpts
	fs := flag.NewFlagSet("sourcemaps upload", flag.ContinueOnError)
	o.flags(fs)
	fs.IntVar(&o.concurrency, "concurrency", 4, "parallel uploads when not bundling")
	fs.BoolVar(&o.bundle, "bundle", true, "send every map as one tar.gz to /artifacts/bundle when the server has it")
	fs.BoolVar(&o.del, "delete", false, "delete each .map from disk after it is stored")
	create := fs.Bool("create-release", true, "create --release first (idempotent) so it need not exist; =false to require it")
	if err := fs.Parse(args[2:]); err != nil {
		return err
	}
	if err := o.check(); err != nil {
		return err
	}
	if *create && o.release != "" {
		base := strings.TrimRight(o.api, "/") + "/v1/projects/" + url.PathEscape(o.project)
		if err := call(ctx, http.MethodPost, base+"/releases", o.key, map[string]any{"version": o.release}, nil); err != nil {
			return fmt.Errorf("create release %s: %w", o.release, err)
		}
	}
	return sourcemapsUpload(ctx, o, args[1], out)
}
