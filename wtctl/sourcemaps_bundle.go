package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var errNoBundle = errors.New("server has no artifacts/bundle")

// retryBase is the first backoff step (doubling, six tries); a variable so tests are fast.
var retryBase = 500 * time.Millisecond

const maxTries = 6

// withRetry sends the request build makes, again after 429 or 503 (waiting Retry-After seconds
// when the server says, else exponential backoff), up to maxTries times.
func withRetry(ctx context.Context, name string, build func() (*http.Request, error)) error {
	_, err := withRetryBody(ctx, name, build)
	return err
}

func withRetryBody(ctx context.Context, name string, build func() (*http.Request, error)) ([]byte, error) {
	var err error
	for try := 0; try < maxTries; try++ {
		req, berr := build()
		if berr != nil {
			return nil, berr
		}
		var resp *http.Response
		var b []byte
		if resp, b, err = send(req, name); err == nil {
			return b, nil
		}
		if resp == nil || (resp.StatusCode != 429 && resp.StatusCode != 503) {
			return nil, err
		}
		wait := retryBase << try
		if s, perr := strconv.Atoi(resp.Header.Get("Retry-After")); perr == nil && s >= 0 {
			wait = time.Duration(s) * time.Second
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, err
}

// send is doArtifact that also hands back the response (body closed) and its first 64 KiB.
func send(req *http.Request, name string) (*http.Response, []byte, error) {
	resp, err := artifactClient().Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode/100 != 2 {
		return resp, nil, fmt.Errorf("%s: %s: %s", name, resp.Status, strings.TrimSpace(string(b)))
	}
	return resp, b, nil
}

type bundleResult struct {
	Uploaded, Skipped, Failed int
	Errors                    []json.RawMessage
}

// uploadBundle posts every map as one tar.gz. errNoBundle means the server lacks the endpoint
// (404/405), so the caller falls back to one request per file.
func uploadBundle(ctx context.Context, o artifactOpts, dir string, names []string) (bundleResult, error) {
	var res bundleResult
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, n := range names {
		data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(n)))
		if err != nil {
			return res, err
		}
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(data))}); err != nil {
			return res, err
		}
		if _, err := tw.Write(data); err != nil {
			return res, err
		}
	}
	if err := tw.Close(); err != nil {
		return res, err
	}
	if err := zw.Close(); err != nil {
		return res, err
	}
	if buf.Len() > maxArtifactBytes {
		return res, errNoBundle // too big for one request; per-file has no such limit
	}
	q := url.Values{}
	if o.release != "" {
		q.Set("release", o.release)
	}
	if o.dist != "" {
		q.Set("dist", o.dist)
	}
	u := strings.TrimRight(o.api, "/") + "/v1/projects/" + url.PathEscape(o.project) + "/artifacts/bundle?" + q.Encode()
	body, err := withRetryBody(ctx, "bundle", func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(buf.Bytes()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+o.key)
		req.Header.Set("Content-Type", "application/octet-stream")
		return req, nil
	})
	if err != nil {
		if strings.Contains(err.Error(), " 404 ") || strings.Contains(err.Error(), " 405 ") {
			return res, errNoBundle
		}
		return res, err
	}
	err = json.Unmarshal(body, &res)
	return res, err
}
