package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"github.com/watchtowerobservability/watchtower-cli/internal/netguard"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// s3Dest is a minimal path-style S3 client (SigV4) so wtctl needs no extra SDK module.
// Env: WT_BACKUP_S3_ENDPOINT (default https://s3.amazonaws.com), WT_BACKUP_S3_REGION (default us-east-1),
// WT_BACKUP_S3_ACCESS_KEY / WT_BACKUP_S3_SECRET_KEY.
type s3Dest struct {
	raw, endpoint, bucket, prefix, region string
	creds                                 aws.Credentials
	hc                                    *http.Client
}

func newS3Dest(raw string) (Dest, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("bad s3 destination %q", raw)
	}
	d := &s3Dest{
		raw: raw, bucket: u.Host, prefix: strings.Trim(u.Path, "/"),
		endpoint: strings.TrimRight(envOr("WT_BACKUP_S3_ENDPOINT", "https://s3.amazonaws.com"), "/"),
		region:   envOr("WT_BACKUP_S3_REGION", "us-east-1"),
		creds: aws.Credentials{
			AccessKeyID: os.Getenv("WT_BACKUP_S3_ACCESS_KEY"), SecretAccessKey: os.Getenv("WT_BACKUP_S3_SECRET_KEY"),
		},
		hc: netguard.Guarded("wtctl", 10*time.Minute),
	}
	if d.creds.AccessKeyID == "" || d.creds.SecretAccessKey == "" {
		return nil, fmt.Errorf("WT_BACKUP_S3_ACCESS_KEY and WT_BACKUP_S3_SECRET_KEY are required for s3 destinations")
	}
	return d, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func (d *s3Dest) URL() string { return d.raw }

func (d *s3Dest) key(k string) string {
	if d.prefix == "" {
		return k
	}
	return d.prefix + "/" + k
}

func (d *s3Dest) do(ctx context.Context, method, key string, q url.Values, body []byte) ([]byte, error) {
	u := d.endpoint + "/" + d.bucket
	if key != "" {
		u += "/" + (&url.URL{Path: key}).EscapedPath()
	}
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(body)
	hash := hex.EncodeToString(h[:])
	req.Header.Set("x-amz-content-sha256", hash)
	if err := v4.NewSigner().SignHTTP(ctx, d.creds, req, hash, "s3", d.region, time.Now()); err != nil {
		return nil, err
	}
	resp, err := d.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("s3 %s %s: %s", method, key, resp.Status)
	}
	return b, nil
}

func (d *s3Dest) Put(ctx context.Context, key string, data []byte) error {
	_, err := d.do(ctx, http.MethodPut, d.key(key), nil, data)
	return err
}

func (d *s3Dest) Get(ctx context.Context, key string) ([]byte, error) {
	return d.do(ctx, http.MethodGet, d.key(key), nil, nil)
}

func (d *s3Dest) Delete(ctx context.Context, key string) error {
	_, err := d.do(ctx, http.MethodDelete, d.key(key), nil, nil)
	return err
}

func (d *s3Dest) List(ctx context.Context, prefix string) ([]string, error) {
	var out []string
	token := ""
	for {
		q := url.Values{"list-type": {"2"}, "prefix": {d.key(prefix)}}
		if token != "" {
			q.Set("continuation-token", token)
		}
		b, err := d.do(ctx, http.MethodGet, "", q, nil)
		if err != nil {
			return nil, err
		}
		var res struct {
			Contents  []struct{ Key string }
			Truncated bool   `xml:"IsTruncated"`
			Next      string `xml:"NextContinuationToken"`
		}
		if err := xml.Unmarshal(b, &res); err != nil {
			return nil, err
		}
		for _, c := range res.Contents {
			out = append(out, strings.TrimPrefix(strings.TrimPrefix(c.Key, d.prefix), "/"))
		}
		if !res.Truncated {
			return out, nil
		}
		token = res.Next
	}
}
