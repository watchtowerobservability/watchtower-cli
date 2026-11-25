package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// importJob is the answer of POST /v1/projects/{prj}/activity/import.
type importJob struct {
	JobID         string `json:"job_id"`
	Status        string `json:"status"`
	Accepted      int    `json:"accepted"`
	RejectedCount int    `json:"rejected_count"`
	Rejected      []struct {
		Line    int `json:"line"`
		Problem struct {
			Detail string `json:"detail"`
		} `json:"problem"`
	} `json:"rejected"`
	Error string `json:"error"`
}

// ndjsonGzip encodes events one per line and gzips them.
func ndjsonGzip(events []map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	enc := json.NewEncoder(zw) // Encode ends each value with a newline
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// A part holds at most this many lines or this many compressed bytes (the gzip writer buffers a
// little past the limit, hence the slack under 8 MiB); a variable so tests can use small parts.
var (
	importPartLines = 20_000
	importPartBytes = 8<<20 - 256<<10
)

// maxPartResumes is how many failed parts in a row (each after its own retries) end the import.
const maxPartResumes = 5

// postImportJob sends the events in one import call when they fit one part (retrying 429/5xx; a
// re-run is safe because the idempotency keys are deterministic), else in resumable parts, and
// prints the job's totals and rejected lines.
func postImportJob(ctx context.Context, url, key string, events []map[string]any, skipped int, out io.Writer) error {
	body, n, err := importPart(events)
	if err != nil {
		return err
	}
	if n == len(events) {
		b, err := sendImportPart(ctx, url, key, body)
		if err != nil {
			return err
		}
		return printImportJob(b, skipped, out)
	}
	return postImportParts(ctx, url, key, events, skipped, out)
}

// importPart gzips the leading events that fit one part and returns how many it took.
func importPart(events []map[string]any) ([]byte, int, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	enc := json.NewEncoder(zw) // Encode ends each value with a newline
	n := 0
	for n < len(events) && n < importPartLines && buf.Len() < importPartBytes {
		if err := enc.Encode(events[n]); err != nil {
			return nil, 0, err
		}
		n++
	}
	if err := zw.Close(); err != nil {
		return nil, 0, err
	}
	return buf.Bytes(), n, nil
}

// postImportParts appends parts to one job (?job_id=&offset=<lines already sent>). After a failed
// part it reads the job's lines_seen and carries on from there, so nothing is sent twice that the
// server already processed. The last part carries final=true.
func postImportParts(ctx context.Context, url, key string, events []map[string]any, skipped int, out io.Writer) error {
	job := newJobID()
	var last []byte
	pos, fails, closed := 0, 0, false
	for !closed {
		body, n, err := importPart(events[pos:])
		if err != nil {
			return err
		}
		final := pos+n >= len(events)
		q := fmt.Sprintf("?job_id=%s&offset=%d", job, pos)
		if final {
			q += "&final=true"
		}
		b, err := sendImportPart(ctx, url+q, key, body)
		if err != nil {
			if fails++; fails > maxPartResumes {
				return fmt.Errorf("import %s stopped at line %d: %w (re-run is safe: keys are deterministic)", job, pos, err)
			}
			seen, serr := importLinesSeen(ctx, url, job, key)
			if serr != nil {
				return fmt.Errorf("import %s: part at line %d failed (%w) and the job could not be read (%v)", job, pos, err, serr)
			}
			fmt.Fprintf(out, "part at line %d failed (%v); resuming from the server's lines_seen=%d\n", pos, err, seen)
			pos, closed = min(seen, len(events)), false
			continue
		}
		fails, last = 0, b
		pos += n
		closed = final
		fmt.Fprintf(out, "import %s: %d of %d lines sent\n", job, pos, len(events))
	}
	return printImportJob(last, skipped, out)
}

// importLinesSeen reads how many lines the job has processed (GET .../activity/imports/{job}).
func importLinesSeen(ctx context.Context, importURL, job, key string) (int, error) {
	u := strings.TrimSuffix(importURL, "/import") + "/imports/" + job
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := guardedClient(0).Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<22))
	var j struct {
		LinesSeen int `json:"lines_seen"`
	}
	if resp.StatusCode == http.StatusNotFound {
		return 0, nil // the first part never arrived
	}
	if resp.StatusCode/100 != 2 || json.Unmarshal(b, &j) != nil {
		return 0, fmt.Errorf("%s", resp.Status)
	}
	return j.LinesSeen, nil
}

func newJobID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// sendImportPart posts one gzip ndjson body, retrying 429, 5xx and network errors with backoff.
func sendImportPart(ctx context.Context, url, key string, body []byte) ([]byte, error) {
	var last error
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			importSleep(time.Duration(1<<attempt) * 500 * time.Millisecond)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("Content-Type", "application/x-ndjson")
		req.Header.Set("Content-Encoding", "gzip")
		resp, err := guardedClient(0).Do(req)
		if err != nil {
			last = err
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<22))
		resp.Body.Close()
		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			last = fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(b)))
			continue
		}
		if resp.StatusCode/100 != 2 {
			return nil, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(b)))
		}
		return b, nil
	}
	return nil, last
}

func printImportJob(b []byte, skipped int, out io.Writer) error {
	var j importJob
	if err := json.Unmarshal(b, &j); err != nil {
		return fmt.Errorf("unreadable import answer: %w", err)
	}
	for _, r := range j.Rejected {
		fmt.Fprintf(os.Stderr, "rejected line %d: %s\n", r.Line, r.Problem.Detail)
	}
	fmt.Fprintf(out, "import %s %s: %d accepted, %d rejected, %d skipped\n", j.JobID, j.Status, j.Accepted, j.RejectedCount, skipped)
	if j.Status == "failed" {
		return fmt.Errorf("import failed: %s (re-run is safe: keys are deterministic)", j.Error)
	}
	return nil
}
