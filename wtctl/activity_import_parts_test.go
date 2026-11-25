package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// partServer is the import protocol: lines_seen, offset skipping, 409 ahead of it, final closes.
type partServer struct {
	seen, requests int
	finals         int
	offsets        []int
	failOnce       int // offset whose first part is processed but answered 400
	failed         bool
}

func (p *partServer) handler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		fmt.Fprintf(w, `{"job_id":"j","status":"running","lines_seen":%d}`, p.seen)
		return
	}
	p.requests++
	off, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if r.URL.Query().Get("job_id") == "" {
		http.Error(w, "no job_id", 400)
		return
	}
	if off > p.seen {
		w.WriteHeader(409)
		return
	}
	p.offsets = append(p.offsets, off)
	zr, err := gzip.NewReader(r.Body)
	if err != nil {
		w.WriteHeader(400)
		return
	}
	lines := 0
	for sc := bufio.NewScanner(zr); sc.Scan(); {
		lines++
	}
	p.seen = max(p.seen, off+lines)
	if r.URL.Query().Get("final") == "true" {
		p.finals++
	}
	if off == p.failOnce && !p.failed && p.failOnce > 0 {
		p.failed = true
		w.WriteHeader(400)
		return
	}
	fmt.Fprintf(w, `{"job_id":"j","status":"running","accepted":%d,"rejected_count":0,"rejected":[],"lines_seen":%d}`, p.seen, p.seen)
}

func manyEvents(n int) []map[string]any {
	evs := make([]map[string]any, n)
	for i := range evs {
		evs[i] = map[string]any{"i": i}
	}
	return evs
}

func TestImportPartsResumeAfterAFailedPart(t *testing.T) {
	importSleep = func(time.Duration) {}
	importPartLines = 3
	t.Cleanup(func() { importPartLines = 20_000 })
	ps := &partServer{failOnce: 3}
	srv := httptest.NewServer(http.HandlerFunc(ps.handler))
	defer srv.Close()
	var out bytes.Buffer
	if err := postImportJob(context.Background(), srv.URL+"/v1/projects/p/activity/import", "k", manyEvents(8), 0, &out); err != nil {
		t.Fatal(err, out.String())
	}
	// part 2 (lines 3-5) was processed but answered 400: the client reads lines_seen=6 and continues there
	if fmt.Sprint(ps.offsets) != "[0 3 6]" || ps.finals != 1 || ps.seen != 8 {
		t.Fatalf("offsets %v finals %d seen %d\n%s", ps.offsets, ps.finals, ps.seen, out.String())
	}
	if !strings.Contains(out.String(), "resuming from the server's lines_seen=6") || !strings.Contains(out.String(), "8 of 8 lines sent") ||
		!strings.Contains(out.String(), "8 accepted") {
		t.Fatalf("progress output:\n%s", out.String())
	}
}

func TestImportSmallInputIsOneRequestWithoutAJob(t *testing.T) {
	var requests int
	var query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		query = r.URL.RawQuery
		fmt.Fprint(w, `{"job_id":"j","status":"done","accepted":5,"rejected_count":0,"rejected":[]}`)
	}))
	defer srv.Close()
	var out bytes.Buffer
	if err := postImportJob(context.Background(), srv.URL+"/v1/projects/p/activity/import", "k", manyEvents(5), 0, &out); err != nil {
		t.Fatal(err)
	}
	if requests != 1 || query != "" {
		t.Fatalf("%d requests, query %q", requests, query)
	}
}

func TestImportPartStopsAtTheByteLimit(t *testing.T) {
	importPartBytes = 1 // every event overshoots: one event per part
	t.Cleanup(func() { importPartBytes = 8<<20 - 256<<10 })
	if _, n, err := importPart(manyEvents(10)); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestImportPartsGiveUpAfterRepeatedFailures(t *testing.T) {
	importSleep = func(time.Duration) {}
	importPartLines = 2
	t.Cleanup(func() { importPartLines = 20_000 })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprint(w, `{"lines_seen":0}`)
			return
		}
		w.WriteHeader(400)
	}))
	defer srv.Close()
	var out bytes.Buffer
	if err := postImportJob(context.Background(), srv.URL+"/v1/projects/p/activity/import", "k", manyEvents(6), 0, &out); err == nil {
		t.Fatal("a part that never succeeds must end the import")
	}
}
