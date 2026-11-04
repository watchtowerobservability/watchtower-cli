package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

const activityVerdictUsage = `usage: wtctl activity verify --page verify.json [--page more.json ...] --keys <url|file> --project prj_...
         [--head head.json] [--witness <vkey> ...] [--quorum n] [--rekor-log <vkey> ...] [--rekor-v1-key rekor.pem] [--json]
  Pages are GET /v1/activity/feed/verify responses (oldest first), head is GET /v1/activity/feed/head.
  Prints VALID, VALID_UNANCHORED, VALID_PRUNED or INVALID; exit 1 on INVALID.`

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(s string) error { *l = append(*l, s); return nil }

// wantsVerdict is whether `wtctl activity verify` args ask for the verdict mode.
func wantsVerdict(args []string) bool {
	for _, a := range args {
		if a == "--page" || a == "-page" || strings.HasPrefix(a, "--page=") {
			return true
		}
	}
	return false
}

// fetchDoc reads a URL (GET, optional bearer token) or a file, at most 4 MiB.
func fetchDoc(ctx context.Context, src, token string) ([]byte, error) {
	if !strings.HasPrefix(src, "http://") && !strings.HasPrefix(src, "https://") {
		return os.ReadFile(src)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := guardedClient(0).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("GET %s: %s", src, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

// trustFlags are the pins shared by verify and monitor.
type trustFlags struct {
	witnesses, rekorLogs listFlag
	quorum               int
	rekorV1              string
}

func (f *trustFlags) bind(fs *flag.FlagSet) {
	fs.Var(&f.witnesses, "witness", "witness C2SP vkey (cosignature/v1); repeatable")
	fs.IntVar(&f.quorum, "quorum", 0, "witness cosignatures a head needs")
	fs.Var(&f.rekorLogs, "rekor-log", "Rekor v2 log checkpoint key as a C2SP Ed25519 vkey; repeatable")
	fs.StringVar(&f.rekorV1, "rekor-v1-key", "", "Rekor v1 public key (PEM) to check signed entry timestamps")
}

func (f *trustFlags) trust(keysDoc []byte, project string) (trust, error) {
	t := trust{keysDoc: keysDoc, project: project, quorum: f.quorum,
		witnesses: map[string]ed25519.PublicKey{}, rekorLogs: map[string]ed25519.PublicKey{}}
	for _, w := range f.witnesses {
		name, pk, err := parseVkey(w, noteCosigV1)
		if err != nil {
			return t, err
		}
		t.witnesses[name] = pk
	}
	for _, r := range f.rekorLogs {
		name, pk, err := parseVkey(r, noteEd25519)
		if err != nil {
			return t, err
		}
		t.rekorLogs[name] = pk
	}
	if f.rekorV1 != "" {
		b, err := os.ReadFile(f.rekorV1)
		if err != nil {
			return t, err
		}
		blk, _ := pem.Decode(b)
		if blk == nil {
			return t, errors.New("rekor-v1-key: not PEM")
		}
		k, err := x509.ParsePKIXPublicKey(blk.Bytes)
		ec, ok := k.(*ecdsa.PublicKey)
		if err != nil || !ok {
			return t, errors.New("rekor-v1-key: not an ECDSA public key")
		}
		t.rekorV1 = ec
	}
	return t, nil
}

// readHead accepts a GET /v1/activity/feed/head response ({sth, project}) or a bare tree head.
func readHead(b []byte) (*headDoc, error) {
	var wrap struct {
		Sth *headDoc `json:"sth"`
	}
	if err := json.Unmarshal(b, &wrap); err != nil {
		return nil, err
	}
	if wrap.Sth != nil {
		return wrap.Sth, nil
	}
	var h headDoc
	return &h, json.Unmarshal(b, &h)
}

// activityVerdictMain is `wtctl activity verify --page ...` (G7).
func activityVerdictMain(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("activity verify", flag.ContinueOnError)
	var pages listFlag
	fs.Var(&pages, "page", "verify page (JSON file); repeatable, oldest first")
	keys := fs.String("keys", "", "keys: URL or file (/.well-known/watchtower-activity/<slug>.json or /v1/activity/keys)")
	project := fs.String("project", "", "project id prj_...")
	headFile := fs.String("head", "", "tree head (JSON file)")
	asJSON := fs.Bool("json", false, "print the verdict as JSON")
	var tf trustFlags
	tf.bind(fs)
	if err := fs.Parse(args); err != nil || len(pages) == 0 || *keys == "" || *project == "" {
		return errors.New(activityVerdictUsage)
	}
	keysDoc, err := fetchDoc(ctx, *keys, "")
	if err != nil {
		return fmt.Errorf("keys: %w", err)
	}
	t, err := tf.trust(keysDoc, *project)
	if err != nil {
		return err
	}
	var ps []verifyPage
	for _, f := range pages {
		b, err := os.ReadFile(f)
		var p verifyPage
		if err == nil {
			err = json.Unmarshal(b, &p)
		}
		if err != nil {
			return fmt.Errorf("page %s: %w", f, err)
		}
		ps = append(ps, p)
	}
	var head *headDoc
	if *headFile != "" {
		b, err := os.ReadFile(*headFile)
		if err == nil {
			head, err = readHead(b)
		}
		if err != nil {
			return fmt.Errorf("head: %w", err)
		}
	}
	v := verdictOf(ps, head, t)
	if *asJSON {
		_ = json.NewEncoder(out).Encode(v)
	} else {
		for _, p := range v.Problems {
			fmt.Fprintln(out, "FAIL", p)
		}
		for _, n := range v.Notes {
			fmt.Fprintln(out, "NOTE", n)
		}
		fmt.Fprintln(out, v.Verdict)
	}
	if v.Verdict == verdictInvalid {
		return fmt.Errorf("verification failed: %s", v.Verdict)
	}
	return nil
}
