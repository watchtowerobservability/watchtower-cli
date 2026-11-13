package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// `wtctl activity monitor` (B7): a customer-run monitor of one account's log. Each pass it
// fetches the project's pinned keys (.well-known), the newest checkpoint note, checks the note's
// signature and witness cosignatures, proves the new head extends the one it pinned last
// (consistency proof; a smaller or different head at the same size is a rollback or fork),
// checks the head's anchor, and exchanges heads with peer monitors (`--peer`, served with
// `--serve`): two signed heads that are not consistent with each other are a split view.

const activityMonitorUsage = `usage: wtctl activity monitor --api <url> --slug <slug> --account <id> --token <wta_...>
         [--state monitor.json] [--peer <url> ...] [--serve :8099] [--interval 5m]
         [--witness <vkey> ...] [--quorum n] [--rekor-log <vkey> ...]
  Exit 1 on any failure (a single pass when --interval is 0).`

type pinnedHead struct {
	Origin string `json:"origin"`
	Size   uint64 `json:"size"`
	Root   string `json:"root"` // hex
	Note   string `json:"note"`
	At     string `json:"at"`
}

type monitor struct {
	api, slug, account, token, state string
	peers                            []string
	tf                               trustFlags
	mu                               sync.Mutex
	pinned                           *pinnedHead
}

func (m *monitor) get(ctx context.Context, path string, auth bool) ([]byte, error) {
	tok := ""
	if auth {
		tok = m.token
	}
	return fetchDoc(ctx, strings.TrimRight(m.api, "/")+path, tok)
}

func (m *monitor) load() {
	b, err := os.ReadFile(m.state)
	var p pinnedHead
	if err == nil && json.Unmarshal(b, &p) == nil && p.Origin != "" {
		m.pinned = &p
	}
}

func (m *monitor) save(p pinnedHead) error {
	m.mu.Lock()
	m.pinned = &p
	m.mu.Unlock()
	if m.state == "" {
		return nil
	}
	b, _ := json.MarshalIndent(p, "", " ")
	return os.WriteFile(m.state, b, 0o600)
}

// headOf checks a checkpoint note against the project's keys; the head it states.
func headOf(note, origin string, keysDoc []byte) (pinnedHead, error) {
	var kd struct{ Keys []struct{ Kid, X string } }
	_ = json.Unmarshal(keysDoc, &kd)
	signed := false
	for _, k := range kd.Keys {
		pk, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.X, "="))
		if err == nil && len(pk) == ed25519.PublicKeySize && verifyNote(note, origin, pk) {
			signed = true
		}
	}
	body, _, _ := parseNote(note)
	o, size, root, ok := parseCheckpoint(body)
	if !signed || !ok || o != origin {
		return pinnedHead{}, fmt.Errorf("checkpoint note of %s is not signed by the project's keys", origin)
	}
	return pinnedHead{Origin: origin, Size: size, Root: hex.EncodeToString(root), Note: note}, nil
}

// consistent proves the log of head a is a prefix of head b with the API's consistency proof.
func (m *monitor) consistent(ctx context.Context, keysDoc []byte, a, b pinnedHead) error {
	if a.Size > b.Size {
		a, b = b, a
	}
	if a.Size == b.Size {
		if a.Root != b.Root {
			return fmt.Errorf("two heads of size %d with different roots (fork)", a.Size)
		}
		return nil
	}
	if a.Size == 0 {
		return nil
	}
	doc, err := m.get(ctx, fmt.Sprintf("/v1/activity/feed/consistency?from_size=%d&to_size=%d", a.Size, b.Size), true)
	if err != nil {
		return err
	}
	if p := checkConsistency(doc, keysDoc, a.Root); len(p) > 0 {
		return errors.New(strings.Join(p, "; "))
	}
	var c consistencyDoc
	_ = json.Unmarshal(doc, &c)
	if !strings.EqualFold(c.ToRoot, b.Root) {
		return fmt.Errorf("consistency proof ends at root %s, not the head's %s", c.ToRoot, b.Root)
	}
	return nil
}

// pass runs one round; the problems found.
func (m *monitor) pass(ctx context.Context, out io.Writer) []string {
	var problems []string
	fail := func(f string, a ...any) { problems = append(problems, fmt.Sprintf(f, a...)) }
	wk, err := m.get(ctx, "/.well-known/watchtower-activity/"+url.PathEscape(m.slug)+".json", false)
	var meta struct {
		ProjectID string `json:"project_id"`
	}
	if err != nil || json.Unmarshal(wk, &meta) != nil || meta.ProjectID == "" {
		return []string{fmt.Sprintf("well-known keys: %v", err)}
	}
	origin := logOrigin(meta.ProjectID, m.account)
	note, err := m.get(ctx, "/v1/activity/tlog/"+url.PathEscape(m.slug)+"/"+url.PathEscape(m.account)+"/checkpoint", true)
	if err != nil {
		return []string{"checkpoint: " + err.Error()}
	}
	cur, err := headOf(string(note), origin, wk)
	if err != nil {
		return []string{err.Error()}
	}
	cur.At = time.Now().UTC().Format(time.RFC3339)
	t, err := m.tf.trust(wk, meta.ProjectID)
	if err != nil {
		return []string{err.Error()}
	}
	body, sigs, _ := parseNote(cur.Note)
	cosigned := 0
	for name, pk := range t.witnesses {
		if _, ok := verifyCosignature(body, sigs, name, pk); ok {
			cosigned++
		}
	}
	if cosigned < t.quorum {
		fail("head %d: %d of %d witness cosignatures", cur.Size, cosigned, t.quorum)
	}
	m.mu.Lock()
	old := m.pinned
	m.mu.Unlock()
	if old != nil && old.Origin == origin {
		if cur.Size < old.Size {
			fail("rollback: the log shows size %d, %d was pinned", cur.Size, old.Size)
		} else if err := m.consistent(ctx, wk, *old, cur); err != nil {
			fail("pinned head %d -> %d: %v", old.Size, cur.Size, err)
		}
	}
	if hb, err := m.get(ctx, "/v1/activity/feed/head", true); err == nil {
		if h, err := readHead(hb); err == nil {
			ok, notes, ap := checkAnchor(h, t)
			for _, n := range append(ap, notes...) {
				fmt.Fprintln(out, "NOTE", n)
			}
			if len(ap) > 0 {
				fail("head %d: anchor does not verify", h.Size)
			} else if ok {
				fmt.Fprintf(out, "OK anchored head %d\n", h.Size)
			}
		}
	}
	for _, peer := range m.peers {
		for _, p := range m.peerHeads(ctx, peer, origin, wk) {
			if err := m.consistent(ctx, wk, p, cur); err != nil {
				fail("SPLIT VIEW with peer %s: %v", peer, err)
			}
		}
	}
	if len(problems) == 0 {
		if err := m.save(cur); err != nil {
			fail("state: %v", err)
		}
		fmt.Fprintf(out, "OK %s size %d root %s (%d cosignatures)\n", origin, cur.Size, cur.Root, cosigned)
	}
	return problems
}

// peerHeads fetches a peer monitor's heads of `origin` (GET <peer>/heads), keeping only
// heads signed by the project.
func (m *monitor) peerHeads(ctx context.Context, peer, origin string, keysDoc []byte) []pinnedHead {
	b, err := fetchDoc(ctx, strings.TrimRight(peer, "/")+"/heads", "")
	var hs []pinnedHead
	if err != nil || json.Unmarshal(b, &hs) != nil {
		return nil
	}
	var out []pinnedHead
	for _, h := range hs {
		if h.Origin != origin {
			continue
		}
		if v, err := headOf(h.Note, origin, keysDoc); err == nil {
			out = append(out, v)
		}
	}
	return out
}

func (m *monitor) serveHeads(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	hs := []pinnedHead{}
	if m.pinned != nil {
		hs = append(hs, *m.pinned)
	}
	m.mu.Unlock()
	var b bytes.Buffer
	_ = json.NewEncoder(&b).Encode(hs)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b.Bytes())
}

// activityMonitorMain is `wtctl activity monitor`.
func activityMonitorMain(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("activity monitor", flag.ContinueOnError)
	m := &monitor{}
	fs.StringVar(&m.api, "api", apiEnv(), "API base URL")
	fs.StringVar(&m.slug, "slug", "", "hosted-page slug of the project")
	fs.StringVar(&m.account, "account", "", "account id")
	fs.StringVar(&m.token, "token", os.Getenv("WT_ACTIVITY_TOKEN"), "account token wta_... with capability verify")
	fs.StringVar(&m.state, "state", "", "file pinning the last head (created)")
	var peers listFlag
	fs.Var(&peers, "peer", "peer monitor URL; repeatable")
	serve := fs.String("serve", "", "serve this monitor's heads at <addr>/heads for peers")
	interval := fs.Duration("interval", 0, "repeat every interval (0: one pass)")
	m.tf.bind(fs)
	if err := fs.Parse(args); err != nil || m.api == "" || m.slug == "" || m.account == "" || m.token == "" {
		return errors.New(activityMonitorUsage)
	}
	m.peers = peers
	m.load()
	if *serve != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /heads", m.serveHeads)
		srv := &http.Server{Addr: *serve, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		go func() { _ = srv.ListenAndServe() }()
		defer srv.Close()
	}
	for {
		problems := m.pass(ctx, out)
		for _, p := range problems {
			fmt.Fprintln(out, "FAIL", p)
		}
		if *interval == 0 {
			if len(problems) > 0 {
				return fmt.Errorf("monitor: %d problem(s)", len(problems))
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(*interval):
		}
	}
}
