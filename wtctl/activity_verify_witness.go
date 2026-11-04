package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// `wtctl activity witness` (B1): a customer-run C2SP tlog-witness for Watchtower activity logs.
// `keygen` writes a key file; `serve` answers POST /add-checkpoint: it checks the log's
// signature (keys from `--log <origin>=<vkey>` pins or the project's .well-known document),
// the consistency proof from the size it cosigned last (kept in --state), and answers its
// cosignature/v1 line. Add it to a project with POST /v1/projects/{prj}/activity/witnesses.

const activityWitnessUsage = `usage: wtctl activity witness keygen --name <witness name> --key witness.key
       wtctl activity witness serve --key witness.key --state witness-state.json --keys <url|file> [--addr :8098]`

type witnessKey struct {
	Name string `json:"name"`
	Seed string `json:"seed"` // base64
}

type witnessServer struct {
	name    string
	priv    ed25519.PrivateKey
	keysDoc []byte
	state   string
	mu      sync.Mutex
	sizes   map[string]pinnedHead
}

// add handles one add-checkpoint body; HTTP status and response body.
func (w *witnessServer) add(body string, now time.Time) (int, string) {
	head, note, ok := strings.Cut(body, "\n\n")
	lines := strings.Split(head, "\n")
	old, err := strconv.ParseUint(strings.TrimPrefix(lines[0], "old "), 10, 64)
	if !ok || err != nil || !strings.HasPrefix(lines[0], "old ") {
		return http.StatusBadRequest, "bad request\n"
	}
	var proof [][]byte
	for _, l := range lines[1:] {
		b, err := base64.StdEncoding.DecodeString(l)
		if err != nil {
			return http.StatusBadRequest, "bad proof line\n"
		}
		proof = append(proof, b)
	}
	cp, _, okn := parseNote(note)
	origin, size, root, okc := parseCheckpoint(cp)
	if !okn || !okc || !strings.HasPrefix(origin, logOriginBase+"/") {
		return http.StatusNotFound, "unknown log\n"
	}
	h, err := headOf(note, origin, w.keysDoc)
	if err != nil {
		return http.StatusForbidden, err.Error() + "\n"
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	cur := w.sizes[origin]
	if old != cur.Size {
		return http.StatusConflict, fmt.Sprintf("%d\n", cur.Size)
	}
	curRoot, _ := hex.DecodeString(cur.Root)
	good := old <= size && ((old == 0 && len(proof) == 0) ||
		(old == size && len(proof) == 0 && h.Root == cur.Root) ||
		(old > 0 && old < size && verifyConsistency(old, size, curRoot, root, proof)))
	if !good {
		return http.StatusUnprocessableEntity, "consistency proof does not verify\n"
	}
	w.sizes[origin] = h
	if err := w.save(); err != nil {
		return http.StatusInternalServerError, "state not saved\n"
	}
	t := uint64(now.Unix())
	sig := ed25519.Sign(w.priv, []byte(cosignatureMessage(t, cp)))
	return http.StatusOK, cosignatureLine(w.name, w.priv.Public().(ed25519.PublicKey), t, sig) + "\n"
}

func (w *witnessServer) save() error {
	b, _ := json.MarshalIndent(w.sizes, "", " ")
	tmp := w.state + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, w.state)
}

func (w *witnessServer) handle(rw http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(rw, "bad body", http.StatusBadRequest)
		return
	}
	status, text := w.add(string(b), time.Now())
	ct := "text/plain; charset=utf-8"
	if status == http.StatusConflict {
		ct = "text/x.tlog.size"
	}
	rw.Header().Set("Content-Type", ct)
	rw.WriteHeader(status)
	_, _ = io.WriteString(rw, text)
}

// activityWitnessMain is `wtctl activity witness`.
func activityWitnessMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(activityWitnessUsage)
	}
	fs := flag.NewFlagSet("activity witness", flag.ContinueOnError)
	name := fs.String("name", "", "witness name (keygen), e.g. witness.example.com/w1")
	keyFile := fs.String("key", "", "key file")
	state := fs.String("state", "", "state file: last cosigned size per log (serve)")
	keys := fs.String("keys", "", "the project's .well-known document or keys: URL or file (serve)")
	addr := fs.String("addr", ":8098", "listen address (serve)")
	if err := fs.Parse(args[1:]); err != nil || *keyFile == "" {
		return errors.New(activityWitnessUsage)
	}
	switch args[0] {
	case "keygen":
		if *name == "" {
			return errors.New(activityWitnessUsage)
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		b, _ := json.Marshal(witnessKey{Name: *name, Seed: base64.StdEncoding.EncodeToString(priv.Seed())})
		if err := os.WriteFile(*keyFile, b, 0o600); err != nil {
			return err
		}
		fmt.Fprintln(out, vkeyOf(*name, noteCosigV1, pub))
		return nil
	case "serve":
		if *state == "" || *keys == "" {
			return errors.New(activityWitnessUsage)
		}
		var k witnessKey
		b, err := os.ReadFile(*keyFile)
		if err == nil {
			err = json.Unmarshal(b, &k)
		}
		seed, err2 := base64.StdEncoding.DecodeString(k.Seed)
		if err != nil || err2 != nil || len(seed) != ed25519.SeedSize {
			return fmt.Errorf("key file %s: not a witness key", *keyFile)
		}
		keysDoc, err := fetchDoc(ctx, *keys, "")
		if err != nil {
			return err
		}
		w := &witnessServer{name: k.Name, priv: ed25519.NewKeyFromSeed(seed), keysDoc: keysDoc, state: *state, sizes: map[string]pinnedHead{}}
		if b, err := os.ReadFile(*state); err == nil {
			_ = json.Unmarshal(b, &w.sizes)
		}
		fmt.Fprintln(out, "witness", vkeyOf(k.Name, noteCosigV1, w.priv.Public().(ed25519.PublicKey)), "on", *addr)
		mux := http.NewServeMux()
		mux.HandleFunc("POST /add-checkpoint", w.handle)
		srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		go func() { <-ctx.Done(); _ = srv.Close() }()
		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
	return errors.New(activityWitnessUsage)
}
