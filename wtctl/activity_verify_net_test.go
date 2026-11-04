package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-cli/internal/repofile"
)

// netVectors is testdata/activity_verify_vectors.json, shared with the Rust and TS verifiers.
type netVectors struct {
	Project string          `json:"project"`
	Account string          `json:"account"`
	Keys    json.RawMessage `json:"keys"`
	Witness struct {
		Name string `json:"name"`
		Seed string `json:"seed"`
		Vkey string `json:"vkey"`
	} `json:"witness_key"`
	RekorLog struct {
		Origin string `json:"origin"`
		X      string `json:"x"`
	} `json:"rekor_log"`
	Note struct {
		Origin, Body, Text, Vkey string
		KeyHash                  string `json:"key_hash"`
		CosignedMessage          string `json:"cosigned_message"`
		CosignatureLine          string `json:"cosignature_line"`
	} `json:"note"`
	Origins []struct{ Account, Origin string } `json:"origin_escaping"`
	Digests []digestDoc                        `json:"digests"`
	Tomb    tombstoneDoc                       `json:"tombstone"`
	Verdict []struct {
		Name        string     `json:"name"`
		Expect      string     `json:"expect"`
		FirstBadSeq int64      `json:"first_bad_seq"`
		Page        verifyPage `json:"page"`
		Head        *headDoc   `json:"head"`
	} `json:"verdicts"`
}

func loadNetVectors(t *testing.T) netVectors {
	t.Helper()
	b, err := os.ReadFile(repofile.Path("testdata/activity_verify_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v netVectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func vectorTrust(t *testing.T, v netVectors, quorum int) trust {
	t.Helper()
	wname, wpk, err := parseVkey(v.Witness.Vkey, noteCosigV1)
	if err != nil {
		t.Fatal(err)
	}
	rk, _ := base64.RawURLEncoding.DecodeString(v.RekorLog.X)
	return trust{
		keysDoc: v.Keys, project: v.Project, quorum: quorum,
		witnesses: map[string]ed25519.PublicKey{wname: wpk},
		rekorLogs: map[string]ed25519.PublicKey{v.RekorLog.Origin: rk},
	}
}

func TestNoteVectors(t *testing.T) {
	v := loadNetVectors(t)
	for _, o := range v.Origins {
		if got := logOrigin(v.Project, o.Account); got != o.Origin {
			t.Errorf("origin of %q = %q, want %q", o.Account, got, o.Origin)
		}
	}
	name, pk, err := parseVkey(v.Note.Vkey, noteEd25519)
	if err != nil || name != v.Note.Origin || hex.EncodeToString(noteKeyHash(name, noteEd25519, pk)) != v.Note.KeyHash {
		t.Fatalf("vkey: %v", err)
	}
	if !verifyNote(v.Note.Text, v.Note.Origin, pk) || verifyNote(strings.Replace(v.Note.Text, "\n3\n", "\n4\n", 1), v.Note.Origin, pk) {
		t.Fatal("note signature")
	}
	body, sigs, ok := parseNote(v.Note.Text + v.Note.CosignatureLine + "\n")
	wname, wpk, _ := parseVkey(v.Witness.Vkey, noteCosigV1)
	tm, good := verifyCosignature(body, sigs, wname, wpk)
	if !ok || !good || tm != 1700003700 || cosignatureMessage(tm, body) != v.Note.CosignedMessage {
		t.Fatalf("cosignature: %v %v %d", ok, good, tm)
	}
	seed, _ := hex.DecodeString(v.Witness.Seed)
	priv := ed25519.NewKeyFromSeed(seed)
	line := cosignatureLine(wname, wpk, tm, ed25519.Sign(priv, []byte(cosignatureMessage(tm, body))))
	if line != v.Note.CosignatureLine || vkeyOf(wname, noteCosigV1, wpk) != v.Witness.Vkey {
		t.Fatalf("cosignature line %q", line)
	}
}

func TestDigestAndTombstoneVectors(t *testing.T) {
	v := loadNetVectors(t)
	if p := checkDigests(v.Digests, v.Keys, v.Project, v.Account); len(p) != 0 {
		t.Fatal(p)
	}
	broken := append([]digestDoc{}, v.Digests...)
	broken[0], broken[1] = broken[1], broken[0]
	if p := checkDigests(broken, v.Keys, v.Project, v.Account); len(p) == 0 {
		t.Fatal("reordered digests verified")
	}
	if err := checkTombstone(v.Tomb, v.Keys, v.Project, v.Account); err != nil {
		t.Fatal(err)
	}
	v.Tomb.Policy = "retention:1d"
	if checkTombstone(v.Tomb, v.Keys, v.Project, v.Account) == nil {
		t.Fatal("altered tombstone verified")
	}
}

func TestVerdictVectors(t *testing.T) {
	v := loadNetVectors(t)
	for _, c := range v.Verdict {
		got := verdictOf([]verifyPage{c.Page}, c.Head, vectorTrust(t, v, 1))
		if got.Verdict != c.Expect || got.FirstBadSeq != c.FirstBadSeq {
			t.Errorf("%s: got %s (bad seq %d, %v %v), want %s", c.Name, got.Verdict, got.FirstBadSeq, got.Problems, got.Notes, c.Expect)
		}
	}
	// without the Rekor log key, or short of the witness quorum, the anchored head is unanchored
	for _, c := range v.Verdict {
		if c.Expect != verdictValid {
			continue
		}
		tr := vectorTrust(t, v, 1)
		tr.rekorLogs = nil
		if got := verdictOf([]verifyPage{c.Page}, c.Head, tr); got.Verdict != verdictUnanchored {
			t.Errorf("untrusted rekor log: %s", got.Verdict)
		}
		if got := verdictOf([]verifyPage{c.Page}, c.Head, vectorTrust(t, v, 2)); got.Verdict != verdictUnanchored {
			t.Errorf("quorum 2: %s", got.Verdict)
		}
	}
}

func TestWitnessServer(t *testing.T) {
	v := loadNetVectors(t)
	seed, _ := hex.DecodeString(v.Witness.Seed)
	w := &witnessServer{name: v.Witness.Name, priv: ed25519.NewKeyFromSeed(seed), keysDoc: v.Keys,
		state: t.TempDir() + "/state.json", sizes: map[string]pinnedHead{}}
	now := time.Unix(1700003700, 0)
	status, line := w.add("old 0\n\n"+v.Note.Text, now)
	if status != 200 || strings.TrimSpace(line) != v.Note.CosignatureLine {
		t.Fatalf("add: %d %q", status, line)
	}
	if status, size := w.add("old 0\n\n"+v.Note.Text, now); status != 409 || size != "3\n" {
		t.Fatalf("stale old: %d %q", status, size)
	}
	if status, _ := w.add("old 0\n\n"+strings.Replace(v.Note.Text, "acct_1\n3", "acct_1\n4", 1), now); status != 403 {
		t.Fatalf("forged note: %d", status)
	}
}
