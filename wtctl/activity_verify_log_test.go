package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/watchtowerobservability/watchtower-cli/internal/repofile"
)

// merkleVectors are testdata/activity_merkle_vectors.json, computed by an independent Python script and shared with
// the Rust (wt-store-pg merkle_log) and TypeScript (verify_log.test.ts) tests.
type merkleVectors struct {
	Data      []string          `json:"data"`
	Roots     map[string]string `json:"roots"`
	Inclusion []struct {
		Index, Size uint64
		Path        []string
	} `json:"inclusion"`
	Consistency []struct {
		From, To uint64
		Proof    []string
	} `json:"consistency"`
}

func loadMerkleVectors(t *testing.T) merkleVectors {
	t.Helper()
	b, err := os.ReadFile(repofile.Path("testdata/activity_merkle_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v merkleVectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func unhexAll(t *testing.T, hs []string) [][]byte {
	t.Helper()
	out := make([][]byte, len(hs))
	for i, h := range hs {
		b, err := hex.DecodeString(h)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = b
	}
	return out
}

func TestMerkleVectors(t *testing.T) {
	v := loadMerkleVectors(t)
	root := func(n uint64) []byte { return unhexAll(t, []string{v.Roots[strconv.FormatUint(n, 10)]})[0] }
	for _, c := range v.Inclusion {
		d, _ := hex.DecodeString(v.Data[c.Index])
		leaf := sha256.Sum256(append([]byte{0}, d...))
		if !verifyInclusion(leaf[:], c.Index, c.Size, unhexAll(t, c.Path), root(c.Size)) {
			t.Errorf("inclusion %d/%d", c.Index, c.Size)
		}
	}
	for _, c := range v.Consistency {
		p := unhexAll(t, c.Proof)
		if !verifyConsistency(c.From, c.To, root(c.From), root(c.To), p) {
			t.Errorf("consistency %d->%d", c.From, c.To)
		}
		if c.From == c.To {
			continue
		}
		if verifyConsistency(c.From, c.To, root(c.To), root(c.From), p) {
			t.Errorf("swapped roots verified %d->%d", c.From, c.To)
		}
		if verifyConsistency(c.From, c.To, root(c.From), root(c.To), append(p, root(1))) {
			t.Errorf("extra node verified %d->%d", c.From, c.To)
		}
	}
}

func TestVerifyConsistencyCommand(t *testing.T) {
	v := loadMerkleVectors(t)
	_, priv, _ := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{9}, 64)))
	keys, _ := json.Marshal(map[string]any{"keys": []map[string]string{{"kid": "k1", "x": base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))}}})
	sth := func(size int64) map[string]any {
		r := v.Roots[strconv.FormatInt(size, 10)]
		msg := fmt.Sprintf(`["wt.activity.merkle.v1","prj_1","a",5,%d,%q]`, 4+size, r)
		return map[string]any{"size": size, "from_seq": 5, "to_seq": 4 + size, "root": r, "kid": "k1", "message": msg,
			"signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(msg)))}
	}
	var proof []string
	for _, c := range v.Consistency {
		if c.From == 7 && c.To == 13 {
			proof = c.Proof
		}
	}
	doc := map[string]any{"from_size": 7, "to_size": 13, "proof": proof, "from_root": v.Roots["7"], "to_root": v.Roots["13"],
		"sth": sth(13), "from_sth": sth(7), "project": "acme"}
	dir := t.TempDir()
	write := func(name string, x any) string {
		b, _ := json.Marshal(x)
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	kf, cf := write("keys.json", json.RawMessage(keys)), write("c.json", doc)
	var out strings.Builder
	if err := activityVerifyMain(context.Background(), []string{"--consistency", cf, "--keys", kf, "--from-root", v.Roots["7"]}, &out); err != nil {
		t.Fatalf("%v: %s", err, out.String())
	}
	if p := checkConsistency(jsonOf(doc), keys, v.Roots["6"]); len(p) != 1 {
		t.Errorf("pinned root: %v", p)
	}
	doc["to_root"] = v.Roots["12"]
	if p := checkConsistency(jsonOf(doc), keys, ""); len(p) == 0 {
		t.Error("a wrong to_root verified")
	}
	doc["to_root"] = v.Roots["13"]
	doc["sth"].(map[string]any)["signature"] = doc["from_sth"].(map[string]any)["signature"]
	if p := checkConsistency(jsonOf(doc), keys, ""); len(p) != 1 || !strings.Contains(p[0], "signature") {
		t.Errorf("bad signature: %v", p)
	}
}

func jsonOf(x any) []byte {
	b, _ := json.Marshal(x)
	return b
}
