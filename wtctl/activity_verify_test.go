package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// signedBundle is the fixture as the janitor writes a signed bundle: event lines (from `from`), a
// checkpoint trailer line, then a manifest signed over wt.activity.manifest.v1.
func signedBundle(t *testing.T, from int, edit func(string) string) (string, []byte) {
	t.Helper()
	exp, cp, keys := fixtureExport(t)
	lines := strings.Split(strings.TrimSpace(exp), "\n")
	var body strings.Builder
	for _, l := range lines[from : len(lines)-1] {
		body.WriteString(edit(l) + "\n")
	}
	var v struct{ Checkpoint map[string]any }
	_ = json.Unmarshal(cp, &v)
	v.Checkpoint["account_id"] = "acme"
	line, _ := json.Marshal(map[string]any{"checkpoint": v.Checkpoint})
	body.Write(append(line, '\n'))
	sum := sha256.Sum256([]byte(body.String()))
	n := 3 - from
	msg := fmt.Sprintf(`["wt.activity.manifest.v1","prj_1","acme",%d,%d,3,%q,%q]`, n, from+1, fixtureHashes[2], hex.EncodeToString(sum[:]))
	_, priv, _ := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{7}, 64)))
	m, _ := json.Marshal(map[string]any{"manifest": map[string]any{
		"rows": n, "count": n, "sha256": hex.EncodeToString(sum[:]), "project_id": "prj_1", "account_id": "acme",
		"first_seq": from + 1, "last_seq": 3, "last_hash": fixtureHashes[2], "last_chain_hash": fixtureHashes[2],
		"kid": "k1", "message": msg, "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(msg))),
	}})
	body.Write(append(m, '\n'))
	return body.String(), keys
}

func TestVerifySignedBundle(t *testing.T) {
	exp, keys := signedBundle(t, 0, func(s string) string { return s })
	o := verifyOpts{keysDoc: keys}
	if n, p := verifyExport(strings.NewReader(exp), o); n != 3 || len(p) != 0 {
		t.Fatalf("good bundle: n=%d problems=%v", n, p)
	}
	for name, mut := range map[string]func(string) string{
		"count":      func(s string) string { return strings.Replace(s, `"count":3`, `"count":2`, 1) },
		"message":    func(s string) string { return strings.Replace(s, `\"acme\",3,1,3`, `\"acme\",3,2,3`, 1) },
		"checkpoint": func(s string) string { return strings.Replace(s, `1761782400`, `1761782401`, 1) },
	} {
		if _, p := verifyExport(strings.NewReader(mut(exp)), o); len(p) == 0 {
			t.Errorf("%s: tampering not detected", name)
		}
	}
}

func TestVerifyFirstRowPrevHash(t *testing.T) {
	// the first row (seq 2) states its link, so it is recomputed instead of trusted
	link := func(h string) func(string) string {
		return func(s string) string {
			return strings.Replace(s, `"chain_seq":2,`, fmt.Sprintf(`"chain_seq":2,"prev_hash":%q,`, h), 1)
		}
	}
	good, keys := signedBundle(t, 1, link(fixtureHashes[0]))
	if n, p := verifyExport(strings.NewReader(good), verifyOpts{keysDoc: keys}); n != 2 || len(p) != 0 {
		t.Fatalf("prev_hash row: n=%d %v", n, p)
	}
	bad, _ := signedBundle(t, 1, link(fixtureHashes[1]))
	if _, p := verifyExport(strings.NewReader(bad), verifyOpts{keysDoc: keys}); len(p) != 1 || !strings.Contains(p[0], "hash mismatch") {
		t.Fatalf("wrong prev_hash: %v", p)
	}
}

// v2Doc is an erased body v2 event (actor id and name, first user target id and a metadata path
// committed); v2Canonical is the body crates/wt-store-pg `chain_body` builds for it, by hand.
const v2Doc = `{"id":"e1","account_id":"a","action":"x","occurred_at":"2023-11-14T22:13:20Z","actor":{"id":"erased","name":null,"type":"user"},"target":{"type":"user","id":"erased"},"context":{"ip":null},"metadata":{"ssn":"1","k":2},"commitments":{"actor_id":"aa","actor_name":"bb","targets[0].id":"cc","metadata.ssn":"dd"}}`
const v2Canonical = `{"account_id":"a","action":"x","actor_type":"user","commit":{"actor_id":"aa","actor_name":"bb","metadata.ssn":"dd","targets[0].id":"cc"},"id":"e1","ip":null,"metadata":{"k":2},"occurred_at_micros":1700000000000000,"project_id":"prj_1","seq":1,"target_name":null,"target_type":"user","v":2}`

func TestChainBodyV2(t *testing.T) {
	doc, err := decodeLine([]byte(v2Doc))
	if err != nil {
		t.Fatal(err)
	}
	b, err := chainBody(doc, "prj_1", "1")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := canonicalJSON(b, &out); err != nil || out.String() != v2Canonical {
		t.Fatalf("v2 body:\n got %s\nwant %s", out.String(), v2Canonical)
	}
}

func TestClientKid(t *testing.T) {
	doc := map[string]any{"metadata": map[string]any{"wt.csig": map[string]any{"kid": "line"}},
		"chain_body": map[string]any{"metadata": map[string]any{"wt.csig": map[string]any{"kid": "k1"}}}}
	if got := clientKid(doc); got != "k1" {
		t.Fatalf("chain_body wins: %q", got)
	}
	delete(doc, "chain_body")
	if clientKid(doc) != "line" || clientKid(map[string]any{}) != "" {
		t.Fatal("metadata fallback")
	}
}
