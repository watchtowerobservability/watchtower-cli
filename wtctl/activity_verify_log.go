package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Consistency of an account's append-only Merkle log (`wtctl activity verify --consistency`).
// Input: the JSON of GET /v1/activity/feed/consistency?from_size=&to_size= ({from_size, to_size,
// proof[] (hex), from_root, to_root, sth, from_sth}). Each signed tree head (STH) is {size,
// from_seq, to_seq, root (hex), kid, message, signature}: `message` is the UTF-8 JSON array
// ["wt.activity.merkle.v1", project, account, from_seq, to_seq, root], Ed25519 (base64url) by key
// `kid`, and size = to_seq - from_seq + 1 (the tree of the chain hashes of those seqs, leaf =
// SHA-256(0x00 || chain hash), node = SHA-256(0x01 || left || right), RFC 9162 section 2.1).
// Checked: both heads' shape, the same log (from_seq), the stated roots, the RFC 9162 2.1.4.2
// consistency proof, both signatures with --keys, and with --from-root the root you pinned.

type sthDoc struct {
	Size      int64  `json:"size"`
	FromSeq   int64  `json:"from_seq"`
	ToSeq     int64  `json:"to_seq"`
	Root      string `json:"root"`
	Kid       string `json:"kid"`
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

type consistencyDoc struct {
	FromSize int64    `json:"from_size"`
	ToSize   int64    `json:"to_size"`
	Proof    []string `json:"proof"`
	FromRoot string   `json:"from_root"`
	ToRoot   string   `json:"to_root"`
	Sth      sthDoc   `json:"sth"`
	FromSth  sthDoc   `json:"from_sth"`
}

func merkleNode(l, r []byte) []byte {
	h := sha256.New()
	h.Write([]byte{1})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

// verifyConsistency is RFC 9162 2.1.4.2: proof shows tree (m, oldRoot) is a prefix of (n, newRoot).
func verifyConsistency(m, n uint64, oldRoot, newRoot []byte, proof [][]byte) bool {
	if m == 0 || m > n {
		return false
	}
	if m == n {
		return len(proof) == 0 && bytes.Equal(oldRoot, newRoot)
	}
	if m&(m-1) == 0 {
		proof = append([][]byte{oldRoot}, proof...)
	}
	if len(proof) == 0 {
		return false
	}
	fn, sn := m-1, n-1
	for fn&1 == 1 {
		fn, sn = fn>>1, sn>>1
	}
	fr, sr := proof[0], proof[0]
	for _, c := range proof[1:] {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			fr, sr = merkleNode(c, fr), merkleNode(c, sr)
			for fn&1 == 0 && fn != 0 {
				fn, sn = fn>>1, sn>>1
			}
		} else {
			sr = merkleNode(sr, c)
		}
		fn, sn = fn>>1, sn>>1
	}
	return sn == 0 && bytes.Equal(fr, oldRoot) && bytes.Equal(sr, newRoot)
}

// verifyInclusion is RFC 9162 2.1.3.2 for an already leaf-hashed leaf.
func verifyInclusion(leaf []byte, index, size uint64, path [][]byte, root []byte) bool {
	if index >= size {
		return false
	}
	fn, sn, r := index, size-1, leaf
	for _, p := range path {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			r = merkleNode(p, r)
			for fn&1 == 0 && fn != 0 {
				fn, sn = fn>>1, sn>>1
			}
		} else {
			r = merkleNode(r, p)
		}
		fn, sn = fn>>1, sn>>1
	}
	return sn == 0 && bytes.Equal(r, root)
}

// checkSth checks a tree head's message shape and, with keys, its signature.
func checkSth(name string, s sthDoc, keysDoc []byte) []string {
	var m []any
	dec := json.NewDecoder(strings.NewReader(s.Message))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil || len(m) != 6 || m[0] != "wt.activity.merkle.v1" {
		return []string{name + ": message is not a wt.activity.merkle.v1 array"}
	}
	if num(m[3]) != s.FromSeq || num(m[4]) != s.ToSeq || strOf(m[5]) != s.Root || s.Size != s.ToSeq-s.FromSeq+1 {
		return []string{name + ": message differs from the head's fields (seqs, root or size)"}
	}
	if keysDoc == nil {
		return nil
	}
	pub, err := pubKey(keysDoc, s.Kid)
	if err != nil {
		return []string{name + ": " + err.Error()}
	}
	sig, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s.Signature, "="))
	if err != nil || !ed25519.Verify(pub, []byte(s.Message), sig) {
		return []string{name + ": signature invalid"}
	}
	return nil
}

// checkConsistency verifies a consistency response; pinned is the hex root you saw at from_size ("" = none).
func checkConsistency(doc, keysDoc []byte, pinned string) []string {
	var c consistencyDoc
	if err := json.Unmarshal(doc, &c); err != nil {
		return []string{"consistency: " + err.Error()}
	}
	p := append(checkSth("sth", c.Sth, keysDoc), checkSth("from_sth", c.FromSth, keysDoc)...)
	if c.Sth.FromSeq != c.FromSth.FromSeq || c.Sth.Size != c.ToSize || c.FromSth.Size != c.FromSize ||
		c.Sth.Root != c.ToRoot || c.FromSth.Root != c.FromRoot {
		p = append(p, "tree heads differ from the stated sizes, roots or log")
	}
	if pinned != "" && !strings.EqualFold(pinned, c.FromRoot) {
		p = append(p, fmt.Sprintf("from_root %s is not the pinned root %s", c.FromRoot, pinned))
	}
	proof := make([][]byte, 0, len(c.Proof))
	for _, h := range c.Proof {
		b, err := hex.DecodeString(h)
		if err != nil {
			return append(p, "proof node is not hex")
		}
		proof = append(proof, b)
	}
	oldRoot, err1 := hex.DecodeString(c.FromRoot)
	newRoot, err2 := hex.DecodeString(c.ToRoot)
	if err1 != nil || err2 != nil || c.FromSize < 1 ||
		!verifyConsistency(uint64(c.FromSize), uint64(c.ToSize), oldRoot, newRoot, proof) {
		p = append(p, fmt.Sprintf("consistency proof %d -> %d does not verify", c.FromSize, c.ToSize))
	}
	return p
}

func reportConsistency(out io.Writer, problems []string, signed bool) error {
	for _, p := range problems {
		fmt.Fprintln(out, "FAIL", p)
	}
	if len(problems) > 0 {
		return fmt.Errorf("consistency check failed: %d problem(s)", len(problems))
	}
	what := "signatures not checked: pass --keys"
	if signed {
		what = "both tree heads signed"
	}
	fmt.Fprintf(out, "OK: the newer tree head extends the older one (%s)\n", what)
	return nil
}
