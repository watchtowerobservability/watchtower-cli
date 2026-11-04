package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// C2SP signed notes, checkpoints and cosignatures (G14, B1), prune tombstones (B4) and hourly
// digests (B3) of the activity log. Formats: docs/superpowers/specs/2026-10-31-activity-verification-spec.md.

const (
	noteEd25519   = 0x01
	noteCosigV1   = 0x04
	logOriginBase = "watchtower.dev/activity"
)

// logOrigin is the checkpoint origin (and note key name) of one account's log: every account
// byte outside A-Z a-z 0-9 - . _ ~ percent-encoded, uppercase hex.
func logOrigin(project, account string) string {
	var b strings.Builder
	for _, c := range []byte(account) {
		if ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') || strings.IndexByte("-._~", c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return logOriginBase + "/" + project + "/" + b.String()
}

// noteKeyHash is SHA-256(name || 0x0A || type || key)[:4].
func noteKeyHash(name string, typ byte, pk []byte) []byte {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{0x0a, typ})
	h.Write(pk)
	return h.Sum(nil)[:4]
}

type noteSig struct {
	name string
	sig  []byte
}

// parseNote splits a signed note into its body (with the final newline) and signature lines.
func parseNote(text string) (string, []noteSig, bool) {
	i := strings.Index(text, "\n\n")
	if i < 0 {
		return "", nil, false
	}
	body, rest := text[:i+1], text[i+2:]
	var sigs []noteSig
	for _, l := range strings.Split(strings.TrimSuffix(rest, "\n"), "\n") {
		l, ok := strings.CutPrefix(l, "— ")
		name, b64, ok2 := strings.Cut(l, " ")
		raw, err := base64.StdEncoding.DecodeString(b64)
		if !ok || !ok2 || err != nil || len(raw) < 4 {
			return "", nil, false
		}
		sigs = append(sigs, noteSig{name, raw})
	}
	return body, sigs, len(sigs) > 0
}

// parseCheckpoint reads `<origin>\n<size>\n<b64 root>\n` (extension lines ignored).
func parseCheckpoint(body string) (origin string, size uint64, root []byte, ok bool) {
	l := strings.Split(body, "\n")
	if len(l) < 4 || l[0] == "" {
		return "", 0, nil, false
	}
	size, err := strconv.ParseUint(l[1], 10, 64)
	root, err2 := base64.StdEncoding.DecodeString(l[2])
	return l[0], size, root, err == nil && err2 == nil && len(root) == 32
}

// parseVkey reads a C2SP verifier key `<name>+<hex key hash>+<base64(type || key)>`.
func parseVkey(v string, typ byte) (string, []byte, error) {
	parts := strings.SplitN(v, "+", 3)
	if len(parts) != 3 {
		return "", nil, fmt.Errorf("vkey %q: want <name>+<hash>+<key>", v)
	}
	raw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(raw) != 33 || raw[0] != typ {
		return "", nil, fmt.Errorf("vkey %q: not an Ed25519 key of type %#x", v, typ)
	}
	if hex.EncodeToString(noteKeyHash(parts[0], typ, raw[1:])) != parts[1] {
		return "", nil, fmt.Errorf("vkey %q: key hash does not match", v)
	}
	return parts[0], raw[1:], nil
}

// vkeyOf is the C2SP verifier key of an Ed25519 key.
func vkeyOf(name string, typ byte, pk []byte) string {
	return fmt.Sprintf("%s+%s+%s", name, hex.EncodeToString(noteKeyHash(name, typ, pk)),
		base64.StdEncoding.EncodeToString(append([]byte{typ}, pk...)))
}

// verifyNote reports whether the note carries a valid Ed25519 signature by key name `name`.
func verifyNote(text, name string, pk ed25519.PublicKey) bool {
	body, sigs, ok := parseNote(text)
	if !ok {
		return false
	}
	kh := noteKeyHash(name, noteEd25519, pk)
	for _, s := range sigs {
		if s.name == name && len(s.sig) == 68 && bytes.Equal(s.sig[:4], kh) && ed25519.Verify(pk, []byte(body), s.sig[4:]) {
			return true
		}
	}
	return false
}

// cosignatureLine is `— <name> <base64(key hash || u64be(time) || signature)>`.
func cosignatureLine(name string, pk []byte, t uint64, sig []byte) string {
	b := append(noteKeyHash(name, noteCosigV1, pk), binary.BigEndian.AppendUint64(nil, t)...)
	return "— " + name + " " + base64.StdEncoding.EncodeToString(append(b, sig...))
}

// cosignatureMessage is what a cosignature/v1 signs.
func cosignatureMessage(t uint64, body string) string {
	return fmt.Sprintf("cosignature/v1\ntime %d\n%s", t, body)
}

// verifyCosignature checks witness `name`'s cosignature over `body` among the note's lines;
// it returns the signed time.
func verifyCosignature(body string, sigs []noteSig, name string, pk ed25519.PublicKey) (uint64, bool) {
	kh := noteKeyHash(name, noteCosigV1, pk)
	for _, s := range sigs {
		if s.name != name || len(s.sig) != 76 || !bytes.Equal(s.sig[:4], kh) {
			continue
		}
		t := binary.BigEndian.Uint64(s.sig[4:12])
		if ed25519.Verify(pk, []byte(cosignatureMessage(t, body)), s.sig[12:]) {
			return t, true
		}
	}
	return 0, false
}

// signedBy checks an Ed25519 base64url signature over msg by key kid of the keys document.
func signedBy(keysDoc []byte, kid, msg, sig string) error {
	pub, err := pubKey(keysDoc, kid)
	if err != nil {
		return err
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(sig, "="))
	if err != nil || !ed25519.Verify(pub, []byte(msg), raw) {
		return fmt.Errorf("signature invalid")
	}
	return nil
}

// jsonArray decodes a signed message (a JSON array) keeping numbers exact.
func jsonArray(msg string) ([]any, error) {
	var a []any
	dec := json.NewDecoder(strings.NewReader(msg))
	dec.UseNumber()
	return a, dec.Decode(&a)
}

type tombstoneDoc struct {
	FromSeq      int64  `json:"from_seq"`
	ToSeq        int64  `json:"to_seq"`
	LastHash     string `json:"last_hash"`
	Policy       string `json:"policy"`
	PrunedAtUnix int64  `json:"pruned_at_unix"`
	Kid          string `json:"kid"`
	Message      string `json:"message"`
	Signature    string `json:"signature"`
}

// checkTombstone verifies a signed prune tombstone of (project, account).
func checkTombstone(t tombstoneDoc, keysDoc []byte, project, account string) error {
	want, _ := json.Marshal([]any{"wt.activity.pruned.v1", project, account, t.FromSeq, t.ToSeq, t.LastHash, t.Policy, t.PrunedAtUnix})
	if t.Message != string(want) {
		return fmt.Errorf("tombstone %d..%d: message differs from its fields", t.FromSeq, t.ToSeq)
	}
	if t.FromSeq < 1 || t.ToSeq < t.FromSeq {
		return fmt.Errorf("tombstone %d..%d: bad range", t.FromSeq, t.ToSeq)
	}
	if err := signedBy(keysDoc, t.Kid, t.Message, t.Signature); err != nil {
		return fmt.Errorf("tombstone %d..%d: %w", t.FromSeq, t.ToSeq, err)
	}
	return nil
}

type digestDoc struct {
	Message   string `json:"message"`
	Digest    string `json:"digest"`
	Kid       string `json:"kid"`
	Signature string `json:"signature"`
}

// checkDigests verifies a run of hourly digests: signatures, SHA-256 and the prev links.
func checkDigests(ds []digestDoc, keysDoc []byte, project, account string) []string {
	var p []string
	prev := ""
	for i, d := range ds {
		sum := sha256.Sum256([]byte(d.Message))
		a, err := jsonArray(d.Message)
		switch {
		case err != nil || len(a) != 9 || a[0] != "wt.activity.digest.v1":
			p = append(p, fmt.Sprintf("digest %d: not a wt.activity.digest.v1 array", i))
		case strOf(a[1]) != project || strOf(a[2]) != account:
			p = append(p, fmt.Sprintf("digest %d: for another log", i))
		case hex.EncodeToString(sum[:]) != d.Digest:
			p = append(p, fmt.Sprintf("digest %d: digest is not SHA-256(message)", i))
		case i > 0 && strOf(a[8]) != prev:
			p = append(p, fmt.Sprintf("digest %d: does not link to the digest before", i))
		}
		if err := signedBy(keysDoc, d.Kid, d.Message, d.Signature); err != nil {
			p = append(p, fmt.Sprintf("digest %d: %v", i, err))
		}
		prev = d.Digest
	}
	return p
}
