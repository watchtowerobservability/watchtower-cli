package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// The three-state verdict (G7, B4) over GET /v1/activity/feed/verify pages and, optionally, the
// account's tree head (GET /v1/activity/feed/head) with its anchor receipts and cosignatures.
// INVALID beats VALID_PRUNED beats VALID / VALID_UNANCHORED (spec, "Verdicts").

const (
	verdictValid      = "VALID"
	verdictUnanchored = "VALID_UNANCHORED"
	verdictPruned     = "VALID_PRUNED"
	verdictInvalid    = "INVALID"
)

type pageRow struct {
	ID       string `json:"id"`
	Seq      int64  `json:"seq"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
	Body     string `json:"body"`
}

type verifyPage struct {
	Data       []pageRow       `json:"data"`
	HeadSeq    int64           `json:"head_seq"`
	AnchorSeq  *int64          `json:"anchor_seq"`
	Checkpoint json.RawMessage `json:"checkpoint"`
	Erased     []struct {
		FromSeq int64 `json:"from_seq"`
		ToSeq   int64 `json:"to_seq"`
	} `json:"erased"`
	Pruned []tombstoneDoc `json:"pruned"`
}

type cosigDoc struct {
	Witness string `json:"witness"`
	Time    int64  `json:"time"`
	Line    string `json:"line"`
}

type headDoc struct {
	sthDoc
	Note         string          `json:"note"`
	Cosignatures []cosigDoc      `json:"cosignatures"`
	Anchor       json.RawMessage `json:"anchor"`
}

// trust is what the verifier pins: the project's keys and id, witnesses and transparency logs.
type trust struct {
	keysDoc   []byte
	project   string
	witnesses map[string]ed25519.PublicKey
	quorum    int
	rekorLogs map[string]ed25519.PublicKey // Rekor v2 checkpoint origin -> key
	rekorV1   *ecdsa.PublicKey
}

type verdict struct {
	Verdict     string   `json:"verdict"`
	FirstBadSeq int64    `json:"first_bad_seq,omitempty"`
	Problems    []string `json:"problems"`
	Notes       []string `json:"notes"`
}

func leafHash(b []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(b)
	return h.Sum(nil)
}

// merkleRoot is the RFC 9162 tree hash of already leaf-hashed leaves.
func merkleRoot(leaves [][]byte) []byte {
	switch len(leaves) {
	case 0:
		s := sha256.Sum256(nil)
		return s[:]
	case 1:
		return leaves[0]
	}
	k := 1
	for k*2 < len(leaves) {
		k *= 2
	}
	return merkleNode(merkleRoot(leaves[:k]), merkleRoot(leaves[k:]))
}

// checkRows checks hashes and links of consecutive rows; the seq of the first bad one.
func checkRows(rows []pageRow, project string) (string, int64) {
	var prev *pageRow
	for i := range rows {
		r := &rows[i]
		ph, err1 := hex.DecodeString(r.PrevHash)
		var body struct {
			Seq     int64  `json:"seq"`
			Project string `json:"project_id"`
		}
		err2 := json.Unmarshal([]byte(r.Body), &body)
		sum := sha256.Sum256(append(ph, r.Body...))
		switch {
		case err1 != nil || err2 != nil:
			return fmt.Sprintf("seq %d: unreadable row", r.Seq), r.Seq
		case hex.EncodeToString(sum[:]) != r.Hash:
			return fmt.Sprintf("seq %d: hash does not match SHA-256(prev_hash || body)", r.Seq), r.Seq
		case body.Seq != r.Seq || (project != "" && body.Project != project):
			return fmt.Sprintf("seq %d: body names another seq or project", r.Seq), r.Seq
		case prev != nil && (r.Seq != prev.Seq+1 || r.PrevHash != prev.Hash):
			return fmt.Sprintf("seq %d: does not link to seq %d", r.Seq, prev.Seq), r.Seq
		case prev == nil && r.Seq == 1 && r.PrevHash != "":
			return "seq 1: has a prev_hash", 1
		}
		prev = r
	}
	return "", 0
}

// checkGap explains rows before the first one: signed tombstones (pruned) or erasure re-anchors.
func checkGap(first pageRow, pages []verifyPage, account string, t trust) (problem string, note string) {
	if first.Seq == 1 {
		return "", ""
	}
	var ts []tombstoneDoc
	for _, p := range pages {
		ts = append(ts, p.Pruned...)
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i].FromSeq < ts[j].FromSeq })
	next := int64(1)
	for _, x := range ts {
		if err := checkTombstone(x, t.keysDoc, t.project, account); err != nil {
			return err.Error(), ""
		}
		if x.FromSeq > next {
			break
		}
		next = max(next, x.ToSeq+1)
		if x.ToSeq == first.Seq-1 && x.LastHash != first.PrevHash {
			return fmt.Sprintf("tombstone ..%d: last_hash is not seq %d's prev_hash", x.ToSeq, first.Seq), ""
		}
	}
	if next >= first.Seq {
		return "", fmt.Sprintf("seqs 1..%d pruned under signed tombstones", first.Seq-1)
	}
	for _, p := range pages {
		for _, e := range p.Erased {
			if e.FromSeq <= next && e.ToSeq >= first.Seq-1 {
				return "", fmt.Sprintf("seqs %d..%d re-anchored by an erasure (unsigned)", next, first.Seq-1)
			}
		}
	}
	return fmt.Sprintf("seqs %d..%d are missing and no tombstone explains them", next, first.Seq-1), ""
}

// verdictOf runs every check over the pages (oldest first) and the optional head.
func verdictOf(pages []verifyPage, head *headDoc, t trust) verdict {
	v := verdict{Problems: []string{}, Notes: []string{}}
	var rows []pageRow
	for _, p := range pages {
		rows = append(rows, p.Data...)
	}
	if len(rows) == 0 {
		v.Verdict, v.Notes = verdictUnanchored, append(v.Notes, "no rows")
		return v
	}
	var acct struct {
		Account string `json:"account_id"`
	}
	_ = json.Unmarshal([]byte(rows[0].Body), &acct)
	if p, seq := checkRows(rows, t.project); p != "" {
		v.Verdict, v.FirstBadSeq, v.Problems = verdictInvalid, seq, append(v.Problems, p)
		return v
	}
	gapProblem, gapNote := checkGap(rows[0], pages, acct.Account, t)
	if gapProblem != "" {
		v.Problems = append(v.Problems, gapProblem)
	}
	hashes := map[int64][]byte{}
	for _, r := range rows {
		hashes[r.Seq], _ = hex.DecodeString(r.Hash)
	}
	for _, p := range pages {
		if len(p.Checkpoint) == 0 || string(p.Checkpoint) == "null" || t.keysDoc == nil {
			continue
		}
		var cp map[string]any
		dec := json.NewDecoder(bytes.NewReader(p.Checkpoint))
		dec.UseNumber()
		if dec.Decode(&cp) == nil {
			v.Problems = append(v.Problems, checkCheckpoint(cp, t.keysDoc, t.project, map[string]map[int64][]byte{acct.Account: hashes})...)
		}
	}
	anchored := false
	if head != nil {
		hp, hn, ok := checkHead(head, hashes, acct.Account, t)
		v.Problems, v.Notes, anchored = append(v.Problems, hp...), append(v.Notes, hn...), ok
	}
	switch {
	case len(v.Problems) > 0:
		v.Verdict = verdictInvalid
	case gapNote != "":
		v.Verdict, v.Notes = verdictPruned, append(v.Notes, gapNote)
	case anchored:
		v.Verdict = verdictValid
	default:
		v.Verdict = verdictUnanchored
	}
	return v
}

// checkHead checks the tree head against the rows, its note, cosignatures and anchor; ok when
// it is anchored by a receipt this tool verified and its witness quorum is met.
func checkHead(h *headDoc, hashes map[int64][]byte, account string, t trust) (problems, notes []string, ok bool) {
	problems = checkSth("head", h.sthDoc, t.keysDoc)
	leaves := make([][]byte, 0, h.Size)
	for s := h.FromSeq; s <= h.ToSeq; s++ {
		c, have := hashes[s]
		if !have {
			return problems, append(notes, fmt.Sprintf("head covers seq %d, which is not among the rows: root not recomputed", s)), false
		}
		leaves = append(leaves, leafHash(c))
	}
	if hex.EncodeToString(merkleRoot(leaves)) != h.Root {
		return append(problems, "head: root is not the Merkle root of the rows"), notes, false
	}
	origin := logOrigin(t.project, account)
	if h.Note != "" && t.keysDoc != nil {
		pub, err := pubKey(t.keysDoc, h.Kid)
		body, _, _ := parseNote(h.Note)
		_, size, root, cok := parseCheckpoint(body)
		if err != nil || !verifyNote(h.Note, origin, pub) || !cok || int64(size) != h.Size || hex.EncodeToString(root) != h.Root {
			problems = append(problems, "head: checkpoint note is not signed for this head")
		}
	}
	cosigned := 0
	text := h.Note
	for _, c := range h.Cosignatures {
		if !strings.Contains(text, c.Line) {
			text += c.Line + "\n"
		}
	}
	if body, sigs, okn := parseNote(text); okn {
		for name, pk := range t.witnesses {
			if _, good := verifyCosignature(body, sigs, name, pk); good {
				cosigned++
			}
		}
	}
	if cosigned < t.quorum {
		notes = append(notes, fmt.Sprintf("head: %d of %d required witness cosignatures", cosigned, t.quorum))
	}
	an, anNotes, anProblems := checkAnchor(h, t)
	notes, problems = append(notes, anNotes...), append(problems, anProblems...)
	return problems, notes, an && cosigned >= t.quorum
}

type anchorDoc struct {
	Top      string            `json:"top"`
	Index    uint64            `json:"index"`
	Size     uint64            `json:"size"`
	Path     []string          `json:"path"`
	Receipts []json.RawMessage `json:"receipts"`
}

func checkAnchor(h *headDoc, t trust) (bool, []string, []string) {
	if len(h.Anchor) == 0 || string(h.Anchor) == "null" {
		return false, []string{"head is not anchored yet"}, nil
	}
	var a anchorDoc
	if err := json.Unmarshal(h.Anchor, &a); err != nil {
		return false, nil, []string{"anchor: unreadable"}
	}
	root, _ := hex.DecodeString(h.Root)
	top, err := hex.DecodeString(a.Top)
	path := make([][]byte, 0, len(a.Path))
	for _, p := range a.Path {
		b, _ := hex.DecodeString(p)
		path = append(path, b)
	}
	if err != nil || !verifyInclusion(leafHash(root), a.Index, a.Size, path, top) {
		return false, nil, []string{"anchor: the head is not included in the anchored hash"}
	}
	var notes []string
	ok := false
	for _, raw := range a.Receipts {
		var r struct {
			Kind    string            `json:"kind"`
			Version int               `json:"version"`
			Entries []json.RawMessage `json:"entries"`
		}
		_ = json.Unmarshal(raw, &r)
		if r.Kind != "rekor" {
			notes = append(notes, fmt.Sprintf("anchor: %s receipt not checked by wtctl", r.Kind))
			continue
		}
		for _, e := range r.Entries {
			var err error
			if r.Version == 2 {
				err = checkRekorV2(e, top, t)
			} else {
				err = checkRekorV1(e, top, t)
			}
			if err != nil {
				notes = append(notes, "anchor: rekor: "+err.Error())
			} else {
				ok = true
			}
		}
	}
	return ok, notes, nil
}

func rekorStatement(top []byte) string {
	b, _ := json.Marshal([]any{"wt.activity.rekor.v1", hex.EncodeToString(top)})
	return string(b)
}

var ed25519SPKI = []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}

// checkRekorV2 checks a Rekor v2 hashedrekord entry: our Ed25519ph signature over SHA-512 of the
// statement, its inclusion in the log and the log's signed checkpoint.
func checkRekorV2(raw json.RawMessage, top []byte, t trust) error {
	var e struct {
		Kid       string `json:"kid"`
		Statement string `json:"statement"`
		Body      string `json:"canonicalized_body"`
		Proof     struct {
			LogIndex   uint64   `json:"log_index"`
			TreeSize   uint64   `json:"tree_size"`
			RootHash   string   `json:"root_hash"`
			Hashes     []string `json:"hashes"`
			Checkpoint struct {
				Envelope string `json:"envelope"`
			} `json:"checkpoint"`
		} `json:"inclusion_proof"`
	}
	if err := json.Unmarshal(raw, &e); err != nil || e.Statement != rekorStatement(top) {
		return fmt.Errorf("entry is not for this anchor")
	}
	body, err := base64.StdEncoding.DecodeString(e.Body)
	var b struct {
		Spec struct {
			H struct {
				Data struct{ Digest string } `json:"data"`
				Sig  struct {
					Content  string `json:"content"`
					Verifier struct {
						PublicKey struct {
							RawBytes string `json:"rawBytes"`
						} `json:"publicKey"`
					} `json:"verifier"`
				} `json:"signature"`
			} `json:"hashedRekordV002"`
		} `json:"spec"`
	}
	if err != nil || json.Unmarshal(body, &b) != nil {
		return fmt.Errorf("unreadable canonicalized_body")
	}
	dig := sha512.Sum512([]byte(e.Statement))
	spki, _ := base64.StdEncoding.DecodeString(b.Spec.H.Sig.Verifier.PublicKey.RawBytes)
	sig, _ := base64.StdEncoding.DecodeString(b.Spec.H.Sig.Content)
	pub, err := pubKey(t.keysDoc, e.Kid)
	if err != nil || base64.StdEncoding.EncodeToString(dig[:]) != b.Spec.H.Data.Digest ||
		!bytes.Equal(spki, append(append([]byte{}, ed25519SPKI...), pub...)) ||
		ed25519.VerifyWithOptions(pub, dig[:], sig, &ed25519.Options{Hash: crypto.SHA512}) != nil {
		return fmt.Errorf("entry is not signed by the project's key over this anchor")
	}
	root, _ := base64.StdEncoding.DecodeString(e.Proof.RootHash)
	var path [][]byte
	for _, h := range e.Proof.Hashes {
		x, _ := base64.StdEncoding.DecodeString(h)
		path = append(path, x)
	}
	if !verifyInclusion(leafHash(body), e.Proof.LogIndex, e.Proof.TreeSize, path, root) {
		return fmt.Errorf("inclusion proof does not verify")
	}
	cb, _, _ := parseNote(e.Proof.Checkpoint.Envelope)
	origin, size, croot, ok := parseCheckpoint(cb)
	pk, known := t.rekorLogs[origin]
	switch {
	case !ok || size != e.Proof.TreeSize || !bytes.Equal(croot, root):
		return fmt.Errorf("checkpoint does not state the proven tree")
	case !known:
		return fmt.Errorf("log %q not trusted (pass --rekor-log <vkey>)", origin)
	case !verifyNote(e.Proof.Checkpoint.Envelope, origin, pk):
		return fmt.Errorf("checkpoint of %s is not signed by its key", origin)
	}
	return nil
}

// checkRekorV1 checks a Rekor v1 entry: the body names SHA-512 of the statement and Rekor's
// signed entry timestamp (ECDSA P-256 over the canonical {body, integratedTime, logID, logIndex}).
func checkRekorV1(raw json.RawMessage, top []byte, t trust) error {
	var e struct {
		Statement      string `json:"statement"`
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integrated_time"`
		LogID          string `json:"log_id"`
		LogIndex       int64  `json:"log_index"`
		Set            string `json:"set"`
	}
	if err := json.Unmarshal(raw, &e); err != nil || e.Statement != rekorStatement(top) || e.Body == "" {
		return fmt.Errorf("v1 entry is not for this anchor or has no body")
	}
	body, err := base64.StdEncoding.DecodeString(e.Body)
	var b struct {
		Spec struct {
			Data struct {
				Hash struct{ Value string } `json:"hash"`
			} `json:"data"`
		} `json:"spec"`
	}
	dig := sha512.Sum512([]byte(e.Statement))
	if err != nil || json.Unmarshal(body, &b) != nil || b.Spec.Data.Hash.Value != hex.EncodeToString(dig[:]) {
		return fmt.Errorf("v1 body does not name this statement")
	}
	if t.rekorV1 == nil {
		return fmt.Errorf("v1 signed entry timestamp not checked (pass --rekor-v1-key)")
	}
	payload, _ := json.Marshal(map[string]any{"body": e.Body, "integratedTime": e.IntegratedTime, "logID": e.LogID, "logIndex": e.LogIndex})
	set, _ := base64.StdEncoding.DecodeString(e.Set)
	sum := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(t.rekorV1, sum[:], set) {
		return fmt.Errorf("v1 signed entry timestamp invalid")
	}
	return nil
}
