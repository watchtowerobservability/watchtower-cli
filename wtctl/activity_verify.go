package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const activityVerifyUsage = "usage: wtctl activity verify <export.ndjson[.gz]> [--project prj_...] [--keys <url|file>] [--checkpoint verify.json]   (--checkpoint needs --keys; exit non-zero on any failure)\n" +
	"       wtctl activity verify --consistency consistency.json [--keys <url|file>] [--from-root <hex root you pinned>]   (see activity_verify_log.go)\n" +
	"       wtctl activity verify --page verify.json --keys <url|file> --project prj_... [--head head.json]   (verdict; see activity_verify_cli.go)"

// Offline verification of an activity export (B-9). The algorithm, so an auditor can reimplement it:
//
// Input: an async export, scheduled export or cold archive (NDJSON, optionally gzip) as the janitor
// writes them, or a dashboard NDJSON export with chain=1: one Event v2 JSON object per line carrying
// `chain_seq` (or `seq`) and `chain_hash` (hex), optionally `chain_body` (the exact hashed object) and
// `prev_hash` (hex, the link of the first row); then optional {"checkpoint": {...}} lines (the newest
// signed checkpoint per account, format below, plus account_id); then a last line {"manifest": {"rows",
// "sha256" (hex SHA-256 of every byte above this line, checkpoint lines included), "project_id",
// archives also "account_id", "first_seq", "last_seq", "last_chain_hash"}}. A signed manifest adds
// "count", "first_seq", "last_seq", "last_hash" (one account only), "kid", "message" and "signature":
// `message` is the UTF-8 JSON array ["wt.activity.manifest.v1", project_id, account_id|null, count,
// first_seq|null, last_seq|null, last_hash|null, sha256], Ed25519 (base64url) by key `kid`; every
// element must match the file. Dashboard downloads without chain=1 and viewer downloads carry no chain
// fields and cannot be verified offline.
//
// Hash chain (one per account; rows sorted by chain_seq; seq 1 links to empty bytes):
//
//	hash(row) = SHA-256( prev_hash_bytes || canonical_json(chain_body(row)) )
//
// chain_body is the row's `chain_body` when present (required for chain body v2 rows, whose
// commitments cannot be rebuilt), else it is rebuilt from the event exactly as crates/wt-store-pg
// activity.rs `chain_body` builds a v1 body: always id, project_id, account_id, actor_id, actor_name, actor_type, action, target_type,
// target_id, target_name, metadata, ip (null when absent), occurred_at_micros (unix microseconds) and
// seq; plus, only when set, user_agent, request_id, session_id, country, actor_email, actor_url,
// on_behalf_of_id, on_behalf_of_name, credential_type, credential_id, credential_fingerprint,
// outcome, severity, trace_id, span_id, targets (stored only with 2+ targets), changes and
// schema_version, operation, context.device_id/region/asn, actor.metadata (as `actor_metadata`) and ext.
// A body v2 row (the line carries `commitments`, {field: hex}) leaves every committed field out
// (`metadata.<path>`, `targets[i].id|name` and for i = 0 also target_id/target_name, or a column)
// and adds "v": 2 and "commit": commitments; salts are never exported, so committed values cannot
// be checked offline, only the hash. canonical_json is crates/wt-audit-chain `canonical_json`: object keys sorted
// bytewise at every level, no whitespace, strings escaped as serde_json does (only `"` `\` and
// control characters < 0x20: \b \f \n \r \t or \u00xx lowercase hex; everything else raw UTF-8),
// numbers as written in the file (the server wrote them with the same serde_json that hashed them).
// The first row of an account whose seq is above 1 (an archive day, a filtered export) is recomputed
// from its `prev_hash` when the line carries one; otherwise its stated hash is taken as the anchor and
// every later row is checked against it.
//
// Checkpoint (optional, --checkpoint): the JSON of GET /v1/activity/feed/verify (or its
// "checkpoint" object). `message` is the exact signed UTF-8 JSON array
// ["wt.activity.checkpoint.v1", project_id, account_id, seq, hex hash, at_unix_s]; `signature` is
// Ed25519 (base64url) by key `kid` from GET /v1/activity/keys?project=<slug>
// ({"keys":[{"kid","x":base64url(32-byte key)}]}). The message must state the checkpoint's seq and
// hash, and a row of the export at that seq must carry that hash. Seqs inside the response's
// `erased` ranges (pseudonymised by an actor erase) are reported as erased, not as tampering.

// canonicalJSON re-encodes a decoded value (decoded with UseNumber) as wt-audit-chain does.
func canonicalJSON(v any, b *bytes.Buffer) error {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSONString(k, b)
			b.WriteByte(':')
			if err := canonicalJSON(x[k], b); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := canonicalJSON(e, b); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case string:
		writeJSONString(x, b)
	case json.Number:
		b.WriteString(x.String()) // shortcut: numbers keep their literal text; floats ryu would print differently mismatch, upgrade if floats appear in hashed metadata
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case nil:
		b.WriteString("null")
	default:
		return fmt.Errorf("unsupported JSON value %T", v)
	}
	return nil
}

func writeJSONString(s string, b *bytes.Buffer) {
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r < 0x20:
			fmt.Fprintf(b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}

func chainHash(prev []byte, body any) ([]byte, error) {
	var b bytes.Buffer
	if err := canonicalJSON(body, &b); err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(prev)
	h.Write(b.Bytes())
	return h.Sum(nil), nil
}

type exportRow struct {
	line int
	seq  int64
	hash []byte
	prev []byte // the stated link, or nil
	doc  map[string]any
}

// chainBody rebuilds crates/wt-store-pg `ActivityEventRow::chain_body` from an exported event.
func chainBody(doc map[string]any, project string, seq json.Number) (map[string]any, error) {
	obj := func(k string) map[string]any { m, _ := doc[k].(map[string]any); return m }
	actor, target, ctx, obo, cred := obj("actor"), obj("target"), obj("context"), obj("on_behalf_of"), obj("credential")
	or := func(m map[string]any, k string) any {
		if v, ok := m[k]; ok {
			return v
		}
		return nil
	}
	at, err := time.Parse(time.RFC3339Nano, strOf(doc["occurred_at"]))
	if err != nil {
		return nil, fmt.Errorf("occurred_at: %w", err)
	}
	meta := doc["metadata"]
	if meta == nil {
		meta = map[string]any{}
	}
	b := map[string]any{
		"id": doc["id"], "project_id": project, "account_id": doc["account_id"],
		"actor_id": or(actor, "id"), "actor_name": or(actor, "name"), "actor_type": or(actor, "type"),
		"action": doc["action"], "target_type": or(target, "type"), "target_id": or(target, "id"),
		"target_name": or(target, "name"), "metadata": meta, "ip": or(ctx, "ip"),
		"occurred_at_micros": json.Number(strconv.FormatInt(at.UnixMicro(), 10)), "seq": seq,
	}
	for k, v := range map[string]any{
		"user_agent": or(ctx, "user_agent"), "request_id": or(ctx, "request_id"), "session_id": or(ctx, "session_id"),
		"country": or(ctx, "country"), "actor_email": or(actor, "email"), "actor_url": or(actor, "url"),
		"on_behalf_of_id": or(obo, "id"), "on_behalf_of_name": or(obo, "name"), "credential_type": or(cred, "type"),
		"credential_id": or(cred, "id"), "credential_fingerprint": or(cred, "fingerprint"),
		"outcome": doc["outcome"], "severity": doc["severity"], "trace_id": doc["trace_id"], "span_id": doc["span_id"],
		"targets": doc["targets"], "changes": doc["changes"], "schema_version": doc["schema_version"],
		"operation": doc["operation"], "device_id": or(ctx, "device_id"), "region": or(ctx, "region"),
		"asn": or(ctx, "asn"), "actor_metadata": or(actor, "metadata"), "ext": doc["ext"],
	} {
		if v != nil {
			b[k] = v
		}
	}
	// body v2 (B-1): committed fields are left out, `commit` holds their salted hashes. Erased
	// values (null, "erased") are therefore irrelevant to the hash.
	if c, ok := doc["commitments"].(map[string]any); ok {
		for f := range c {
			removeField(b, f)
		}
		b["v"], b["commit"] = json.Number("2"), c
	}
	return b, nil
}

// removeField drops a committed field from a body as crates/wt-store-pg `commit::remove_field`:
// `metadata.<path>`, `targets[i].id|name` (for i == 0 also `target_id|name`) or a top-level key.
func removeField(b map[string]any, f string) {
	if path, ok := strings.CutPrefix(f, "metadata."); ok {
		keys := strings.Split(path, ".")
		m, _ := b["metadata"].(map[string]any)
		for _, k := range keys[:len(keys)-1] {
			m, _ = m[k].(map[string]any)
		}
		if m != nil {
			delete(m, keys[len(keys)-1])
		}
		return
	}
	var i int
	var key string
	if n, err := fmt.Sscanf(f, "targets[%d].%s", &i, &key); err == nil && n == 2 && (key == "id" || key == "name") {
		if ts, _ := b["targets"].([]any); i < len(ts) {
			if t, ok := ts[i].(map[string]any); ok {
				delete(t, key)
			}
		}
		if i == 0 {
			delete(b, "target_"+key)
		}
		return
	}
	delete(b, f)
}

type verifyOpts struct {
	project    string
	checkpoint []byte // GET /v1/activity/feed/verify JSON, or nil
	keysDoc    []byte
	signers    map[string]int // when set: events per customer signing kid (N3)
}

// clientKid is the customer key that signed the event: `metadata["wt.csig"].kid`, which the
// chain hash covers (the line's `signed_by` is only a convenience copy).
func clientKid(doc map[string]any) string {
	m, _ := doc["metadata"].(map[string]any)
	if b, ok := doc["chain_body"].(map[string]any); ok {
		m, _ = b["metadata"].(map[string]any)
	}
	c, _ := m["wt.csig"].(map[string]any)
	return strOf(c["kid"])
}

func decodeLine(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var obj map[string]any
	return obj, dec.Decode(&obj)
}

// verifyExport checks an export; it returns the event count and every problem found.
func verifyExport(r io.Reader, o verifyOpts) (rows int, problems []string) {
	bad := func(line int, f string, a ...any) {
		problems = append(problems, fmt.Sprintf("line %d: ", line)+fmt.Sprintf(f, a...))
	}
	accts := map[string][]exportRow{}
	var trailer []map[string]any // {"checkpoint": ...} lines
	var manifest map[string]any
	manifestLine := 0
	sum := sha256.New()
	br := bufio.NewReader(r)
	for line := 1; ; line++ {
		raw, err := br.ReadBytes('\n')
		if len(bytes.TrimSpace(raw)) > 0 {
			obj, derr := decodeLine(raw)
			cp, isCheckpoint := obj["checkpoint"].(map[string]any)
			switch m, isManifest := obj["manifest"].(map[string]any); {
			case derr != nil:
				bad(line, "not JSON: %v", derr)
			case manifest != nil:
				bad(line, "content after the manifest line")
			case isManifest:
				manifest, manifestLine = m, line
			case isCheckpoint:
				trailer = append(trailer, cp)
			default:
				rows++
				seqN, ok := obj["chain_seq"].(json.Number)
				if !ok {
					seqN, _ = obj["seq"].(json.Number)
				}
				seq, serr := seqN.Int64()
				want, herr := hex.DecodeString(strOf(obj["chain_hash"]))
				var prev []byte
				if p, ok := obj["prev_hash"].(string); ok {
					prev, _ = hex.DecodeString(p)
				}
				account := strOf(obj["account_id"])
				if account == "" || serr != nil || herr != nil || len(want) == 0 {
					bad(line, "event needs account_id, chain_seq and chain_hash (hex)")
				} else {
					accts[account] = append(accts[account], exportRow{line, seq, want, prev, obj})
				}
				if k := clientKid(obj); k != "" && o.signers != nil {
					o.signers[k]++
				}
			}
			if manifest == nil {
				sum.Write(raw)
			}
		}
		if err != nil {
			if err != io.EOF {
				problems = append(problems, "read: "+err.Error())
			}
			break
		}
	}
	project := o.project
	if manifest == nil {
		problems = append(problems, "no manifest line (export may be truncated)")
	} else {
		if p := strOf(manifest["project_id"]); project == "" {
			project = p
		} else if p != "" && p != project {
			bad(manifestLine, "manifest project_id %q differs from --project %q", p, project)
		}
		if n, _ := manifest["rows"].(json.Number); n.String() != strconv.Itoa(rows) {
			bad(manifestLine, "manifest rows %s, file has %d", n, rows)
		}
		if strOf(manifest["sha256"]) != hex.EncodeToString(sum.Sum(nil)) {
			bad(manifestLine, "manifest sha256 does not match the lines above it")
		}
		if n, ok := manifest["count"].(json.Number); ok && n.String() != strconv.Itoa(rows) {
			bad(manifestLine, "manifest count %s, file has %d", n, rows)
		}
	}
	if project == "" {
		return rows, append(problems, "project id unknown: pass --project prj_...")
	}
	var cp map[string]any
	erased := func(int64) bool { return false }
	if o.checkpoint != nil {
		doc, err := decodeLine(o.checkpoint)
		if err != nil {
			return rows, append(problems, "checkpoint file: "+err.Error())
		}
		cp = doc
		if c, ok := doc["checkpoint"].(map[string]any); ok {
			cp = c
		}
		ranges, _ := doc["erased"].([]any)
		erased = func(seq int64) bool {
			for _, x := range ranges {
				m, _ := x.(map[string]any)
				if seq >= num(m["from_seq"]) && seq <= num(m["to_seq"]) {
					return true
				}
			}
			return false
		}
	}
	hashes := map[string]map[int64][]byte{}
	for account, rs := range accts {
		sort.Slice(rs, func(i, j int) bool { return rs[i].seq < rs[j].seq })
		hashes[account] = map[int64][]byte{}
		var prev []byte
		for i, x := range rs {
			if i == 0 && x.prev != nil {
				prev = x.prev
			}
			switch {
			case i > 0 && x.seq != rs[i-1].seq+1:
				bad(x.line, "account %s: seq %d follows %d (gap or duplicate)", account, x.seq, rs[i-1].seq)
			case i == 0 && x.seq != 1 && x.prev == nil: // anchor: see the doc comment
			default:
				body, err := rowBody(x, project)
				var got []byte
				if err == nil {
					got, err = chainHash(prev, body)
				}
				if (err != nil || !bytes.Equal(got, x.hash)) && !erased(x.seq) {
					bad(x.line, "account %s seq %d: hash mismatch (row modified or chain broken)", account, x.seq)
				}
			}
			prev = x.hash
			hashes[account][x.seq] = x.hash
		}
		if manifest != nil && strOf(manifest["account_id"]) == account {
			last := rs[len(rs)-1]
			fs, _ := manifest["first_seq"].(json.Number)
			ls, _ := manifest["last_seq"].(json.Number)
			if fs.String() != strconv.FormatInt(rs[0].seq, 10) || ls.String() != strconv.FormatInt(last.seq, 10) ||
				strOf(manifest["last_chain_hash"]) != hex.EncodeToString(last.hash) {
				bad(manifestLine, "manifest seq range or last_chain_hash does not match account %q", account)
			}
		}
	}
	if cp != nil {
		problems = append(problems, checkCheckpoint(cp, o.keysDoc, project, hashes)...)
	}
	if o.keysDoc != nil {
		for _, c := range trailer {
			problems = append(problems, checkCheckpoint(c, o.keysDoc, project, hashes)...)
		}
		if manifest != nil && manifest["signature"] != nil {
			for _, p := range checkManifest(manifest, o.keysDoc, project, rows, accts) {
				bad(manifestLine, "%s", p)
			}
		}
	}
	return rows, problems
}

// rowBody is the line's `chain_body` (its seq must match) or the rebuilt v1 body.
func rowBody(x exportRow, project string) (any, error) {
	seq := json.Number(strconv.FormatInt(x.seq, 10))
	if b, ok := x.doc["chain_body"].(map[string]any); ok {
		if s, _ := b["seq"].(json.Number); s != seq {
			return nil, errors.New("chain_body seq differs")
		}
		return b, nil
	}
	return chainBody(x.doc, project, seq)
}

// pubKey finds `kid` in a GET /v1/activity/keys document.
func pubKey(keysDoc []byte, kid string) (ed25519.PublicKey, error) {
	var kd struct{ Keys []struct{ Kid, X string } }
	if err := json.Unmarshal(keysDoc, &kd); err != nil {
		return nil, fmt.Errorf("keys document: %w", err)
	}
	for _, k := range kd.Keys {
		if raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.X, "=")); err == nil && k.Kid == kid && len(raw) == ed25519.PublicKeySize {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("unknown key id %q", kid)
}

// checkManifest verifies a signed manifest's Ed25519 signature and that its message states this file.
func checkManifest(m map[string]any, keysDoc []byte, project string, rows int, accts map[string][]exportRow) []string {
	pub, err := pubKey(keysDoc, strOf(m["kid"]))
	if err != nil {
		return []string{"manifest signature: " + err.Error()}
	}
	sig, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(strOf(m["signature"]), "="))
	msg := strOf(m["message"])
	if err != nil || !ed25519.Verify(pub, []byte(msg), sig) {
		return []string{"manifest signature invalid"}
	}
	var a []any
	dec := json.NewDecoder(strings.NewReader(msg))
	dec.UseNumber()
	if err := dec.Decode(&a); err != nil || len(a) != 8 || a[0] != "wt.activity.manifest.v1" {
		return []string{"manifest message is not a wt.activity.manifest.v1 array"}
	}
	n, _ := a[3].(json.Number)
	if strOf(a[1]) != project || n.String() != strconv.Itoa(rows) || strOf(a[7]) != strOf(m["sha256"]) {
		return []string{"signed manifest message differs from the file (project, count or sha256)"}
	}
	if a[2] == nil {
		return nil
	}
	rs := accts[strOf(a[2])]
	if len(rs) == 0 {
		return []string{fmt.Sprintf("signed manifest names account %q, which has no rows here", strOf(a[2]))}
	}
	f, _ := a[4].(json.Number)
	l, _ := a[5].(json.Number)
	last := rs[len(rs)-1]
	if f.String() != strconv.FormatInt(rs[0].seq, 10) || l.String() != strconv.FormatInt(last.seq, 10) || strOf(a[6]) != hex.EncodeToString(last.hash) {
		return []string{"signed manifest seq range or last hash differs from the rows"}
	}
	return nil
}

func strOf(v any) string { s, _ := v.(string); return s }

// num is a JSON integer, or -1.
func num(v any) int64 {
	n, ok := v.(json.Number)
	i, err := n.Int64()
	if !ok || err != nil {
		return -1
	}
	return i
}

func checkCheckpoint(cp map[string]any, keysDoc []byte, project string, hashes map[string]map[int64][]byte) []string {
	bad := func(f string, args ...any) []string { return []string{"checkpoint: " + fmt.Sprintf(f, args...)} }
	pub, err := pubKey(keysDoc, strOf(cp["kid"]))
	if err != nil {
		return bad("%v", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(strOf(cp["signature"]), "="))
	if err != nil {
		return bad("signature is not base64url")
	}
	msg := strOf(cp["message"])
	if !ed25519.Verify(pub, []byte(msg), sig) {
		return bad("signature invalid")
	}
	var m []any
	dec := json.NewDecoder(strings.NewReader(msg))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil || len(m) != 6 || m[0] != "wt.activity.checkpoint.v1" {
		return bad("message is not a wt.activity.checkpoint.v1 array")
	}
	seqN, _ := m[3].(json.Number)
	cs, _ := cp["seq"].(json.Number)
	if seqN.String() != cs.String() || strOf(m[4]) != strOf(cp["hash"]) {
		return bad("message seq/hash differ from the checkpoint fields")
	}
	if strOf(m[1]) != project {
		return bad("signed for project %s, export is %s", strOf(m[1]), project)
	}
	seq, _ := seqN.Int64()
	if h, ok := hashes[strOf(m[2])][seq]; ok && hex.EncodeToString(h) != strOf(m[4]) {
		return bad("signed hash of seq %d differs from the export's row", seq)
	}
	return nil
}

// activityVerifyMain is `wtctl activity verify`: any failure is a non-nil error (exit 1).
func activityVerifyMain(ctx context.Context, args []string, out io.Writer) error {
	if wantsVerdict(args) {
		return activityVerdictMain(ctx, args, out)
	}
	fs := flag.NewFlagSet("activity verify", flag.ContinueOnError)
	keys := fs.String("keys", "", "public keys: URL (GET /v1/activity/keys?project=<slug>) or file")
	cpFile := fs.String("checkpoint", "", "GET /v1/activity/feed/verify response (JSON file) holding the signed checkpoint")
	project := fs.String("project", "", "project id prj_... (default: the manifest's)")
	consistency := fs.String("consistency", "", "GET /v1/activity/feed/consistency response (JSON file): check the Merkle log only appended")
	fromRoot := fs.String("from-root", "", "with --consistency: the hex root of the older tree head you saw before")
	var files []string
	for len(args) > 0 { // flags may follow the file
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			break
		}
		files, args = append(files, fs.Arg(0)), fs.Args()[1:]
	}
	if (len(files) != 1 && *consistency == "") || (*consistency != "" && len(files) != 0) || (*cpFile != "" && *keys == "") {
		return errors.New(activityVerifyUsage)
	}
	o := verifyOpts{project: *project}
	var err error
	if *cpFile != "" {
		if o.checkpoint, err = os.ReadFile(*cpFile); err != nil {
			return fmt.Errorf("checkpoint: %w", err)
		}
	}
	if *keys != "" {
		if strings.HasPrefix(*keys, "http://") || strings.HasPrefix(*keys, "https://") {
			var req *http.Request
			if req, err = http.NewRequestWithContext(ctx, http.MethodGet, *keys, nil); err == nil {
				var resp *http.Response
				if resp, err = guardedClient(0).Do(req); err == nil {
					defer resp.Body.Close()
					if resp.StatusCode/100 != 2 {
						return fmt.Errorf("fetch keys: %s", resp.Status)
					}
					o.keysDoc, err = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
				}
			}
		} else {
			o.keysDoc, err = os.ReadFile(*keys)
		}
		if err != nil {
			return fmt.Errorf("keys: %w", err)
		}
	}
	if *consistency != "" {
		doc, err := os.ReadFile(*consistency)
		if err != nil {
			return fmt.Errorf("consistency: %w", err)
		}
		return reportConsistency(out, checkConsistency(doc, o.keysDoc, *fromRoot), o.keysDoc != nil)
	}
	f, err := os.Open(files[0])
	if err != nil {
		return err
	}
	defer f.Close()
	in := bufio.NewReader(f)
	var r io.Reader = in
	if magic, _ := in.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(in)
		if err != nil {
			return err
		}
		defer gz.Close()
		r = gz
	}
	o.signers = map[string]int{}
	n, problems := verifyExport(r, o)
	for _, p := range problems {
		fmt.Fprintln(out, "FAIL", p)
	}
	if len(problems) > 0 {
		return fmt.Errorf("verification failed: %d problem(s) in %d event(s)", len(problems), n)
	}
	what := "hash chains and manifest"
	if o.checkpoint != nil {
		what += " and signed checkpoint"
	}
	if o.keysDoc != nil {
		what += " (signed manifest and checkpoint lines checked when present)"
	} else {
		what += " (signatures not checked: pass --keys)"
	}
	fmt.Fprintf(out, "OK: %d event(s), %s verified\n", n, what)
	kids := make([]string, 0, len(o.signers))
	for k := range o.signers {
		kids = append(kids, k)
	}
	sort.Strings(kids)
	for _, k := range kids {
		fmt.Fprintf(out, "  signed by %s: %d event(s) (customer signature checked at ingest)\n", k, o.signers[k])
	}
	return nil
}
