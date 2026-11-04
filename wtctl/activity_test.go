package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Hashes computed independently in Python (sha256(prev || json.dumps(sort_keys, compact, ensure_ascii=False)))
// from the same bodies, i.e. the wt-audit-chain algorithm.
var fixtureHashes = []string{
	"c55dbb3f2c5eb29b7d26e81e9265c2aec2d351a7d8f7cb45ac84b05be55874d2",
	"84be4ca451e2e5f3e036d2d95e0fff2dcf6e013aa205c459a017f5c6d0d18bf9",
	"c09a0af42859def5032f4ce1179ebcfd2f9f86123d995d4aafb7aed9d7dbfd0f",
}

// fixtureExport is an archive as the janitor writes it: Event v2 lines whose rebuilt chain bodies are
// the bodies the fixture hashes were computed from, then the manifest. cp is a verify response.
func fixtureExport(t *testing.T) (export string, cp, keysDoc []byte) {
	t.Helper()
	acts := []string{"doc.created", "doc.updated", "doc.deleted"}
	mds := []string{`{"title":"héllo \"q\"\n","n":3}`, `{"a":[1,null,true]}`, `{}`}
	var body strings.Builder
	for i := 0; i < 3; i++ {
		s := i + 1
		fmt.Fprintf(&body, `{"id":"00000000-0000-0000-0000-00000000000%d","account_id":"acme","action":%q,"occurred_at":"2023-11-14T22:13:20.00000%dZ","received_at":"2023-11-14T22:13:21.000000Z","actor":{"id":"u1","type":"user"},"target":{"type":"doc","id":"d1"},"context":{},"metadata":%s,"chain_seq":%d,"chain_hash":%q}`+"\n",
			s, acts[i], s, mds[i], s, fixtureHashes[i])
	}
	sum := sha256.Sum256([]byte(body.String()))
	fmt.Fprintf(&body, `{"manifest":{"rows":3,"sha256":%q,"project_id":"prj_1","account_id":"acme","first_seq":1,"last_seq":3,"last_chain_hash":%q}}`+"\n",
		hex.EncodeToString(sum[:]), fixtureHashes[2])
	pub, priv, _ := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{7}, 64)))
	msg := fmt.Sprintf(`["wt.activity.checkpoint.v1","prj_1","acme",3,%q,1761782400]`, fixtureHashes[2])
	sig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(msg)))
	cp, _ = json.Marshal(map[string]any{"checkpoint": map[string]any{"seq": 3, "hash": fixtureHashes[2], "at": "2026-10-30T00:00:00Z",
		"kid": "k1", "kind": "periodic", "message": msg, "signature": sig}, "erased": []any{}})
	keys, _ := json.Marshal(map[string]any{"keys": []map[string]string{{"kid": "k1", "x": base64.RawURLEncoding.EncodeToString(pub)}}})
	return body.String(), cp, keys
}

func TestVerifyExport(t *testing.T) {
	exp, cp, keys := fixtureExport(t)
	o := verifyOpts{checkpoint: cp, keysDoc: keys}
	if n, p := verifyExport(strings.NewReader(exp), o); n != 3 || len(p) != 0 {
		t.Fatalf("good export: n=%d problems=%v", n, p)
	}
	for name, mut := range map[string]func(string) string{
		"modified row": func(s string) string { return strings.Replace(s, `"doc.updated"`, `"doc.UPDATED"`, 1) },
		"deleted row":  func(s string) string { l := strings.Split(s, "\n"); return strings.Join(append(l[:1], l[2:]...), "\n") },
		"no manifest": func(s string) string {
			l := strings.Split(strings.TrimSpace(s), "\n")
			return strings.Join(l[:len(l)-1], "\n")
		},
		"manifest wrong": func(s string) string { return strings.Replace(s, `"rows":3`, `"rows":4`, 1) },
	} {
		if _, p := verifyExport(strings.NewReader(mut(exp)), o); len(p) == 0 {
			t.Errorf("%s: tampering not detected", name)
		}
	}
	badSig := verifyOpts{checkpoint: []byte(strings.Replace(string(cp), "1761782400", "1761782401", 1)), keysDoc: keys}
	if _, p := verifyExport(strings.NewReader(exp), badSig); len(p) == 0 {
		t.Error("bad signature not detected")
	}
}

func TestVerifyCommandExit(t *testing.T) {
	exp, cp, keys := fixtureExport(t)
	dir := t.TempDir()
	ef, kf, cf := filepath.Join(dir, "e.ndjson.gz"), filepath.Join(dir, "k.json"), filepath.Join(dir, "v.json")
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, _ = w.Write([]byte(exp))
	_ = w.Close()
	_ = os.WriteFile(ef, gz.Bytes(), 0o600)
	_ = os.WriteFile(kf, keys, 0o600)
	_ = os.WriteFile(cf, cp, 0o600)
	var out bytes.Buffer
	if err := activityVerifyMain(context.Background(), []string{ef, "--checkpoint", cf, "--keys", kf}, &out); err != nil {
		t.Fatal(err, out.String())
	}
	_ = os.WriteFile(ef, []byte(strings.Replace(exp, "doc.created", "doc.xcreated", 1)), 0o600)
	if err := activityVerifyMain(context.Background(), []string{ef}, &out); err == nil {
		t.Fatal("tampered export must fail")
	}
}

func TestImportMapping(t *testing.T) {
	csvData := "id,action,occurred_at,organization_id,actor_id,actor_name,target_type,target_id,context_location,metadata\n" +
		"b,doc.b,2024-01-02 10:00:00,acme,u1,Ann,doc,2,1.1.1.1,\"{\"\"k\"\":1}\"\n" +
		"a,doc.a,2024-01-01T10:00:00Z,acme,u1,Ann,doc,1,,\n" +
		"x,,2024-01-01T10:00:00Z,acme,u1,,,,,\n"
	rows, err := importRows("workos-csv", []byte(csvData))
	if err != nil {
		t.Fatal(err)
	}
	evs, skipped := buildImportEvents("workos-csv", rows, "")
	if len(evs) != 2 || len(skipped) != 1 || evs[0]["action"] != "doc.a" || evs[1]["occurred_at"] != "2024-01-02T10:00:00Z" {
		t.Fatalf("workos: %v %v", evs, skipped)
	}
	if want := "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"; evs[0]["idempotency_key"] != want { // sha256("a")
		t.Fatalf("key %v", evs[0]["idempotency_key"])
	}
	if evs[1]["metadata"].(map[string]any)["k"] == nil || evs[1]["context"].(map[string]any)["ip"] != "1.1.1.1" {
		t.Fatalf("workos extras: %v", evs[1])
	}

	nd := `{"id":"r1","action":"login","created":"2024-03-01T00:00:00Z","group":{"id":"g1"},"actor":{"id":"u9","name":"Zed"},"target":{"id":"t","type":"app"},"source_ip":"2.2.2.2","is_failure":true,"fields":{"why":"pw"}}` + "\n"
	rows, _ = importRows("retraced-ndjson", []byte(nd))
	evs, _ = buildImportEvents("retraced-ndjson", rows, "")
	if len(evs) != 1 || evs[0]["account_id"] != "g1" || evs[0]["outcome"] != "failure" || evs[0]["metadata"].(map[string]any)["why"] != "pw" {
		t.Fatalf("retraced: %v", evs)
	}

	my := filepath.Join(t.TempDir(), "m.yaml")
	_ = os.WriteFile(my, []byte("format: csv\nmap: {id: Ref, action: Event, occurred_at: When, actor_id: Who}\nconst: {account_id: acme}\nmetadata: [Note]\n"), 0o600)
	rows, err = importRows(my, []byte("Ref,Event,When,Who,Note\n1,x.y,1700000000,bob,hi\n"))
	if err != nil {
		t.Fatal(err)
	}
	evs, _ = buildImportEvents(my, rows, "")
	if len(evs) != 1 || evs[0]["account_id"] != "acme" || evs[0]["occurred_at"] != "2023-11-14T22:13:20Z" || evs[0]["metadata"].(map[string]any)["note"] != "hi" {
		t.Fatalf("yaml: %v", evs)
	}
}

func TestImportBatchesAndRetry(t *testing.T) {
	importSleep = func(time.Duration) {}
	var calls, sizes []int
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if n == 1 {
			w.WriteHeader(503)
			return
		}
		var b struct{ Events []any }
		_ = json.NewDecoder(r.Body).Decode(&b)
		sizes = append(sizes, len(b.Events))
		calls = append(calls, n)
		if r.Header.Get("Authorization") != "Bearer wti_k" {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(202)
	}))
	defer srv.Close()
	var sb strings.Builder
	sb.WriteString("id,action,occurred_at,account_id,actor_id\n")
	for i := 0; i < 250; i++ {
		fmt.Fprintf(&sb, "%d,a.b,2024-01-01T00:00:%02dZ,acme,u\n", i, i%60)
	}
	f := filepath.Join(t.TempDir(), "w.csv")
	_ = os.WriteFile(f, []byte(sb.String()), 0o600)
	var out bytes.Buffer
	if err := activityImportMain(context.Background(), []string{"--from", "workos-csv", f, "--api", srv.URL, "--key", "wti_k"}, &out); err != nil {
		t.Fatal(err, out.String())
	}
	if fmt.Sprint(sizes) != "[100 100 50]" {
		t.Fatalf("batches %v", sizes)
	}
}

func TestTailAndTypes(t *testing.T) {
	var out bytes.Buffer
	polls := [][]tailEvent{
		{{ID: "1", Action: "old"}},
		{{ID: "3", Action: "c", Warnings: []any{"missing field x"}}, {ID: "2", Action: "b"}, {ID: "1", Action: "old"}},
	}
	i := 0
	fetch := func() ([]tailEvent, error) { r := polls[i]; i++; return r, nil }
	if err := tailLoop(context.Background(), fetch, time.Millisecond, false, 2, &out); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if strings.Contains(s, "old") || strings.Index(s, " b ") > strings.Index(s, " c ") || !strings.Contains(s, "warning: missing field x") {
		t.Fatalf("tail output:\n%s", s)
	}

	defs := []schemaDef{{Action: "doc.deleted", Version: 2, MetadataSchema: map[string]any{
		"properties": map[string]any{"reason": map[string]any{"type": "string", "enum": []any{"spam", "user"}}, "count": map[string]any{"type": "integer"}},
		"required":   []any{"reason"}}}}
	ts, py, gos := renderTypes(defs, "ts"), renderTypes(defs, "py"), renderTypes(defs, "go")
	if !strings.Contains(ts, `"reason": "spam" | "user";`) || !strings.Contains(ts, `"count"?: number;`) || !strings.Contains(ts, `"doc.deleted": DocDeletedMetadata;`) {
		t.Fatal(ts)
	}
	if !strings.Contains(py, `reason: Literal["spam", "user"]`) || !strings.Contains(py, "count: NotRequired[int]") {
		t.Fatal(py)
	}
	if !strings.Contains(gos, "Count *int64 `json:\"count,omitempty\"`") {
		t.Fatal(gos)
	}
	_ = io.Discard
}
