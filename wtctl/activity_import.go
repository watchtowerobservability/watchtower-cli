package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
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

	"gopkg.in/yaml.v3"
)

// B-8 importers. Every source row is reduced to a flat map (account_id, action, occurred_at,
// actor_id, actor_name, actor_type, actor_email, target_type, target_id, target_name, ip, user_agent,
// outcome, severity, id, plus metadata_* keys), then to an Event v2. The original occurred_at is kept;
// the idempotency key is hex(SHA-256(source id)) so a re-run adds nothing; events are posted per
// account in occurred order so the server-side chain follows the real timeline. The tenant is the
// key's (wti_ with scope ingest:activity); --project is accepted for symmetry and is not sent.

// importMapping is the mapping.yaml form: {format: csv|ndjson, map: {field: column}, const: {field: value}, metadata: [columns]}.
type importMapping struct {
	Format   string            `yaml:"format"`
	Map      map[string]string `yaml:"map"`
	Const    map[string]string `yaml:"const"`
	Metadata []string          `yaml:"metadata"`
}

var importSleep = time.Sleep

func activityImportMain(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("activity import", flag.ContinueOnError)
	from := fs.String("from", "", "workos-csv, retraced-ndjson or a mapping.yaml path")
	api := fs.String("api", os.Getenv("WT_API_URL"), "API base URL; default $WT_API_URL")
	key := fs.String("key", os.Getenv("WT_ACTIVITY_KEY"), "ingestion key (wti_...); default $WT_ACTIVITY_KEY")
	_ = fs.String("project", "", "project id (implied by the key)")
	account := fs.String("account", "", "account_id for rows that carry none")
	dry := fs.Bool("dry-run", false, "map and print the first events, send nothing")
	var files []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			break
		}
		files, args = append(files, fs.Arg(0)), fs.Args()[1:]
	}
	if *from == "" || len(files) != 1 || (!*dry && (*api == "" || *key == "")) {
		return errors.New("usage: wtctl activity import --from workos-csv|retraced-ndjson|mapping.yaml <file> --api <url> --key <wti_...> [--project <prj>] [--account <id>] [--dry-run]")
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		return err
	}
	rows, err := importRows(*from, data)
	if err != nil {
		return err
	}
	events, skipped := buildImportEvents(*from, rows, *account)
	for _, s := range skipped {
		fmt.Fprintln(os.Stderr, "skipped:", s)
	}
	if *dry {
		for i, e := range events {
			if i == 3 {
				break
			}
			b, _ := json.Marshal(e)
			fmt.Fprintln(out, string(b))
		}
		fmt.Fprintf(out, "dry run: %d event(s) mapped, %d skipped\n", len(events), len(skipped))
		return nil
	}
	url := strings.TrimRight(*api, "/") + "/v1/activity/events"
	for i := 0; i < len(events); i += 100 {
		if err := postImportBatch(ctx, url, *key, events[i:min(i+100, len(events))]); err != nil {
			return fmt.Errorf("batch at event %d: %w (re-run is safe: keys are deterministic)", i, err)
		}
	}
	fmt.Fprintf(out, "imported %d event(s), %d skipped\n", len(events), len(skipped))
	return nil
}

func normKey(s string) string {
	return strings.NewReplacer(".", "_", "-", "_", " ", "_").Replace(strings.ToLower(strings.TrimSpace(s)))
}

// importRows parses the file into flat rows keyed by normalized column name (nested JSON flattened with "_").
func importRows(from string, data []byte) ([]map[string]string, error) {
	switch from {
	case "workos-csv":
		return csvRows(data)
	case "retraced-ndjson":
		return ndjsonRows(data)
	}
	m, err := loadMapping(from)
	if err != nil {
		return nil, err
	}
	if m.Format == "ndjson" {
		return ndjsonRows(data)
	}
	return csvRows(data)
}

func csvRows(data []byte) ([]map[string]string, error) {
	recs, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
	if err != nil {
		return nil, err
	}
	if len(recs) == 0 {
		return nil, nil
	}
	var rows []map[string]string
	for _, r := range recs[1:] {
		row := map[string]string{}
		for i, h := range recs[0] {
			if i < len(r) {
				row[normKey(h)] = r[i]
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func ndjsonRows(data []byte) ([]map[string]string, error) {
	var rows []map[string]string
	for n, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.UseNumber()
		var v map[string]any
		if err := dec.Decode(&v); err != nil {
			return nil, fmt.Errorf("line %d: %w", n+1, err)
		}
		row := map[string]string{}
		flatten("", v, row)
		rows = append(rows, row)
	}
	return rows, nil
}

func flatten(prefix string, v any, out map[string]string) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			flatten(prefix+normKey(k)+"_", e, out)
		}
	case nil:
	case string:
		out[strings.TrimSuffix(prefix, "_")] = x
	case json.Number:
		out[strings.TrimSuffix(prefix, "_")] = x.String()
	default:
		b, _ := json.Marshal(x)
		out[strings.TrimSuffix(prefix, "_")] = string(b)
	}
}

func loadMapping(path string) (*importMapping, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("--from must be workos-csv, retraced-ndjson or a mapping.yaml: %w", err)
	}
	var m importMapping
	if err := yaml.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// presets map event fields to (normalized) source columns, first non-empty wins.
var workosMap = map[string][]string{
	"id": {"id"}, "action": {"action"}, "occurred_at": {"occurred_at"}, "account_id": {"organization_id", "account_id"},
	"actor_id": {"actor_id", "actor_user_id"}, "actor_name": {"actor_name"}, "actor_type": {"actor_type"},
	"target_type": {"target_type", "targets_0_type"}, "target_id": {"target_id", "targets_0_id"}, "target_name": {"target_name", "targets_0_name"},
	"ip": {"context_location", "ip"}, "user_agent": {"context_user_agent", "user_agent"},
}

// retracedMap: Retraced events have group (the tenant), created, source_ip and is_failure.
var retracedMap = map[string][]string{
	"id": {"id"}, "action": {"action"}, "occurred_at": {"created"}, "account_id": {"group_id"},
	"actor_id": {"actor_id"}, "actor_name": {"actor_name"}, "target_type": {"target_type"}, "target_id": {"target_id"},
	"target_name": {"target_name"}, "ip": {"source_ip"},
}

// parseTime returns the normalized RFC3339Nano UTC string and the instant it denotes.
func parseTime(s string) (string, time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, l := range []string{time.RFC3339Nano, "2006-01-02 15:04:05", "2006-01-02T15:04:05", "2006-01-02 15:04:05.999999999"} {
		if t, err := time.Parse(l, s); err == nil {
			t = t.UTC()
			return t.Format(time.RFC3339Nano), t, true
		}
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 0 {
		t := time.Unix(n, 0).UTC()
		if n > 1e12 {
			t = time.UnixMilli(n).UTC()
		}
		return t.Format(time.RFC3339Nano), t, true
	}
	return "", time.Time{}, false
}

// buildImportEvents maps rows to Event v2 bodies sorted by (account, occurred_at); unusable rows are listed in skipped.
func buildImportEvents(from string, rows []map[string]string, defAccount string) (events []map[string]any, skipped []string) {
	fields := map[string][]string{}
	var consts map[string]string
	var metaCols []string
	switch from {
	case "workos-csv":
		fields = workosMap
	case "retraced-ndjson":
		fields = retracedMap
	default:
		m, _ := loadMapping(from)
		for k, v := range m.Map {
			fields[k] = []string{normKey(v)}
		}
		consts, metaCols = m.Const, m.Metadata
		for i := range metaCols {
			metaCols[i] = normKey(metaCols[i])
		}
	}
	type item struct {
		acct string
		ts   time.Time
		ev   map[string]any
	}
	var items []item
	for n, row := range rows {
		get := func(f string) string {
			for _, c := range fields[f] {
				if v := strings.TrimSpace(row[c]); v != "" {
					return v
				}
			}
			return consts[f]
		}
		account, action, actor := get("account_id"), get("action"), get("actor_id")
		if account == "" {
			account = defAccount
		}
		at, atTime, okAt := parseTime(get("occurred_at"))
		if account == "" || action == "" || actor == "" || !okAt {
			skipped = append(skipped, fmt.Sprintf("row %d: needs account_id, action, actor_id and a parseable occurred_at", n+1))
			continue
		}
		ev := map[string]any{"account_id": account, "action": action, "occurred_at": at}
		put := func(dst map[string]any, k, f string) {
			if v := get(f); v != "" {
				dst[k] = v
			}
		}
		a := map[string]any{"id": actor}
		put(a, "name", "actor_name")
		put(a, "type", "actor_type")
		put(a, "email", "actor_email")
		ev["actor"] = a
		if t := (map[string]any{}); get("target_type") != "" && get("target_id") != "" {
			t["type"], t["id"] = get("target_type"), get("target_id")
			put(t, "name", "target_name")
			ev["target"] = t
		}
		ctxm := map[string]any{}
		put(ctxm, "ip", "ip")
		put(ctxm, "user_agent", "user_agent")
		if len(ctxm) > 0 {
			ev["context"] = ctxm
		}
		put(ev, "outcome", "outcome")
		put(ev, "severity", "severity")
		if from == "retraced-ndjson" && row["is_failure"] == "true" {
			ev["outcome"] = "failure"
		}
		md := map[string]any{}
		for k, v := range row {
			switch {
			case strings.HasPrefix(k, "fields_") && v != "":
				md[strings.TrimPrefix(k, "fields_")] = v
			case from == "workos-csv" && k == "metadata" && v != "":
				var m map[string]any
				if json.Unmarshal([]byte(v), &m) == nil {
					for mk, mv := range m {
						md[mk] = mv
					}
				}
			}
		}
		for _, c := range metaCols {
			if row[c] != "" {
				md[c] = row[c]
			}
		}
		if len(md) > 0 {
			ev["metadata"] = md
		}
		src := get("id")
		if src == "" { // no source id: hash the row itself so the key is still stable
			b, _ := json.Marshal(row)
			src = string(b)
		}
		sum := sha256.Sum256([]byte(src))
		ev["idempotency_key"] = hex.EncodeToString(sum[:])
		items = append(items, item{account, atTime, ev})
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].acct != items[j].acct {
			return items[i].acct < items[j].acct
		}
		return items[i].ts.Before(items[j].ts)
	})
	for _, it := range items {
		events = append(events, it.ev)
	}
	return events, skipped
}

// postImportBatch posts one batch, retrying 429/5xx/network errors with backoff.
func postImportBatch(ctx context.Context, url, key string, batch []map[string]any) error {
	body, _ := json.Marshal(map[string]any{"events": batch})
	var last error
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			importSleep(time.Duration(1<<attempt) * 500 * time.Millisecond)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("Content-Type", "application/json")
		resp, err := guardedClient(0).Do(req)
		if err != nil {
			last = err
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()
		switch {
		case resp.StatusCode/100 == 2:
			return nil
		case resp.StatusCode == 429 || resp.StatusCode >= 500:
			last = fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(b)))
		default:
			return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(b)))
		}
	}
	return last
}
