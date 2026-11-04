package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
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
	"time"
)

// `wtctl import helicone` (PLT-052): Helicone is in maintenance mode after its acquisition. This
// replays the JSONL file `npx @helicone/export --format jsonl` writes as OTLP gen_ai spans on the
// gateway, so past LLM requests (model, tokens, cost, latency, user, properties) show in LLM
// observability next to new OpenLLMetry traffic. Span and trace ids are derived from the Helicone
// response id, so a second run of the same file is deduplicated downstream (at-least-once).
const heliconeUsage = "usage: wtctl import helicone --file <export.jsonl> [--endpoint <gateway url>] [--key <ingestion key>] [--service <name>] [--dry-run]\n" +
	"       (endpoint and key default to $WT_OTLP_ENDPOINT and $WT_INGEST_KEY)"

const heliconeBatch = 200

// heliconeRow is one exported request; unknown fields are ignored.
type heliconeRow struct {
	ResponseID        string         `json:"response_id"`
	ResponseCreatedAt string         `json:"response_created_at"`
	ResponseStatus    int            `json:"response_status"`
	RequestCreatedAt  string         `json:"request_created_at"`
	RequestUserID     string         `json:"request_user_id"`
	RequestProperties map[string]any `json:"request_properties"`
	Model             string         `json:"model"`
	Provider          string         `json:"provider"`
	PromptTokens      *float64       `json:"prompt_tokens"`
	CompletionTokens  *float64       `json:"completion_tokens"`
	Latency           *float64       `json:"latency"` // milliseconds
	Cost              *float64       `json:"cost"`    // USD
}

func otlpStr(k, v string) map[string]any {
	return map[string]any{"key": k, "value": map[string]any{"stringValue": v}}
}

func otlpInt(k string, v float64) map[string]any {
	return map[string]any{"key": k, "value": map[string]any{"intValue": strconv.FormatInt(int64(v), 10)}}
}

func otlpDouble(k string, v float64) map[string]any {
	return map[string]any{"key": k, "value": map[string]any{"doubleValue": v}}
}

func heliconeTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999Z07:00", "2006-01-02 15:04:05.999999999", "2006-01-02T15:04:05.999999999"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// heliconeSpan maps one row to an OTLP/JSON span; ok is false for a row without id or start time.
func heliconeSpan(r heliconeRow) (map[string]any, bool) {
	start, ok := heliconeTime(r.RequestCreatedAt)
	if r.ResponseID == "" || !ok {
		return nil, false
	}
	end := start
	if r.Latency != nil && *r.Latency > 0 {
		end = start.Add(time.Duration(*r.Latency * float64(time.Millisecond)))
	} else if t, ok := heliconeTime(r.ResponseCreatedAt); ok && t.After(start) {
		end = t
	}
	sum := sha256.Sum256([]byte("helicone:" + r.ResponseID))
	attrs := []any{otlpStr("gen_ai.operation.name", "chat"), otlpStr("import.source", "helicone"), otlpStr("helicone.response_id", r.ResponseID)}
	if r.Model != "" {
		attrs = append(attrs, otlpStr("gen_ai.request.model", r.Model), otlpStr("gen_ai.response.model", r.Model))
	}
	if r.Provider != "" {
		attrs = append(attrs, otlpStr("gen_ai.provider.name", strings.ToLower(r.Provider)))
	}
	if r.PromptTokens != nil {
		attrs = append(attrs, otlpInt("gen_ai.usage.input_tokens", *r.PromptTokens))
	}
	if r.CompletionTokens != nil {
		attrs = append(attrs, otlpInt("gen_ai.usage.output_tokens", *r.CompletionTokens))
	}
	if r.Cost != nil {
		attrs = append(attrs, otlpDouble("gen_ai.usage.cost", *r.Cost))
	}
	if r.RequestUserID != "" {
		attrs = append(attrs, otlpStr("user.id", r.RequestUserID))
	}
	for k, v := range r.RequestProperties {
		if !strings.HasPrefix(strings.ToLower(k), "wt.") { // tenant attributes come only from the key
			attrs = append(attrs, otlpStr("helicone.property."+k, fmt.Sprint(v)))
		}
	}
	status := map[string]any{"code": 1}
	if r.ResponseStatus >= 400 {
		status = map[string]any{"code": 2, "message": "HTTP " + strconv.Itoa(r.ResponseStatus)}
	}
	if r.ResponseStatus != 0 {
		attrs = append(attrs, otlpInt("http.response.status_code", float64(r.ResponseStatus)))
	}
	name := "chat"
	if r.Model != "" {
		name += " " + r.Model
	}
	return map[string]any{
		"traceId": hex.EncodeToString(sum[:16]), "spanId": hex.EncodeToString(sum[16:24]), "name": name, "kind": 3,
		"startTimeUnixNano": strconv.FormatInt(start.UnixNano(), 10), "endTimeUnixNano": strconv.FormatInt(end.UnixNano(), 10),
		"attributes": attrs, "status": status,
	}, true
}

func heliconePayload(service string, spans []any) []byte {
	b, _ := json.Marshal(map[string]any{"resourceSpans": []any{map[string]any{
		"resource":   map[string]any{"attributes": []any{otlpStr("service.name", service)}},
		"scopeSpans": []any{map[string]any{"scope": map[string]any{"name": "wtctl.import.helicone"}, "spans": spans}},
	}}})
	return b
}

func heliconePost(ctx context.Context, hc *http.Client, endpoint, key string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(endpoint, "/")+"/v1/traces", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("gateway answered HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

func importHelicone(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("import helicone", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var file, endpoint, key, service string
	var dry bool
	fs.StringVar(&file, "file", "", "")
	fs.StringVar(&endpoint, "endpoint", os.Getenv("WT_OTLP_ENDPOINT"), "")
	fs.StringVar(&key, "key", os.Getenv("WT_INGEST_KEY"), "")
	fs.StringVar(&service, "service", "helicone-import", "")
	fs.BoolVar(&dry, "dry-run", false, "")
	if err := fs.Parse(args); err != nil || file == "" {
		return errors.New(heliconeUsage)
	}
	if !dry && (endpoint == "" || key == "") {
		return errors.New("--endpoint and --key are required (or $WT_OTLP_ENDPOINT, $WT_INGEST_KEY)\n" + heliconeUsage)
	}
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	hc := guardedClient(30 * time.Second)
	var batch []any
	sent, skipped := 0, 0
	flush := func() error {
		if len(batch) == 0 || dry {
			sent += len(batch)
			batch = batch[:0]
			return nil
		}
		if err := heliconePost(ctx, hc, endpoint, key, heliconePayload(service, batch)); err != nil {
			return fmt.Errorf("after %d spans: %w", sent, err)
		}
		sent += len(batch)
		batch = batch[:0]
		return nil
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20) // rows with --include-body can be large
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var r heliconeRow
		if json.Unmarshal(line, &r) != nil {
			skipped++
			continue
		}
		s, ok := heliconeSpan(r)
		if !ok {
			skipped++
			continue
		}
		if batch = append(batch, s); len(batch) >= heliconeBatch {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if err := flush(); err != nil {
		return err
	}
	verb := "imported"
	if dry {
		verb = "would import"
	}
	fmt.Fprintf(out, "%s %d Helicone requests as gen_ai spans; skipped %d rows without response_id or request_created_at\n", verb, sent, skipped)
	return nil
}
