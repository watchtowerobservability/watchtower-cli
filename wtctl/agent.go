package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const agentUsage = `usage: wtctl agent setup claude|gemini|cursor|codex --endpoint <otlp url> [--dir .] [--dry-run]
       wtctl agent headers                       (prints OTLP headers JSON from $WT_INGEST_KEY; used as Claude Code's otelHeadersHelper)
       wtctl agent inspect issues|monitors|logs|trace <id> --api <url> --key <key> --project <id> [--limit 20] [--text <q>]   (read-only, JSON output)`

// agentMain is `wtctl agent`: trace a coding agent into Watchtower and let an agent read back
// what it broke. The ingest key never lands in a file: Claude Code gets a headers helper, the
// others read OTEL_EXPORTER_OTLP_HEADERS from the environment.
func agentMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) < 1 {
		return errors.New(agentUsage)
	}
	switch args[0] {
	case "setup":
		return agentSetup(args[1:], out)
	case "headers":
		key := os.Getenv("WT_INGEST_KEY")
		if key == "" {
			return errors.New("WT_INGEST_KEY is not set")
		}
		return json.NewEncoder(out).Encode(map[string]string{"Authorization": "Bearer " + key})
	case "inspect":
		return agentInspect(ctx, args[1:], out)
	}
	return errors.New(agentUsage)
}

func agentSetup(args []string, out io.Writer) error {
	if len(args) < 1 {
		return errors.New(agentUsage)
	}
	tool := args[0]
	fs := flag.NewFlagSet("agent setup", flag.ContinueOnError)
	var endpoint, dir string
	var dry bool
	fs.StringVar(&endpoint, "endpoint", os.Getenv("WT_OTLP_ENDPOINT"), "OTLP/HTTP base URL of the gateway")
	fs.StringVar(&dir, "dir", ".", "project directory to write the agent settings into")
	fs.BoolVar(&dry, "dry-run", false, "print the settings instead of writing them")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if endpoint == "" {
		return errors.New("--endpoint (or $WT_OTLP_ENDPOINT) is required")
	}
	endpoint = strings.TrimRight(endpoint, "/")
	mcp := map[string]any{"mcpServers": map[string]any{"watchtower": map[string]any{
		"command": "wtctl", "args": []string{"mcp", "serve", "--stdio", "--project", "${WT_PROJECT_ID}"},
		"env": map[string]string{"WT_API_URL": "${WT_API_URL}", "WT_API_KEY": "${WT_API_KEY}", "WT_OPENAPI_JSON": "${WT_OPENAPI_JSON}"},
	}}}
	switch tool {
	case "claude":
		settings := map[string]any{
			"env": map[string]string{
				"CLAUDE_CODE_ENABLE_TELEMETRY": "1",
				"OTEL_METRICS_EXPORTER":        "otlp",
				"OTEL_LOGS_EXPORTER":           "otlp",
				"OTEL_EXPORTER_OTLP_PROTOCOL":  "http/protobuf",
				"OTEL_EXPORTER_OTLP_ENDPOINT":  endpoint,
			},
			"otelHeadersHelper": "wtctl agent headers",
		}
		if err := mergeJSONFile(filepath.Join(dir, ".claude", "settings.json"), settings, dry, out); err != nil {
			return err
		}
		return mergeJSONFile(filepath.Join(dir, ".mcp.json"), mcp, dry, out)
	case "gemini":
		s := map[string]any{"telemetry": map[string]any{"enabled": true, "target": "local", "otlpEndpoint": endpoint, "otlpProtocol": "http"}}
		fmt.Fprintln(out, "# export OTEL_EXPORTER_OTLP_HEADERS=\"Authorization=Bearer $WT_INGEST_KEY\" in your shell: the key is not written to disk")
		return mergeJSONFile(filepath.Join(dir, ".gemini", "settings.json"), s, dry, out)
	case "cursor":
		fmt.Fprintln(out, "# Cursor has no OTel export; the MCP server below lets it read Watchtower")
		return mergeJSONFile(filepath.Join(dir, ".cursor", "mcp.json"), mcp, dry, out)
	case "codex":
		fmt.Fprintf(out, "# add to ~/.codex/config.toml, and export OTEL_EXPORTER_OTLP_HEADERS=\"Authorization=Bearer $WT_INGEST_KEY\"\n[otel]\nexporter = { otlp-http = { endpoint = %q, protocol = \"binary\" } }\n", endpoint+"/v1/logs")
		return nil
	}
	return errors.New(agentUsage)
}

// mergeJSONFile deep-merges add into the JSON object at path (created when missing), keeping
// every key it does not set. With dry the result is printed and nothing is written.
func mergeJSONFile(path string, add map[string]any, dry bool, out io.Writer) error {
	cur := map[string]any{}
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, &cur); err != nil {
			return fmt.Errorf("%s is not a JSON object: %w", path, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	deepMerge(cur, add)
	b, err := json.MarshalIndent(cur, "", "  ")
	if err != nil {
		return err
	}
	if dry {
		fmt.Fprintf(out, "# %s\n%s\n", path, b)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	fmt.Fprintln(out, "wrote", path)
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func deepMerge(dst, src map[string]any) {
	for k, v := range src {
		if sm, ok := v.(map[string]any); ok {
			if dm, ok := dst[k].(map[string]any); ok {
				deepMerge(dm, sm)
				continue
			}
		}
		if sm, ok := v.(map[string]string); ok {
			m := map[string]any{}
			for a, b := range sm {
				m[a] = b
			}
			v = m
			if dm, ok := dst[k].(map[string]any); ok {
				deepMerge(dm, m)
				continue
			}
		}
		dst[k] = v
	}
}

// agentInspect only issues GET requests, so an agent can be given this command safely.
func agentInspect(ctx context.Context, args []string, out io.Writer) error {
	if len(args) < 1 {
		return errors.New(agentUsage)
	}
	what, rest := args[0], args[1:]
	id := ""
	if what == "trace" {
		if len(rest) < 1 {
			return errors.New("trace needs an id")
		}
		id, rest = rest[0], rest[1:]
	}
	fs := flag.NewFlagSet("agent inspect", flag.ContinueOnError)
	var api, key, project, text string
	var limit int
	fs.StringVar(&api, "api", os.Getenv("WT_API_URL"), "API base URL")
	fs.StringVar(&key, "key", os.Getenv("WT_API_KEY"), "API key")
	fs.StringVar(&project, "project", os.Getenv("WT_PROJECT_ID"), "project id")
	fs.StringVar(&text, "text", "", "log text filter")
	fs.IntVar(&limit, "limit", 20, "page size")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if api == "" || key == "" || project == "" {
		return errors.New("--api, --key and --project are required")
	}
	base := strings.TrimRight(api, "/") + "/v1/projects/" + url.PathEscape(project)
	var u string
	switch what {
	case "issues", "monitors":
		u = fmt.Sprintf("%s/%s?limit=%d", base, what, limit)
	case "logs":
		u = fmt.Sprintf("%s/logs/search?limit=%d&text=%s", base, limit, url.QueryEscape(text))
	case "trace":
		u = base + "/traces/" + url.PathEscape(id)
	default:
		return errors.New(agentUsage)
	}
	var v json.RawMessage
	if err := call(ctx, "GET", u, key, nil, &v); err != nil {
		return err
	}
	_, err := fmt.Fprintln(out, string(v))
	return err
}
