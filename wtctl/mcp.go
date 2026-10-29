package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const mcpUsage = "usage: wtctl mcp serve --stdio --url <https://host/mcp> --key <wtk_...> --project <id> [--toolset triage|logs|traces|llm|health|...|all]   (stdio proxy to the hosted MCP endpoint; --url defaults to $WT_MCP_URL)\n       wtctl mcp key-ref --key <wtk_...>   (the id to pass to PUT /v1/projects/{p}/mcp/keys/{key_ref}/toolsets)\n       wtctl mcp skills install [--dir .claude/skills]   (write the published agent skill files)"

// mcpKeyRef is the non-secret key id the server derives (first 8 bytes of SHA-256, hex).
func mcpKeyRef(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:8])
}

// mcpMain proxies an IDE agent's stdio MCP session to the hosted endpoint. The key stays in this
// process and is only sent to --url.
func mcpMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) >= 1 && args[0] == "key-ref" {
		fs := flag.NewFlagSet("mcp key-ref", flag.ContinueOnError)
		key := fs.String("key", os.Getenv("WT_API_KEY"), "API key (wtk_...)")
		if err := fs.Parse(args[1:]); err != nil || *key == "" {
			return errors.New(mcpUsage)
		}
		_, err := io.WriteString(out, mcpKeyRef(*key)+"\n")
		return err
	}
	if len(args) >= 1 && args[0] == "skills" {
		return skillsMain(args[1:], out)
	}
	if len(args) < 1 || args[0] != "serve" {
		return errors.New(mcpUsage)
	}
	fs := flag.NewFlagSet("mcp serve", flag.ContinueOnError)
	var endpoint, key, project, toolset string
	var stdio bool
	fs.BoolVar(&stdio, "stdio", false, "serve over stdin/stdout (required)")
	fs.StringVar(&endpoint, "url", os.Getenv("WT_MCP_URL"), "hosted MCP endpoint (https://host/mcp)")
	fs.StringVar(&key, "key", os.Getenv("WT_API_KEY"), "API key (wtk_...)")
	fs.StringVar(&project, "project", "", "project id")
	fs.StringVar(&toolset, "toolset", "all", "triage, logs, traces, llm or all")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if !stdio || endpoint == "" || key == "" || project == "" {
		return errors.New(mcpUsage)
	}
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("mcp: --url must be an http(s) URL")
	}
	q := u.Query()
	q.Set("project", project)
	q.Set("toolset", toolset)
	u.RawQuery = q.Encode()
	return mcpProxy(ctx, u.String(), key, os.Stdin, out)
}

// mcpProxy forwards each newline-delimited JSON-RPC message to the endpoint (streamable HTTP) and
// writes the reply messages to out.
// shortcut: sequential, no server-initiated requests or resumable streams; fine for tool calls,
// revisit if the hosted server starts to push.
func mcpProxy(ctx context.Context, endpoint, key string, in io.Reader, out io.Writer) error {
	hc := &http.Client{Timeout: 5 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64<<10), 8<<20)
	var session string
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(line))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if session != "" {
			req.Header.Set("Mcp-Session-Id", session)
		}
		resp, err := hc.Do(req)
		if err != nil {
			return errors.New("mcp: " + strings.ReplaceAll(err.Error(), key, "***"))
		}
		if id := resp.Header.Get("Mcp-Session-Id"); id != "" {
			session = id
		}
		err = mcpReply(resp, out)
		resp.Body.Close()
		if err != nil {
			return err
		}
	}
	return sc.Err()
}

func mcpReply(resp *http.Response, out io.Writer) error {
	if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("mcp: the endpoint answered %s", resp.Status)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "%s\n", bytes.TrimSpace(b))
		return err
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 8<<20)
	for sc.Scan() {
		if d, ok := strings.CutPrefix(sc.Text(), "data:"); ok {
			if _, err := fmt.Fprintf(out, "%s\n", strings.TrimSpace(d)); err != nil {
				return err
			}
		}
	}
	return sc.Err()
}
