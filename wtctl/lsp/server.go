// Package lsp is the stdio language server behind `wtctl lsp` (LSP 3.17): production
// latency and error lenses and hovers on functions. It sends only file paths and function
// names to the API, never source text.
package lsp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// Server is one LSP session.
type Server struct {
	API    *Client
	WebURL string // base of issue and trace links; defaults to the API URL

	mu       sync.Mutex // guards docs, root, cfg and writes to out
	out      io.Writer
	docs     map[string]string
	root     string
	cfg      *Config
	shutdown bool
}

// NewServer builds a server writing responses to out.
func NewServer(api *Client, webURL string, out io.Writer) *Server {
	if webURL == "" {
		webURL = api.BaseURL
	}
	return &Server{API: api, WebURL: webURL, out: out, docs: map[string]string{}}
}

type message struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Serve reads framed messages from in until exit or EOF.
func (s *Server) Serve(ctx context.Context, in io.Reader) error {
	r := bufio.NewReader(in)
	for {
		body, err := readFrame(r)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		var m message
		if err := json.Unmarshal(body, &m); err != nil {
			s.reply(nil, nil, &rpcError{-32700, "parse error"})
			continue
		}
		if m.Method == "exit" {
			return nil
		}
		s.handle(ctx, m)
	}
}

func readFrame(r *bufio.Reader) ([]byte, error) {
	n := -1
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if v, ok := strings.CutPrefix(strings.ToLower(line), "content-length:"); ok {
			n, _ = strconv.Atoi(strings.TrimSpace(v))
		}
	}
	if n < 0 || n > 64<<20 {
		return nil, fmt.Errorf("bad Content-Length")
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

func (s *Server) reply(id json.RawMessage, result any, e *rpcError) {
	resp := map[string]any{"jsonrpc": "2.0", "id": id}
	if len(id) == 0 {
		resp["id"] = nil
	}
	if e != nil {
		resp["error"] = e
	} else {
		resp["result"] = result
	}
	b, _ := json.Marshal(resp)
	s.mu.Lock()
	defer s.mu.Unlock()
	fmt.Fprintf(s.out, "Content-Length: %d\r\n\r\n%s", len(b), b)
}

func (s *Server) handle(ctx context.Context, m message) {
	isReq := len(m.ID) > 0
	var (
		res any
		err error
	)
	switch m.Method {
	case "initialize":
		res, err = s.initialize(m.Params)
	case "initialized", "$/cancelRequest", "workspace/didChangeConfiguration":
	case "shutdown":
		s.shutdown = true
		res = nil
	case "textDocument/didOpen":
		var p struct {
			TextDocument struct{ URI, Text string } `json:"textDocument"`
		}
		if json.Unmarshal(m.Params, &p) == nil {
			s.setDoc(p.TextDocument.URI, p.TextDocument.Text)
		}
	case "textDocument/didChange":
		var p struct {
			TextDocument   struct{ URI string }    `json:"textDocument"`
			ContentChanges []struct{ Text string } `json:"contentChanges"`
		}
		// full sync: the last change carries the whole text
		if json.Unmarshal(m.Params, &p) == nil && len(p.ContentChanges) > 0 {
			s.setDoc(p.TextDocument.URI, p.ContentChanges[len(p.ContentChanges)-1].Text)
		}
	case "textDocument/didClose":
		var p struct {
			TextDocument struct{ URI string } `json:"textDocument"`
		}
		if json.Unmarshal(m.Params, &p) == nil {
			s.setDoc(p.TextDocument.URI, "")
		}
	case "textDocument/codeLens":
		res, err = s.codeLens(ctx, m.Params)
	case "textDocument/hover":
		res, err = s.hover(ctx, m.Params)
	case "workspace/executeCommand":
		res, err = s.executeCommand(m.Params)
	default:
		if isReq {
			s.reply(m.ID, nil, &rpcError{-32601, "method not found: " + m.Method})
		}
		return
	}
	if !isReq {
		return
	}
	if err != nil {
		s.reply(m.ID, nil, &rpcError{-32603, err.Error()})
		return
	}
	s.reply(m.ID, res, nil)
}

func (s *Server) setDoc(uri, text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if text == "" {
		delete(s.docs, uri)
		return
	}
	s.docs[uri] = text
}

func (s *Server) initialize(raw json.RawMessage) (any, error) {
	var p struct {
		RootURI  string `json:"rootUri"`
		RootPath string `json:"rootPath"`
	}
	_ = json.Unmarshal(raw, &p)
	root := p.RootPath
	if p.RootURI != "" {
		root = uriPath(p.RootURI)
	}
	cfg, err := LoadConfig(root)
	if err != nil {
		cfg = &Config{} // a broken file disables lenses instead of the whole session
	}
	if v := os.Getenv("WT_PROJECT"); v != "" {
		cfg.Project = v
	}
	s.mu.Lock()
	s.root, s.cfg = root, cfg
	s.mu.Unlock()
	return map[string]any{
		"capabilities": map[string]any{
			"textDocumentSync":       1,
			"codeLensProvider":       map[string]any{"resolveProvider": false},
			"hoverProvider":          true,
			"executeCommandProvider": map[string]any{"commands": []string{cmdOpenIssue, cmdOpenTrace}},
		},
		"serverInfo": map[string]any{"name": "wtctl-lsp"},
	}, nil
}

func uriPath(uri string) string {
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "file" {
		return uri
	}
	p := u.Path
	// file:///C:/x (or c%3A) decodes to /C:/x; drop the slash so Windows sees a drive path.
	if len(p) > 2 && p[0] == '/' && p[2] == ':' {
		p = p[1:]
	}
	return filepath.FromSlash(p)
}

// docInfo is a mapped document: its text, service and repo-relative path.
type docInfo struct {
	text, service, rel, project string
	funcs                       []Func
}

// mapped returns the document for uri, or nil when it maps to no service or has no functions.
func (s *Server) mapped(uri string) *docInfo {
	s.mu.Lock()
	root, cfg, text, open := s.root, s.cfg, s.docs[uri], false
	_, open = s.docs[uri]
	s.mu.Unlock()
	if cfg == nil || root == "" || cfg.Project == "" {
		return nil
	}
	p := uriPath(uri)
	rel, err := filepath.Rel(root, p)
	if err != nil || strings.HasPrefix(rel, "..") {
		return nil
	}
	rel = filepath.ToSlash(rel)
	svc, ok := cfg.ServiceFor(rel)
	if !ok {
		return nil
	}
	if !open {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		text = string(b)
	}
	fs := Functions(rel, text)
	if len(fs) == 0 {
		return nil
	}
	return &docInfo{text: text, service: svc, rel: rel, project: cfg.Project, funcs: fs}
}

func (s *Server) stats(ctx context.Context, d *docInfo) (map[string]Stat, error) {
	names := make([]string, len(d.funcs))
	for i, f := range d.funcs {
		names[i] = f.Name
	}
	return s.API.CodeStats(ctx, d.project, d.service, d.rel, names)
}
