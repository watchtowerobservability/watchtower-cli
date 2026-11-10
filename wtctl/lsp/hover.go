package lsp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

func (s *Server) issueURL(project, id string) string {
	return strings.TrimSuffix(s.WebURL, "/") + "/projects/" + url.PathEscape(project) + "/issues/" + url.PathEscape(id)
}

func (s *Server) traceURL(project, id string) string {
	return strings.TrimSuffix(s.WebURL, "/") + "/projects/" + url.PathEscape(project) + "/traces/" + url.PathEscape(id)
}

func (s *Server) hover(ctx context.Context, raw json.RawMessage) (any, error) {
	var p struct {
		TextDocument struct{ URI string } `json:"textDocument"`
		Position     position             `json:"position"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	d := s.mapped(p.TextDocument.URI)
	if d == nil {
		return nil, nil
	}
	var fn *Func
	for i := range d.funcs {
		if d.funcs[i].Line == p.Position.Line {
			fn = &d.funcs[i]
		}
	}
	if fn == nil {
		return s.logHover(ctx, d, p.Position.Line), nil
	}
	stats, err := s.stats(ctx, d)
	if err != nil {
		return nil, nil
	}
	st, ok := stats[fn.Name]
	if !ok {
		return nil, nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "**%s** (last 24h): %d calls, p50 %.0f ms, p95 %.0f ms, %d errors", fn.Name, st.Count, st.P50Ms, st.P95Ms, st.Errors)
	if st.LastIssue != nil {
		fmt.Fprintf(&b, "\n\nLatest issue: [%s](%s)", st.LastIssue.Title, s.issueURL(d.project, st.LastIssue.ID))
	}
	if st.TraceExample != "" {
		fmt.Fprintf(&b, "\n\n[Slowest trace](%s)", s.traceURL(d.project, st.TraceExample))
	}
	return map[string]any{"contents": map[string]string{"kind": "markdown", "value": b.String()}}, nil
}

// executeCommand returns the URL for the client to open: arguments are [project, id].
func (s *Server) executeCommand(raw json.RawMessage) (any, error) {
	var p struct {
		Command   string   `json:"command"`
		Arguments []string `json:"arguments"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	if p.Command == cmdOpenLogs && len(p.Arguments) >= 4 && len(p.Arguments) <= 5 {
		lit := ""
		if len(p.Arguments) == 5 {
			lit = p.Arguments[4]
		}
		return s.logsURL(p.Arguments[0], p.Arguments[1], p.Arguments[2], p.Arguments[3], lit), nil
	}
	if len(p.Arguments) != 2 {
		return nil, fmt.Errorf("%s needs [project, id]", p.Command)
	}
	switch p.Command {
	case cmdOpenIssue:
		return s.issueURL(p.Arguments[0], p.Arguments[1]), nil
	case cmdOpenTrace:
		return s.traceURL(p.Arguments[0], p.Arguments[1]), nil
	}
	return nil, fmt.Errorf("unknown command %q", p.Command)
}
