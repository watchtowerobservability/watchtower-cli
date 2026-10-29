package lsp

import (
	"context"
	"encoding/json"
	"fmt"
)

const (
	cmdOpenIssue = "watchtower.openIssue"
	cmdOpenTrace = "watchtower.openTrace"
)

type position struct {
	Line      int `json:"line"`
	Character int `json:"character"`
}

type lspRange struct {
	Start position `json:"start"`
	End   position `json:"end"`
}

type command struct {
	Title     string   `json:"title"`
	Command   string   `json:"command"`
	Arguments []string `json:"arguments,omitempty"`
}

type codeLens struct {
	Range   lspRange `json:"range"`
	Command command  `json:"command"`
}

// lensTitle renders "p95 120 ms · 4 errors/24h".
func lensTitle(s Stat) string {
	return fmt.Sprintf("p95 %.0f ms · %d errors/24h", s.P95Ms, s.Errors)
}

// lensCommand opens the latest issue when there is one, else the example trace.
func (s *Server) lensCommand(d *docInfo, st Stat) command {
	c := command{Title: lensTitle(st)}
	switch {
	case st.LastIssue != nil:
		c.Command, c.Arguments = cmdOpenIssue, []string{d.project, st.LastIssue.ID}
	case st.TraceExample != "":
		c.Command, c.Arguments = cmdOpenTrace, []string{d.project, st.TraceExample}
	}
	return c
}

func (s *Server) codeLens(ctx context.Context, raw json.RawMessage) (any, error) {
	var p struct {
		TextDocument struct{ URI string } `json:"textDocument"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	lenses := []codeLens{}
	d := s.mapped(p.TextDocument.URI)
	if d == nil {
		return lenses, nil // unmapped files get no lens
	}
	stats, err := s.stats(ctx, d)
	if err != nil {
		return lenses, nil // an unreachable API must not break the editor
	}
	for _, f := range d.funcs {
		st, ok := stats[f.Name]
		if !ok {
			continue
		}
		at := position{Line: f.Line}
		lenses = append(lenses, codeLens{Range: lspRange{at, at}, Command: s.lensCommand(d, st)})
	}
	return lenses, nil
}
