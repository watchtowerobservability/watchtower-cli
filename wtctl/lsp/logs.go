package lsp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"github.com/watchtowerobservability/watchtower-cli/internal/netguard"
)

const (
	cmdOpenLogs = "watchtower.openLogs"
	maxLogSites = 15  // lenses with a lookup each, per file
	logWindow   = 100 // lines fetched per site; the volume shown is capped by it
)

// logCallRe finds logger calls per language (one regex, not a parser; a call split over lines is
// matched on its first line only).
var logCallRe = map[string]*regexp.Regexp{
	".go":   regexp.MustCompile(`\b(?:log|logger|slog|zap|zerolog)\w*\.(?:Debug|Info|Warn|Warning|Error|Fatal|Print|Printf|Println|Debugf|Infof|Warnf|Errorf|InfoContext|WarnContext|ErrorContext)\(`),
	".rs":   regexp.MustCompile(`\b(?:tracing::)?(?:trace|debug|info|warn|error)!\(|\blog::(?:trace|debug|info|warn|error)!\(`),
	".ts":   regexp.MustCompile(`\b(?:console|log|logger)\.(?:debug|info|warn|error|log)\(`),
	".py":   regexp.MustCompile(`\b(?:logging|log|logger|_log)\.(?:debug|info|warning|warn|error|exception|critical)\(`),
	".java": regexp.MustCompile(`\b(?:log|logger|LOG|LOGGER)\.(?:trace|debug|info|warn|error)\(`),
	".cs":   regexp.MustCompile(`\b_?[lL]ogger\.Log(?:Trace|Debug|Information|Warning|Error|Critical)\(`),
	".kt":   regexp.MustCompile(`\b(?:log|logger|LOG|LOGGER)\.(?:trace|debug|info|warn|error)\(|\bprintln\(`),
}

func init() {
	for _, e := range []string{".tsx", ".js", ".jsx", ".mjs"} {
		logCallRe[e] = logCallRe[".ts"]
	}
}

// LogSites returns the 0-based lines of logger calls in text, at most max.
func LogSites(name, text string, max int) []int {
	re := logCallRe[strings.ToLower(filepath.Ext(name))]
	if re == nil {
		return nil
	}
	var out []int
	for i, l := range strings.Split(text, "\n") {
		if re.MatchString(l) {
			if out = append(out, i); len(out) == max {
				break
			}
		}
	}
	return out
}

// LogSite is what the logs API holds for one source line.
type LogSite struct {
	Lines []string // newest first, "severity body"
	Count int      // matched lines in the window (capped at logWindow)
	More  bool
}

type logsReq struct {
	Text  string    `json:"text,omitempty"`
	Attrs []logAttr `json:"attrs"`
	From  string    `json:"from"`
	Limit int       `json:"limit"`
	Svcs  []string  `json:"services"`
}

type logAttr struct {
	Key   string `json:"key"`
	Op    string `json:"op"`
	Value string `json:"value"`
}

// logAttrs matches by the code location the SDKs stamp on log records (code.filepath may be absolute).
func logAttrs(file string, line int) []logAttr {
	return []logAttr{{"code.filepath", "contains", file}, {"code.lineno", "eq", strconv.Itoa(line)}}
}

var litRe = regexp.MustCompile(`"((?:[^"\\]|\\.)+)"|'([^']+)'|\x60([^\x60]+)\x60`)

// Literal is the longest fixed text of the first string literal on a logger line, without format
// verbs and placeholders (%s, %d, {}, {0}, ${x}); "" when under 6 characters. The template fallback
// when records carry no code location.
func Literal(line string) string {
	m := litRe.FindStringSubmatch(line)
	if m == nil {
		return ""
	}
	lit := m[1] + m[2] + m[3]
	best := ""
	for _, part := range placeholderRe.Split(lit, -1) {
		if p := strings.TrimSpace(part); len(p) > len(best) {
			best = p
		}
	}
	if len(best) < 6 {
		return ""
	}
	return best
}

var placeholderRe = regexp.MustCompile(`%[-+# 0-9.]*[a-zA-Z]|\$?\{[^}]*\}|\\.`)

type cached struct {
	at   time.Time
	site LogSite
}

// logTTL keeps one lookup per source line for a minute, as the VS Code extension does.
const logTTL = 60 * time.Second

// LogsAt asks POST /logs/search for the last 24h of records logged at file:line (1-based).
//
// When no record carries the location and lit is not empty, it falls back to records whose body
// contains lit.
func (c *Client) LogsAt(ctx context.Context, project, service, file string, line int, lit string) (LogSite, error) {
	key := fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%s", project, service, file, line, lit)
	c.mu.Lock()
	if e, ok := c.logCache[key]; ok && time.Since(e.at) < logTTL {
		c.mu.Unlock()
		return e.site, nil
	}
	c.mu.Unlock()
	site, err := c.logsAt(ctx, project, service, logAttrs(file, line), "")
	if err == nil && site.Count == 0 && lit != "" {
		site, err = c.logsAt(ctx, project, service, nil, lit)
	}
	if err == nil {
		c.mu.Lock()
		if c.logCache == nil {
			c.logCache = map[string]cached{}
		}
		c.logCache[key] = cached{time.Now(), site}
		c.mu.Unlock()
	}
	return site, err
}

func (c *Client) logsAt(ctx context.Context, project, service string, attrs []logAttr, text string) (LogSite, error) {
	hc := c.HTTP
	if hc == nil {
		hc = netguard.Guarded("wtctl", 10*time.Second)
	}
	b, _ := json.Marshal(logsReq{Text: text, Attrs: attrs, From: time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339),
		Limit: logWindow, Svcs: []string{service}})
	u := strings.TrimSuffix(c.BaseURL, "/") + "/v1/projects/" + url.PathEscape(project) + "/logs/search"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
	if err != nil {
		return LogSite{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return LogSite{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return LogSite{}, fmt.Errorf("logs/search: HTTP %d", resp.StatusCode)
	}
	var r struct {
		Data []struct {
			Body     string `json:"body"`
			Severity string `json:"severity_text"`
		} `json:"data"`
		Next string `json:"next_cursor"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return LogSite{}, err
	}
	s := LogSite{Count: len(r.Data), More: r.Next != ""}
	for _, e := range r.Data {
		s.Lines = append(s.Lines, strings.TrimSpace(e.Severity+" "+truncate(e.Body, 160)))
	}
	return s, nil
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func logsTitle(s LogSite) string {
	plus := ""
	if s.More || s.Count >= logWindow {
		plus = "+"
	}
	return fmt.Sprintf("%d%s log lines/24h", s.Count, plus)
}

// logsURL opens the Logs explorer filtered to one source line (the page reads q as JSON).
func (s *Server) logsURL(project, service, file, line, text string) string {
	n, _ := strconv.Atoi(line)
	f := map[string]any{"services": service, "severities": []string{}, "attrs": logAttrs(file, n)}
	if text != "" { // the template fallback filters on the body instead of the location
		f["attrs"], f["text"] = []logAttr{}, text
	}
	q, _ := json.Marshal(f)
	return strings.TrimSuffix(s.WebURL, "/") + "/projects/" + url.PathEscape(project) + "/logs?q=" + url.QueryEscape(string(q))
}

// logLenses is one lens per logger call that has logged in the last day.
func (s *Server) logLenses(ctx context.Context, d *docInfo) []codeLens {
	out := []codeLens{}
	for _, l := range LogSites(d.rel, d.text, maxLogSites) {
		lit := Literal(strings.Split(d.text, "\n")[l])
		site, err := s.API.LogsAt(ctx, d.project, d.service, d.rel, l+1, lit)
		if err != nil || site.Count == 0 {
			continue
		}
		at := position{Line: l}
		out = append(out, codeLens{Range: lspRange{at, at}, Command: command{
			Title: logsTitle(site), Command: cmdOpenLogs,
			Arguments: []string{d.project, d.service, d.rel, strconv.Itoa(l + 1), lit},
		}})
	}
	return out
}

// logHover lists the latest lines logged at the hovered call, or nil.
func (s *Server) logHover(ctx context.Context, d *docInfo, line int) any {
	for _, l := range LogSites(d.rel, d.text, 1<<30) {
		if l != line {
			continue
		}
		lit := Literal(strings.Split(d.text, "\n")[l])
		site, err := s.API.LogsAt(ctx, d.project, d.service, d.rel, l+1, lit)
		if err != nil || site.Count == 0 {
			return nil
		}
		var b strings.Builder
		fmt.Fprintf(&b, "**%s** at this line", logsTitle(site))
		for _, x := range site.Lines[:min(5, len(site.Lines))] {
			fmt.Fprintf(&b, "\n\n`%s`", strings.ReplaceAll(x, "`", "'"))
		}
		fmt.Fprintf(&b, "\n\n[Open in Logs](%s)", s.logsURL(d.project, d.service, d.rel, strconv.Itoa(l+1), lit))
		return map[string]any{"contents": map[string]string{"kind": "markdown", "value": b.String()}}
	}
	return nil
}
