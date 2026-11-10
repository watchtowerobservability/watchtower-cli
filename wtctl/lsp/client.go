package lsp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"github.com/watchtowerobservability/watchtower-cli/internal/netguard"
)

// Stat mirrors one entry of GET /v1/projects/{p}/code-stats.
type Stat struct {
	Function  string  `json:"function"`
	Count     uint64  `json:"count"`
	Errors    uint64  `json:"errors"`
	P50Ms     float64 `json:"p50_ms"`
	P95Ms     float64 `json:"p95_ms"`
	LastIssue *struct {
		ID    string `json:"id"`
		Title string `json:"title"`
	} `json:"last_issue"`
	TraceExample string `json:"trace_example"`
}

// Client calls the Watchtower API. It sends only the service, file path and function names.
type Client struct {
	BaseURL string // WT_API_URL
	Key     string // WT_API_KEY
	HTTP    *http.Client

	mu       sync.Mutex
	logCache map[string]cached
}

// maxFuncs is the API limit per request.
const maxFuncs = 50

// CodeStats returns stats by function name; functions with no data are absent.
func (c *Client) CodeStats(ctx context.Context, project, service, file string, funcs []string) (map[string]Stat, error) {
	out := map[string]Stat{}
	hc := c.HTTP
	if hc == nil {
		hc = netguard.Guarded("wtctl", 10*time.Second)
	}
	for len(funcs) > 0 {
		n := min(len(funcs), maxFuncs)
		q := url.Values{"service": {service}, "file": {file}, "functions": {strings.Join(funcs[:n], ",")}}
		funcs = funcs[n:]
		u := strings.TrimSuffix(c.BaseURL, "/") + "/v1/projects/" + url.PathEscape(project) + "/code-stats?" + q.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.Key)
		resp, err := hc.Do(req)
		if err != nil {
			return nil, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("code-stats: HTTP %d", resp.StatusCode)
		}
		var r struct {
			Data []Stat `json:"data"`
		}
		if err := json.Unmarshal(body, &r); err != nil {
			return nil, err
		}
		for _, s := range r.Data {
			out[s.Function] = s
		}
	}
	return out, nil
}
