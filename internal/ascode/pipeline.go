package ascode

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// pipelineOps maps `kind: Pipeline` onto the pipeline API. The manifest spec is
// {signal, description?, config, tests?}: the live body is the pipeline plus its ACTIVE version's
// config and tests, so a no-change apply writes nothing; a change creates a new version (the API
// runs its tests; a failure is a 422 and nothing is activated) and activates it.
type pipelineOps struct{}

func (pipelineOps) list(ctx context.Context, c *Client) (map[string]Item, error) {
	out := map[string]Item{}
	cursor := ""
	for {
		var page struct {
			Data       []map[string]any `json:"data"`
			NextCursor *string          `json:"next_cursor"`
		}
		q := "?limit=200"
		if cursor != "" {
			q += "&cursor=" + url.QueryEscape(cursor)
		}
		if err := c.do(ctx, http.MethodGet, "pipelines"+q, nil, &page); err != nil {
			return nil, err
		}
		for _, p := range page.Data {
			name, _ := p["name"].(string)
			id, _ := p["id"].(string)
			body := map[string]any{"signal": p["signal"], "description": p["description"]}
			if n, ok := p["active_version"].(float64); ok {
				var v map[string]any
				if err := c.do(ctx, http.MethodGet, fmt.Sprintf("pipelines/%s/versions/%d", url.PathEscape(id), int(n)), nil, &v); err != nil {
					return nil, err
				}
				body["config"], body["tests"] = v["config"], v["tests"]
			}
			out[name] = Item{Ref: id, Name: name, Body: body}
		}
		if page.NextCursor == nil || *page.NextCursor == "" {
			return out, nil
		}
		cursor = *page.NextCursor
	}
}

func (pipelineOps) create(ctx context.Context, c *Client, name string, spec map[string]any) (map[string]any, error) {
	signal, _ := spec["signal"].(string)
	if signal == "" {
		return nil, errors.New("spec.signal is required")
	}
	head := map[string]any{"signal": signal, "name": name}
	if d, ok := spec["description"]; ok {
		head["description"] = d
	}
	var made map[string]any
	if err := c.do(ctx, http.MethodPost, "pipelines", head, &made); err != nil {
		return nil, err
	}
	id, _ := made["id"].(string)
	return publish(ctx, c, id, spec)
}

func (pipelineOps) update(ctx context.Context, c *Client, it Item, name string, spec map[string]any) (map[string]any, error) {
	if s, _ := spec["signal"].(string); s != "" && s != it.Body["signal"] {
		return nil, fmt.Errorf("pipeline %q: the signal cannot change (delete and recreate it)", name)
	}
	if d, ok := spec["description"]; ok && d != it.Body["description"] {
		if err := c.do(ctx, http.MethodPatch, "pipelines/"+url.PathEscape(it.Ref), map[string]any{"description": d}, nil); err != nil {
			return nil, err
		}
	}
	return publish(ctx, c, it.Ref, spec)
}

// publish adds a version from spec.config (and spec.tests) and activates it.
func publish(ctx context.Context, c *Client, id string, spec map[string]any) (map[string]any, error) {
	cfg, ok := spec["config"]
	if !ok {
		return nil, nil
	}
	base := "pipelines/" + url.PathEscape(id)
	body := map[string]any{"config": cfg, "note": "wtctl apply"}
	if t, ok := spec["tests"]; ok {
		body["tests"] = t
	}
	var v map[string]any
	if err := c.do(ctx, http.MethodPost, base+"/versions", body, &v); err != nil {
		return nil, err
	}
	var out map[string]any
	err := c.do(ctx, http.MethodPost, base+"/activate", map[string]any{"version": v["version"]}, &out)
	return out, err
}

func (pipelineOps) remove(ctx context.Context, c *Client, it Item) error {
	return c.do(ctx, http.MethodDelete, "pipelines/"+url.PathEscape(it.Ref), nil, nil)
}
