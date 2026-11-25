package ascode

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// checkSchemas validates the body every create/update in out would send against the request-body
// schema of the API's OpenAPI document, so a manifest the API would 422 fails Plan before any write.
// A server without the document, or a path the document does not know, is skipped (older servers).
func (c *Client) checkSchemas(ctx context.Context, out []Change) error {
	var problems []string
	for _, ch := range out {
		if (ch.Op != OpCreate && ch.Op != OpUpdate) || ch.doc == nil {
			continue
		}
		k := ByKind(ch.Kind)
		if k.ops != nil {
			continue
		}
		spec, err := c.resolveRefs(k, localSpec(k, ch.doc.Spec), false)
		if err != nil {
			continue // Plan reports reference errors itself
		}
		body := withName(k, ch.Name, spec)
		if ch.Op == OpUpdate && !k.Singleton {
			for _, f := range k.UpdateOmit {
				delete(body, f)
			}
		}
		method, tmpl := route(k, ch.Op)
		schema := c.requestSchema(ctx, method, tmpl)
		if schema == nil {
			continue
		}
		var norm any // what the API sees: JSON, not Go ints
		if b, err := json.Marshal(body); err == nil {
			_ = json.Unmarshal(b, &norm)
		}
		skip := map[string]bool{} // a reference to a resource created in this run has no id yet
		for _, r := range k.Refs {
			skip[r.to()[strings.LastIndex(r.to(), ".")+1:]] = true
		}
		v := schemaCheck{doc: c.openapi, skip: skip}
		for _, p := range v.check(schema, norm, "", 0) {
			problems = append(problems, fmt.Sprintf("%s/%s: %s", ch.Kind, ch.Name, p))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("the API schema rejects the manifests (nothing was written):\n  %s", strings.Join(problems, "\n  "))
	}
	return nil
}

// route is the method and OpenAPI path template Create or Update sends op to.
func route(k *Kind, op string) (method, tmpl string) {
	method, tmpl = http.MethodPost, k.Path
	switch {
	case op == OpCreate && k.ByName:
		method, tmpl = http.MethodPut, k.Path+"/{name}"
	case k.Singleton:
		method = k.updateMethod()
	case op == OpUpdate:
		method, tmpl = k.updateMethod(), k.Path+"/{id}"
	}
	if !strings.HasPrefix(tmpl, "/v1/") {
		tmpl = "/v1/projects/{prj}/" + tmpl
	}
	return method, tmpl
}

// dropReadOnly removes the top-level fields of an exported spec that the create body does not accept (read-only
// response fields such as an SLO's `kind` or rule ids), so the export applies as written.
func (c *Client) dropReadOnly(ctx context.Context, k *Kind, d *Doc) {
	if k.ops != nil {
		return
	}
	m, t := route(k, OpCreate)
	s := c.requestSchema(ctx, m, t)
	for i := 0; i < 8 && s != nil; i++ { // follow a top-level $ref
		ref, _ := s["$ref"].(string)
		if ref == "" {
			break
		}
		var cur any = c.openapi
		for _, seg := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
			m, _ := cur.(map[string]any)
			cur = m[seg]
		}
		s, _ = cur.(map[string]any)
	}
	props, _ := s["properties"].(map[string]any)
	if s == nil || s["additionalProperties"] != false || props == nil {
		return
	}
	for f := range d.Spec {
		if _, ok := props[f]; !ok {
			delete(d.Spec, f)
		}
	}
}

// requestSchema returns the JSON request-body schema of method on the path template, or nil.
func (c *Client) requestSchema(ctx context.Context, method, tmpl string) map[string]any {
	if !c.openapiTried {
		c.openapiTried = true
		c.openapi = c.fetchOpenAPI(ctx)
	}
	paths, _ := c.openapi["paths"].(map[string]any)
	want := strings.Split(tmpl, "/")
	best, bestWild := map[string]any(nil), 1<<30
	for p, item := range paths {
		got := strings.Split(p, "/")
		if len(got) != len(want) {
			continue
		}
		wild, ok := 0, true
		for i := range got {
			gw, ww := strings.HasPrefix(got[i], "{"), strings.HasPrefix(want[i], "{")
			if gw || ww {
				wild++
			} else if got[i] != want[i] {
				ok = false
				break
			}
		}
		op, _ := item.(map[string]any)[strings.ToLower(method)].(map[string]any)
		if ok && op != nil && wild < bestWild {
			best, bestWild = op, wild
		}
	}
	rb, _ := best["requestBody"].(map[string]any)
	content, _ := rb["content"].(map[string]any)
	js, _ := content["application/json"].(map[string]any)
	s, _ := js["schema"].(map[string]any)
	return s
}

func (c *Client) fetchOpenAPI(ctx context.Context) map[string]any {
	if c.API == nil || c.API.Client == nil {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.API.Server, "/")+"/openapi.json", nil)
	if err != nil {
		return nil
	}
	resp, err := c.API.Client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var doc map[string]any
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&doc) != nil {
		return nil
	}
	return doc
}

type schemaCheck struct {
	doc  map[string]any
	skip map[string]bool
}

// check returns "field: reason" lines for val against schema (shortcut: types of scalars are not checked).
func (v schemaCheck) check(schema map[string]any, val any, path string, depth int) []string {
	if depth > 24 {
		return nil
	}
	if ref, _ := schema["$ref"].(string); ref != "" {
		var cur any = v.doc
		for _, seg := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
			m, _ := cur.(map[string]any)
			cur = m[seg]
		}
		s, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		return v.check(s, val, path, depth+1)
	}
	at := func(p string) string {
		if p == "" {
			return "(body)"
		}
		return p
	}
	var out []string
	// shortcut: oneOf/anyOf are not checked, because the published schema can lag the server (a `domain` monitor's
	// config matches no variant); check them once every variant is generated from the server's types.
	if all, _ := schema["allOf"].([]any); len(all) > 0 {
		for _, b := range all {
			bm, _ := b.(map[string]any)
			out = append(out, v.check(bm, val, path, depth+1)...)
		}
	}
	if val == nil {
		return out
	}
	if en, _ := schema["enum"].([]any); len(en) > 0 {
		found := false
		for _, e := range en {
			if fmt.Sprint(e) == fmt.Sprint(val) {
				found = true
			}
		}
		if !found {
			out = append(out, fmt.Sprintf("%s: %s is not one of %s", at(path), short(val), short(en)))
		}
	}
	switch x := val.(type) {
	case map[string]any:
		props, _ := schema["properties"].(map[string]any)
		extra := schema["additionalProperties"]
		keys := make([]string, 0, len(x))
		for f := range x {
			keys = append(keys, f)
		}
		sort.Strings(keys)
		for _, f := range keys {
			sub := joinPath(path, f)
			if ps, ok := props[f].(map[string]any); ok {
				out = append(out, v.check(ps, x[f], sub, depth+1)...)
			} else if es, ok := extra.(map[string]any); ok {
				out = append(out, v.check(es, x[f], sub, depth+1)...)
			} else if extra == false {
				out = append(out, sub+": unknown field")
			}
		}
		req, _ := schema["required"].([]any)
		for _, r := range req {
			if f, _ := r.(string); f != "" && !v.skip[f] {
				if _, ok := x[f]; !ok {
					out = append(out, joinPath(path, f)+": required")
				}
			}
		}
	case []any:
		if items, ok := schema["items"].(map[string]any); ok {
			for i, el := range x {
				out = append(out, v.check(items, el, fmt.Sprintf("%s[%d]", path, i), depth+1)...)
			}
		}
	}
	return out
}

func joinPath(path, f string) string {
	if path == "" {
		return f
	}
	return path + "." + f
}
