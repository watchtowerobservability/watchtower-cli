package ascode

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// errUnresolved marks a create that names a resource this run has not created yet (a dry run cannot ask
// the server about it).
var errUnresolved = errors.New("depends on a resource that does not exist yet")

// saKeyOps maps `kind: ServiceAccountKey` onto /v1/orgs/{org}/service-accounts/{id}/keys. The manifest
// name is "<service account name>/<key name>"; the spec is the key request without its name:
// {scopes | preset, expires_in_days?, project_id?, env_id?}. A key that exists is left alone (its
// secret is gone), so the kind is create only; revoked keys do not count.
type saKeyOps struct{}

func splitSaKey(name string) (account, key string, err error) {
	account, key, ok := strings.Cut(name, "/")
	if !ok || account == "" || key == "" {
		return "", "", fmt.Errorf("ServiceAccountKey %q: name must be <service account>/<key name>", name)
	}
	return account, key, nil
}

// accountID is the id of the live service account called name.
func (saKeyOps) accountID(ctx context.Context, c *Client, name string) (string, error) {
	accounts, err := c.List(ctx, ByKind("ServiceAccount"))
	if err != nil {
		return "", err
	}
	a, ok := accounts[name]
	if !ok {
		return "", fmt.Errorf("service account %q: %w", name, errUnresolved)
	}
	return a.Ref, nil
}

func (o saKeyOps) list(ctx context.Context, c *Client) (map[string]Item, error) {
	accounts, err := c.List(ctx, ByKind("ServiceAccount"))
	if err != nil {
		return nil, err
	}
	out := map[string]Item{}
	for account, a := range accounts {
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
			if err := c.do(ctx, http.MethodGet, "/v1/orgs/{org}/service-accounts/"+url.PathEscape(a.Ref)+"/keys"+q, nil, &page); err != nil {
				return nil, err
			}
			for _, b := range page.Data {
				name, _ := b["name"].(string)
				id, _ := b["id"].(string)
				if name == "" || id == "" || b["revoked_at"] != nil {
					continue
				}
				full := account + "/" + name
				out[full] = Item{Ref: id, Name: full, Body: b}
			}
			if page.NextCursor == nil || *page.NextCursor == "" {
				break
			}
			cursor = *page.NextCursor
		}
	}
	return out, nil
}

func (o saKeyOps) create(ctx context.Context, c *Client, name string, spec map[string]any) (map[string]any, error) {
	account, key, err := splitSaKey(name)
	if err != nil {
		return nil, err
	}
	id, err := o.accountID(ctx, c, account)
	if err != nil {
		return nil, err
	}
	body := make(map[string]any, len(spec)+1)
	for k, v := range spec {
		body[k] = v
	}
	body["name"] = key
	var out map[string]any
	err = c.do(ctx, http.MethodPost, "/v1/orgs/{org}/service-accounts/"+url.PathEscape(id)+"/keys", body, &out)
	return out, err
}

// update never runs for a create-only kind; it is the create for safety.
func (o saKeyOps) update(ctx context.Context, c *Client, _ Item, name string, spec map[string]any) (map[string]any, error) {
	return o.create(ctx, c, name, spec)
}

func (o saKeyOps) remove(ctx context.Context, c *Client, it Item) error {
	account, _, err := splitSaKey(it.Name)
	if err != nil {
		return err
	}
	id, err := o.accountID(ctx, c, account)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodDelete, "/v1/orgs/{org}/service-accounts/"+url.PathEscape(id)+"/keys/"+url.PathEscape(it.Ref), nil, nil)
}
