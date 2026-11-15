package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func routingTest(ctx context.Context, args []string, out io.Writer) error {
	var o rulesOpts
	fs := o.flags("routing test")
	o.api, o.project = apiEnv(), os.Getenv("WT_PROJECT")
	lbl := fs.String("labels", "", "alert labels, k=v,k=v")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if o.api == "" || o.key == "" || o.project == "" || *lbl == "" {
		return errors.New("usage: wtctl routing test --labels k=v,... --api <url> --key <key> --project <id>")
	}
	labels := map[string]string{}
	for _, kv := range strings.Split(*lbl, ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return fmt.Errorf("bad label %q, want k=v", kv)
		}
		labels[strings.TrimSpace(k)] = v
	}
	base := strings.TrimRight(o.api, "/") + "/v1/projects/" + url.PathEscape(o.project)
	var res struct {
		Matches []struct {
			RouteID    string   `json:"route_id"`
			ReceiverID string   `json:"receiver_id"`
			Hint       string   `json:"hint"`
			Path       []string `json:"path"`
		}
	}
	if err := call(ctx, http.MethodPost, base+"/routing:test", o.key, map[string]any{"labels": labels}, &res); err != nil {
		return err
	}
	if len(res.Matches) == 0 {
		fmt.Fprintln(out, "no route matches: the alert is dropped")
	}
	names := receiverNames(ctx, base, o.key)
	for _, m := range res.Matches {
		who := m.ReceiverID
		if n := names[m.ReceiverID]; n != "" {
			who = n + " (" + m.ReceiverID + ")"
		}
		if who == "" {
			who = "none: " + m.Hint
		}
		fmt.Fprintf(out, "route %s -> receiver %s\n", m.RouteID, who)
	}
	return nil
}

func receiverNames(ctx context.Context, base, key string) map[string]string {
	var r struct{ Data []struct{ ID, Name string } }
	names := map[string]string{}
	if call(ctx, http.MethodGet, base+"/receivers?limit=200", key, nil, &r) == nil {
		for _, x := range r.Data {
			names[x.ID] = x.Name
		}
	}
	return names
}
