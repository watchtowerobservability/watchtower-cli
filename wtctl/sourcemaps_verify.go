package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// sourcemapsVerify asks the API whether a minified position of a release resolves to its original
// source; it prints the position, or the reason and returns an error so CI can fail on it.
func sourcemapsVerify(ctx context.Context, args []string, out io.Writer) error {
	var o artifactOpts
	fs := flag.NewFlagSet("sourcemaps verify", flag.ContinueOnError)
	o.flags(fs)
	script := fs.String("url", "", "URL or path of the minified script")
	line := fs.Int("line", 0, "one-based line in the minified script")
	col := fs.Int("column", 0, "one-based column in the minified script")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := o.check(); err != nil {
		return err
	}
	if o.release == "" || *script == "" || *line < 1 || *col < 1 {
		return errors.New("--release, --url, --line (>= 1) and --column (>= 1) are required")
	}
	return verifyResolve(ctx, o, *script, *line, *col, out)
}

func verifyResolve(ctx context.Context, o artifactOpts, script string, line, col int, out io.Writer) error {
	var r struct {
		Source *string `json:"source"`
		Line   *int    `json:"line"`
		Column *int    `json:"column"`
		Name   *string `json:"name"`
		Reason *string `json:"reason"`
	}
	endpoint := strings.TrimRight(o.api, "/") + "/v1/projects/" + url.PathEscape(o.project) + "/artifacts/resolve"
	body := map[string]any{"release": o.release, "url": script, "line": line, "column": col}
	if err := call(ctx, http.MethodPost, endpoint, o.key, body, &r); err != nil {
		return err
	}
	if r.Reason != nil || r.Source == nil || r.Line == nil || r.Column == nil {
		reason := "unknown"
		if r.Reason != nil {
			reason = *r.Reason
		}
		return fmt.Errorf("%s:%d:%d does not resolve in release %s: %s", script, line, col, o.release, reason)
	}
	name := ""
	if r.Name != nil {
		name = " (" + *r.Name + ")"
	}
	fmt.Fprintf(out, "%s:%d:%d -> %s:%d:%d%s\n", script, line, col, *r.Source, *r.Line, *r.Column, name)
	return nil
}
