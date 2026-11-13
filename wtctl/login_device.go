package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Device login (RFC 8628 style): `wtctl login` without a key asks the API for a device code, prints
// a URL and a short code for the user to approve in the web app (where they pick the token's
// scopes), then polls until the API hands over a short-lived personal access token.

type deviceStart struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type devicePoll struct {
	Status    string   `json:"status"`
	Token     string   `json:"token"`
	TokenID   string   `json:"token_id"`
	Scopes    []string `json:"scopes"`
	ExpiresAt string   `json:"expires_at"`
}

// absURL resolves a path the server returned (no public address configured) against the API URL.
func absURL(api, u string) string {
	if strings.HasPrefix(u, "/") {
		return strings.TrimRight(api, "/") + u
	}
	return u
}

// deviceLogin runs the flow against api and returns the approved token. wait sleeps between polls.
func deviceLogin(ctx context.Context, api, scope string, out io.Writer, wait func(time.Duration)) (devicePoll, error) {
	api = strings.TrimRight(api, "/")
	body := map[string]any{}
	if scope != "" {
		body["scope"] = scope
	}
	var d deviceStart
	// The device endpoints take no credential; the bearer is empty.
	if err := call(ctx, http.MethodPost, api+"/v1/auth/device", "", body, &d); err != nil {
		return devicePoll{}, err
	}
	fmt.Fprintf(out, "Open %s\nand confirm the code %s (sign in first if asked).\nWaiting for approval...\n",
		absURL(api, d.VerificationURIComplete), d.UserCode)
	interval := time.Duration(max(d.Interval, 1)) * time.Second
	deadline := time.Now().Add(time.Duration(d.ExpiresIn) * time.Second)
	for time.Now().Before(deadline) {
		wait(interval)
		var p devicePoll
		err := call(ctx, http.MethodPost, api+"/v1/auth/device/token", "", map[string]string{"device_code": d.DeviceCode}, &p)
		switch {
		case err != nil && strings.Contains(err.Error(), " 404 "):
			return p, errors.New("the login code expired or was already used; run wtctl login again")
		case err != nil && strings.Contains(err.Error(), " 429 "):
			interval += 5 * time.Second // slow down
			continue
		case err != nil:
			return p, err
		}
		switch p.Status {
		case "approved":
			return p, nil
		case "denied":
			return p, errors.New("the login was denied")
		}
	}
	return devicePoll{}, errors.New("timed out waiting for approval; run wtctl login again")
}

// logoutMain forgets a context (default: the current one) and, when its token came from a device
// login, asks the API to revoke it. A bootstrap token cannot revoke itself; that failure is only
// reported, the local copy is removed regardless.
func logoutMain(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("logout", flag.ContinueOnError)
	name := fs.String("context", "", "context name (default: the current one)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, p, err := loadConfig()
	if err != nil {
		return err
	}
	if *name == "" {
		*name = c.Current
	}
	sel, ok := c.Contexts[*name]
	if !ok {
		return errors.New("no context to log out of (wtctl context list)")
	}
	if sel.TokenID != "" {
		if err := call(ctx, http.MethodDelete, sel.API+"/v1/me/tokens/"+sel.TokenID, sel.Key, nil, nil); err != nil {
			fmt.Fprintln(out, "could not revoke the token on the server (revoke it under Settings, Personal access tokens):", err)
		} else {
			fmt.Fprintln(out, "token revoked")
		}
	}
	delete(c.Contexts, *name)
	if c.Current == *name {
		c.Current = ""
	}
	if err := saveConfig(c, p); err != nil {
		return err
	}
	fmt.Fprintf(out, "context %q removed from %s\n", *name, p)
	return nil
}
