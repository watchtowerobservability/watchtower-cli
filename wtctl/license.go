package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const licenseUsage = "usage: wtctl license verify --file <licence.json> --pubkey <base64url ed25519 key> [--now <unix>]"

type licensePayload struct {
	Org          string          `json:"org"`
	Entitlements json.RawMessage `json:"entitlements"`
	NotAfter     int64           `json:"not_after"`
}

// verifyLicense checks the offline licence file format of crates/wt-auth/src/license.rs:
// {"payload": b64url(JSON), "signature": b64url(Ed25519 over the payload bytes)}.
func verifyLicense(file []byte, pub ed25519.PublicKey) (licensePayload, error) {
	var f struct{ Payload, Signature string }
	var p licensePayload
	if err := json.Unmarshal(file, &f); err != nil {
		return p, errors.New("licence file is malformed")
	}
	payload, e1 := base64.RawURLEncoding.DecodeString(f.Payload)
	sig, e2 := base64.RawURLEncoding.DecodeString(f.Signature)
	if e1 != nil || e2 != nil {
		return p, errors.New("licence file is malformed")
	}
	if !ed25519.Verify(pub, payload, sig) {
		return p, errors.New("licence signature does not verify")
	}
	return p, json.Unmarshal(payload, &p)
}

// licenseMain is `wtctl license verify`.
func licenseMain(_ context.Context, args []string, out io.Writer) error {
	if len(args) < 1 || args[0] != "verify" {
		return errors.New(licenseUsage)
	}
	fs := flag.NewFlagSet("license verify", flag.ContinueOnError)
	file := fs.String("file", "", "licence file")
	pubS := fs.String("pubkey", "", "base64url Ed25519 public key")
	now := fs.Int64("now", time.Now().Unix(), "unix time to check expiry against")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	raw, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	pub, err := base64.RawURLEncoding.DecodeString(*pubS)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("--pubkey must be base64url of a 32-byte Ed25519 key")
	}
	p, err := verifyLicense(raw, pub)
	if err != nil {
		return err
	}
	state := "valid"
	if p.NotAfter < *now {
		state = "expired (free entitlements apply; ingest unaffected)"
	}
	_, err = fmt.Fprintf(out, "org=%s state=%s not_after=%d\n", p.Org, state, p.NotAfter)
	return err
}

// adminMain is `wtctl admin plans list|put <name> --entitlements <json>`; it talks to the
// internal listener with X-WT-Internal-Token.
func adminMain(ctx context.Context, args []string, out io.Writer) error {
	const usage = "usage: wtctl admin plans list|put <name> --entitlements <json> --api <internal url> [--token $WT_INTERNAL_TOKEN]"
	if len(args) < 2 || args[0] != "plans" {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet("admin plans", flag.ContinueOnError)
	api := fs.String("api", "", "internal listener base URL")
	token := fs.String("token", os.Getenv("WT_INTERNAL_TOKEN"), "internal token")
	ent := fs.String("entitlements", "", "entitlements JSON (put)")
	verb, rest := args[1], args[2:]
	name := ""
	if verb == "put" && len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		name, rest = rest[0], rest[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return err
	}
	method, body := http.MethodGet, io.Reader(nil)
	switch verb {
	case "list":
	case "put":
		if name == "" || !json.Valid([]byte(*ent)) {
			return errors.New(usage)
		}
		b, _ := json.Marshal(map[string]json.RawMessage{"name": mustJSON(name), "entitlements": json.RawMessage(*ent)})
		method, body = http.MethodPut, bytes.NewReader(b)
	default:
		return errors.New(usage)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(*api, "/")+"/internal/plans", body)
	if err != nil {
		return err
	}
	req.Header.Set("X-WT-Internal-Token", *token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := guardedClient(0).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	_, err = fmt.Fprintln(out, strings.TrimSpace(string(data)))
	return err
}

func mustJSON(s string) json.RawMessage {
	b, _ := json.Marshal(s)
	return b
}
