package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLicenseVerifyCommand(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	enc := base64.RawURLEncoding.EncodeToString
	payload := []byte(`{"org":"acme","entitlements":{"projects":5},"not_after":2000}`)
	file := `{"payload":"` + enc(payload) + `","signature":"` + enc(ed25519.Sign(priv, payload)) + `"}`
	path := filepath.Join(t.TempDir(), "lic.json")
	if err := os.WriteFile(path, []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(now string, key []byte) (string, error) {
		var out bytes.Buffer
		err := licenseMain(context.Background(), []string{"verify", "--file", path, "--pubkey", enc(key), "--now", now}, &out)
		return out.String(), err
	}
	if s, err := run("1000", pub); err != nil || !strings.Contains(s, "state=valid") {
		t.Fatalf("valid: %q %v", s, err)
	}
	if s, err := run("3000", pub); err != nil || !strings.Contains(s, "expired") {
		t.Fatalf("expired: %q %v", s, err)
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if _, err := run("1000", other); err == nil {
		t.Fatal("wrong key must fail")
	}
	if err := os.WriteFile(path, []byte(strings.Replace(file, `"payload":"`, `"payload":"A`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run("1000", pub); err == nil {
		t.Fatal("tampered must fail")
	}
}
