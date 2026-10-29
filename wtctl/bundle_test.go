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
	"time"

	"github.com/watchtowerobservability/watchtower-cli/internal/netguard"
)

func testBundle(t *testing.T) ([]byte, ed25519.PublicKey) {
	t.Helper()
	dir := t.TempDir()
	put := func(rel, body string) string {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	img := put("api.tar", strings.Repeat("image-bytes", 1000))
	put("chart/Chart.yaml", "name: watchtower\n")
	put("docs/a.md", "# a\n")
	lic := put("LICENSE", "terms")
	pub, priv, _ := ed25519.GenerateKey(nil)
	sbom, err := sbomCycloneDX([]byte(`{"packages":[{"name":"serde","version":"1.0.0","license":"MIT"}]}`), []byte("watchtower\ngithub.com/x/y v1.2.3\n"), "v1")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	err = createBundle(bundleSpec{Version: "v1", Created: time.Unix(1700000000, 0), Images: map[string]string{"watchtower/api:v1": img},
		ChartDir: filepath.Join(dir, "chart"), DocsDir: filepath.Join(dir, "docs"), LicenseFile: lic, SBOM: sbom, Key: priv}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), pub
}

func TestBundleManifestHasSumsAndSignature(t *testing.T) {
	b, pub := testBundle(t)
	m, err := verifyBundle(bytes.NewReader(b), pub, nil)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, f := range m.Files {
		names[f.Path] = len(f.SHA256) == 64
	}
	for _, want := range []string{"images/watchtower_api_v1.tar", "chart/Chart.yaml", "docs/index.html", "docs/a.md", "LICENSE", "sbom.cdx.json"} {
		if !names[want] {
			t.Errorf("manifest lacks %s", want)
		}
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if _, err := verifyBundle(bytes.NewReader(b), other, nil); err == nil {
		t.Fatal("a different key must not verify")
	}
}

func TestBundleVerifyDetectsTamper(t *testing.T) {
	b, pub := testBundle(t)
	i := bytes.Index(b, []byte("image-bytes"))
	if i < 0 {
		t.Fatal("payload not found")
	}
	bad := append([]byte(nil), b...)
	bad[i] = 'X'
	if _, err := verifyBundle(bytes.NewReader(bad), pub, nil); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("want checksum mismatch, got %v", err)
	}
	if _, err := verifyBundle(bytes.NewReader(b[:len(b)-2048]), pub, nil); err == nil {
		t.Fatal("a truncated bundle must fail")
	}
}

func TestBundleLoadPushesOnlyAfterVerify(t *testing.T) {
	b, pub := testBundle(t)
	file := filepath.Join(t.TempDir(), "b.tar")
	if err := os.WriteFile(file, b, 0o644); err != nil {
		t.Fatal(err)
	}
	var calls []string
	run := func(_ context.Context, name string, args ...string) error {
		calls = append(calls, name+" "+args[len(args)-1])
		return nil
	}
	if err := loadBundle(context.Background(), file, pub, "reg.local:5000", &bytes.Buffer{}, run); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0] != "skopeo docker://reg.local:5000/watchtower/api:v1" {
		t.Fatalf("calls %v", calls)
	}
	b[bytes.Index(b, []byte("image-bytes"))] = 'X'
	_ = os.WriteFile(file, b, 0o644)
	calls = nil
	if err := loadBundle(context.Background(), file, pub, "reg.local:5000", &bytes.Buffer{}, run); err == nil || len(calls) != 0 {
		t.Fatalf("tampered bundle must push nothing: %v %v", err, calls)
	}
}

func TestLicenseVerifiesOffline(t *testing.T) {
	t.Setenv("WT_AIRGAP", "1")
	t.Setenv("WT_EGRESS_ALLOW", "")
	pub, priv, _ := ed25519.GenerateKey(nil)
	enc := base64.RawURLEncoding.EncodeToString
	payload := []byte(`{"org":"acme","entitlements":{"projects":5},"not_after":2000}`)
	path := filepath.Join(t.TempDir(), "lic.json")
	file := `{"payload":"` + enc(payload) + `","signature":"` + enc(ed25519.Sign(priv, payload)) + `"}`
	if err := os.WriteFile(path, []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	before := netguard.DeniedTotal()["wtctl"]
	var out bytes.Buffer
	if err := licenseMain(context.Background(), []string{"verify", "--file", path, "--pubkey", enc(pub), "--now", "1000"}, &out); err != nil {
		t.Fatal(err)
	}
	if netguard.DeniedTotal()["wtctl"] != before {
		t.Fatal("licence verification attempted network egress")
	}
}
