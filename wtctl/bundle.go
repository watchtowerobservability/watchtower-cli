package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-cli/internal/netguard"
)

const bundleUsage = `usage: wtctl bundle create --version v --out bundle.tar --key <ed25519 seed file> [--image ref=oci.tar]... [--chart dir] [--docs dir] [--license file] [--root repo]
       wtctl bundle verify bundle.tar --pubkey <base64url ed25519 key>
       wtctl bundle load bundle.tar --pubkey <base64url ed25519 key> --registry host:port`

// guardedClient is the wtctl HTTP client: HTTP(S)_PROXY honoured (D-85), WT_AIRGAP policy applied
// to the host it dials (the proxy when one is set).
func guardedClient(timeout time.Duration) *http.Client {
	c := netguard.NewClientWith(netguard.FromEnv("wtctl"), netguard.Options{}, func(t *http.Transport) { t.Proxy = http.ProxyFromEnvironment })
	c.Timeout = timeout
	c.Transport = clientHeader{c.Transport}
	return c
}

// clientHeader names the wtctl version on every request (X-WT-Client: wtctl/0.3.0), so the server can
// answer a too-old client with client_too_old instead of quietly empty data (B16).
type clientHeader struct{ next http.RoundTripper }

func (h clientHeader) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-WT-Client", "wtctl/"+Version)
	next := h.next
	if next == nil {
		next = http.DefaultTransport
	}
	return next.RoundTrip(r)
}

type bundleFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type bundleImage struct {
	Ref  string `json:"ref"`
	Path string `json:"path"`
}

type bundleManifest struct {
	Version string        `json:"version"`
	Created string        `json:"created"`
	Images  []bundleImage `json:"images"`
	Files   []bundleFile  `json:"files"`
}

// bundleSpec lists what goes into an offline bundle.
type bundleSpec struct {
	Version     string
	Created     time.Time
	Images      map[string]string // image ref -> OCI/docker tar on disk
	ChartDir    string
	DocsDir     string
	LicenseFile string
	SBOM        []byte
	Key         ed25519.PrivateKey
}

type bundleEntry struct {
	name string
	data []byte // set for small generated entries
	file string // else read from disk
}

func (e bundleEntry) open() (io.ReadCloser, error) {
	if e.file == "" {
		return io.NopCloser(bytes.NewReader(e.data)), nil
	}
	return os.Open(e.file)
}

func walkEntries(prefix, dir string, out *[]bundleEntry) error {
	if dir == "" {
		return nil
	}
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		*out = append(*out, bundleEntry{name: path.Join(prefix, filepath.ToSlash(rel)), file: p})
		return nil
	})
}

// docsIndex is the static HTML landing page of the bundled docs (no scripts, no external assets).
func docsIndex(version string, entries []bundleEntry) []byte {
	var b strings.Builder
	b.WriteString("<!doctype html><meta charset=utf-8><title>Watchtower docs " + html.EscapeString(version) + "</title><h1>Watchtower " + html.EscapeString(version) + "</h1><ul>\n")
	for _, e := range entries {
		rel := strings.TrimPrefix(e.name, "docs/")
		b.WriteString(`<li><a href="` + html.EscapeString(rel) + `">` + html.EscapeString(rel) + "</a></li>\n")
	}
	b.WriteString("</ul>\n")
	return []byte(b.String())
}

func sumsText(files []bundleFile) []byte {
	var b strings.Builder
	for _, f := range files {
		b.WriteString(f.SHA256 + "  " + f.Path + "\n")
	}
	return []byte(b.String())
}

func hashEntry(e bundleEntry) (bundleFile, error) {
	r, err := e.open()
	if err != nil {
		return bundleFile{}, err
	}
	defer r.Close()
	h := sha256.New()
	n, err := io.Copy(h, r)
	return bundleFile{Path: e.name, SHA256: hex.EncodeToString(h.Sum(nil)), Size: n}, err
}

func writeTar(tw *tar.Writer, name string, mod time.Time, size int64, r io.Reader) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: size, ModTime: mod}); err != nil {
		return err
	}
	_, err := io.Copy(tw, r)
	return err
}

// createBundle writes manifest.json, manifest.sig (Ed25519 over the manifest bytes), SHA256SUMS
// and then the payload, in that order so a verifier can check the signature before reading images.
func createBundle(s bundleSpec, w io.Writer) error {
	if s.Version == "" || len(s.Key) != ed25519.PrivateKeySize {
		return errors.New("bundle needs a version and an Ed25519 key")
	}
	var docs []bundleEntry
	if err := walkEntries("docs", s.DocsDir, &docs); err != nil {
		return err
	}
	entries := []bundleEntry{}
	var imgs []bundleImage
	refs := make([]string, 0, len(s.Images))
	for ref := range s.Images {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	for _, ref := range refs {
		n := "images/" + strings.NewReplacer("/", "_", ":", "_").Replace(ref) + ".tar"
		entries = append(entries, bundleEntry{name: n, file: s.Images[ref]})
		imgs = append(imgs, bundleImage{Ref: ref, Path: n})
	}
	if err := walkEntries("chart", s.ChartDir, &entries); err != nil {
		return err
	}
	entries = append(entries, docs...)
	if s.DocsDir != "" {
		entries = append(entries, bundleEntry{name: "docs/index.html", data: docsIndex(s.Version, docs)})
	}
	if s.LicenseFile != "" {
		entries = append(entries, bundleEntry{name: "LICENSE", file: s.LicenseFile})
	}
	if s.SBOM != nil {
		entries = append(entries, bundleEntry{name: "sbom.cdx.json", data: s.SBOM})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	m := bundleManifest{Version: s.Version, Created: s.Created.UTC().Format(time.RFC3339), Images: imgs}
	for _, e := range entries {
		f, err := hashEntry(e)
		if err != nil {
			return err
		}
		m.Files = append(m.Files, f)
	}
	mj, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	sig := []byte(base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.Key, mj)))
	tw := tar.NewWriter(w)
	for _, h := range []struct {
		n string
		d []byte
	}{{"manifest.json", mj}, {"manifest.sig", sig}, {"SHA256SUMS", sumsText(m.Files)}} {
		if err := writeTar(tw, h.n, s.Created, int64(len(h.d)), bytes.NewReader(h.d)); err != nil {
			return err
		}
	}
	for i, e := range entries {
		r, err := e.open()
		if err != nil {
			return err
		}
		err = writeTar(tw, e.name, s.Created, m.Files[i].Size, r)
		_ = r.Close()
		if err != nil {
			return err
		}
	}
	return tw.Close()
}

func safeName(n string) bool {
	return n != "" && !path.IsAbs(n) && path.Clean(n) == n && !strings.HasPrefix(n, "../")
}

// verifyBundle checks the signature, the SHA256SUMS file and every payload hash, offline. visit,
// when set, receives each payload entry's reader after its hash was computed on a copy: it runs
// before the hash is final, so callers must trust nothing until verifyBundle returns nil.
func verifyBundle(r io.Reader, pub ed25519.PublicKey, visit func(name string, data io.Reader) error) (*bundleManifest, error) {
	tr := tar.NewReader(r)
	head := map[string][]byte{}
	for _, want := range []string{"manifest.json", "manifest.sig", "SHA256SUMS"} {
		h, err := tr.Next()
		if err != nil || h.Name != want {
			return nil, fmt.Errorf("bundle must start with %s", want)
		}
		b, err := io.ReadAll(io.LimitReader(tr, 64<<20))
		if err != nil {
			return nil, err
		}
		head[want] = b
	}
	sig, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(head["manifest.sig"])))
	if err != nil || !ed25519.Verify(pub, head["manifest.json"], sig) {
		return nil, errors.New("manifest signature does not verify")
	}
	var m bundleManifest
	if err := json.Unmarshal(head["manifest.json"], &m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if !bytes.Equal(sumsText(m.Files), head["SHA256SUMS"]) {
		return nil, errors.New("SHA256SUMS does not match the signed manifest")
	}
	want := map[string]bundleFile{}
	for _, f := range m.Files {
		if !safeName(f.Path) {
			return nil, fmt.Errorf("unsafe path %q in manifest", f.Path)
		}
		want[f.Path] = f
	}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		f, ok := want[h.Name]
		if !ok {
			return nil, fmt.Errorf("%s is not in the manifest", h.Name)
		}
		hash := sha256.New()
		src := io.TeeReader(tr, hash)
		if visit != nil {
			if err := visit(h.Name, src); err != nil {
				return nil, err
			}
		}
		if _, err := io.Copy(io.Discard, src); err != nil { // drain what visit left
			return nil, err
		}
		if hex.EncodeToString(hash.Sum(nil)) != f.SHA256 {
			return nil, fmt.Errorf("%s: checksum mismatch", h.Name)
		}
		delete(want, h.Name)
	}
	if len(want) > 0 {
		return nil, fmt.Errorf("%d files from the manifest are missing", len(want))
	}
	return &m, nil
}

// sbomCycloneDX turns `cargo metadata` JSON and `go list -m all` output into CycloneDX 1.5 JSON.
func sbomCycloneDX(cargoMeta, goList []byte, version string) ([]byte, error) {
	type comp struct {
		Type     string `json:"type"`
		Name     string `json:"name"`
		Version  string `json:"version"`
		Purl     string `json:"purl"`
		Licenses []any  `json:"licenses,omitempty"`
	}
	comps := []comp{}
	if len(cargoMeta) > 0 {
		var cm struct {
			Packages []struct{ Name, Version, License string } `json:"packages"`
		}
		if err := json.Unmarshal(cargoMeta, &cm); err != nil {
			return nil, fmt.Errorf("cargo metadata: %w", err)
		}
		for _, p := range cm.Packages {
			c := comp{Type: "library", Name: p.Name, Version: p.Version, Purl: "pkg:cargo/" + p.Name + "@" + p.Version}
			if p.License != "" {
				c.Licenses = []any{map[string]any{"expression": p.License}}
			}
			comps = append(comps, c)
		}
	}
	for _, l := range strings.Split(string(goList), "\n") {
		if f := strings.Fields(l); len(f) >= 2 {
			comps = append(comps, comp{Type: "library", Name: f[0], Version: f[1], Purl: "pkg:golang/" + f[0] + "@" + f[1]})
		}
	}
	sort.Slice(comps, func(i, j int) bool { return comps[i].Purl < comps[j].Purl })
	return json.MarshalIndent(map[string]any{
		"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
		"metadata":   map[string]any{"component": map[string]any{"type": "application", "name": "watchtower", "version": version}},
		"components": comps,
	}, "", "  ")
}

func cmdOutput(ctx context.Context, dir, name string, args ...string) []byte {
	c := exec.CommandContext(ctx, name, args...)
	c.Dir = dir
	out, _ := c.Output() // a missing toolchain yields an SBOM without that ecosystem
	return out
}

type imageFlags map[string]string

func (f imageFlags) String() string { return "" }
func (f imageFlags) Set(v string) error {
	ref, p, ok := strings.Cut(v, "=")
	if !ok || ref == "" || p == "" {
		return errors.New("--image wants ref=path.tar")
	}
	f[ref] = p
	return nil
}

func bundlePub(s string) (ed25519.PublicKey, error) {
	pub, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("--pubkey must be base64url of a 32-byte Ed25519 key")
	}
	return pub, nil
}

func bundleMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) < 1 {
		return errors.New(bundleUsage)
	}
	fl := flag.NewFlagSet("bundle "+args[0], flag.ContinueOnError)
	version := fl.String("version", "", "release version")
	outFile := fl.String("out", "bundle.tar", "output file")
	keyFile := fl.String("key", "", "file with the base64url Ed25519 seed (create)")
	chart := fl.String("chart", "", "Helm chart directory")
	docs := fl.String("docs", "", "docs directory")
	lic := fl.String("license", "", "licence text file")
	root := fl.String("root", ".", "repository root (SBOM source)")
	pubS := fl.String("pubkey", "", "base64url Ed25519 public key")
	registry := fl.String("registry", "", "target registry host[:port] (load)")
	images := imageFlags{}
	fl.Var(images, "image", "ref=oci.tar (repeatable)")
	rest := args[1:]
	var file string
	if args[0] != "create" && len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		file, rest = rest[0], rest[1:]
	}
	if err := fl.Parse(rest); err != nil {
		return err
	}
	switch args[0] {
	case "create":
		raw, err := os.ReadFile(*keyFile)
		if err != nil {
			return err
		}
		seed, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(seed) != ed25519.SeedSize {
			return errors.New("--key must hold a base64url 32-byte Ed25519 seed")
		}
		sbom, err := sbomCycloneDX(
			cmdOutput(ctx, *root, "cargo", "metadata", "--format-version", "1", "--locked"),
			cmdOutput(ctx, filepath.Join(*root, "go"), "go", "list", "-m", "all"), *version)
		if err != nil {
			return err
		}
		f, err := os.Create(*outFile)
		if err != nil {
			return err
		}
		err = createBundle(bundleSpec{Version: *version, Created: time.Now(), Images: images, ChartDir: *chart,
			DocsDir: *docs, LicenseFile: *lic, SBOM: sbom, Key: ed25519.NewKeyFromSeed(seed)}, f)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err == nil {
			_, err = fmt.Fprintf(out, "wrote %s\n", *outFile)
		}
		return err
	case "verify", "load":
		pub, err := bundlePub(*pubS)
		if err != nil {
			return err
		}
		if file == "" {
			return errors.New(bundleUsage)
		}
		if args[0] == "load" {
			return loadBundle(ctx, file, pub, *registry, out, runTool)
		}
		f, err := os.Open(file)
		if err != nil {
			return err
		}
		defer f.Close()
		m, err := verifyBundle(f, pub, nil)
		if err == nil {
			_, err = fmt.Fprintf(out, "bundle %s ok: %d files, signature valid\n", m.Version, len(m.Files))
		}
		return err
	}
	return errors.New(bundleUsage)
}

func runTool(ctx context.Context, name string, args ...string) error {
	c := exec.CommandContext(ctx, name, args...)
	if b, err := c.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(b)))
	}
	return nil
}

// loadBundle verifies the bundle, then copies every image into registry with skopeo.
func loadBundle(ctx context.Context, file string, pub ed25519.PublicKey, registry string, out io.Writer,
	run func(ctx context.Context, name string, args ...string) error) error {
	if registry == "" {
		return errors.New("--registry is required")
	}
	tmp, err := os.MkdirTemp("", "wt-bundle-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	m, err := verifyBundle(f, pub, func(name string, r io.Reader) error {
		if !strings.HasPrefix(name, "images/") {
			return nil
		}
		w, err := os.Create(filepath.Join(tmp, path.Base(name)))
		if err != nil {
			return err
		}
		_, err = io.Copy(w, r)
		if cerr := w.Close(); err == nil {
			err = cerr
		}
		return err
	})
	if err != nil {
		return err // nothing was pushed: the push happens only after a full verify
	}
	for _, im := range m.Images {
		if err := run(ctx, "skopeo", "copy", "--all", "oci-archive:"+filepath.Join(tmp, path.Base(im.Path)),
			"docker://"+registry+"/"+im.Ref); err != nil {
			return err
		}
		fmt.Fprintf(out, "pushed %s/%s\n", registry, im.Ref)
	}
	return nil
}
