package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const sizeUsage = `usage: wtctl size upload <app.apk|app.aab|app.ipa> --app-id <id> [--version v] [--build n] [--branch b] [--commit sha]
         --api <url> --key <key> --project <prj_...> [--base-branch main] [--max-increase-bytes N] [--max-increase-pct P]
  Reads the package's size breakdown, uploads it (RUM-010 size analysis) and, with a --max-increase
  flag, compares it with the latest earlier build of the base branch and fails on a regression.`

// sizeComponent is one path prefix of a package and its uncompressed bytes.
type sizeComponent struct {
	Name  string `json:"name"`
	Bytes int64  `json:"bytes"`
}

// sizeReport is the breakdown of one package.
type sizeReport struct {
	Platform      string
	TotalBytes    int64
	DownloadBytes int64
	Components    []sizeComponent
}

func sizeMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) < 2 || args[0] != "upload" || strings.HasPrefix(args[1], "-") {
		return errors.New(sizeUsage)
	}
	return sizeUploadCmd(ctx, args[1], args[2:], out)
}

// componentOf groups a package entry: native libraries per ABI, iOS frameworks and plug-ins per
// bundle, dex files together, everything else by its first directory.
func componentOf(platform, name string) string {
	segs := strings.Split(strings.TrimPrefix(name, "/"), "/")
	if platform == "ios" && len(segs) > 2 && segs[0] == "Payload" && strings.HasSuffix(segs[1], ".app") {
		segs = segs[2:]
	}
	prefix := ""
	if platform == "android" && len(segs) > 1 && segs[0] == "base" { // AAB module
		prefix, segs = "base/", segs[1:]
	}
	if len(segs) == 1 {
		if strings.HasSuffix(segs[0], ".dex") {
			return prefix + "dex"
		}
		return prefix + segs[0]
	}
	switch segs[0] {
	case "lib", "Frameworks", "PlugIns":
		return prefix + segs[0] + "/" + segs[1]
	case "dex":
		return prefix + "dex"
	}
	return prefix + segs[0]
}

// analyzeSize reads a zip package (APK, AAB or IPA). The download size is the sum of the
// compressed entries: close to what a store serves, not the store's exact number.
func analyzeSize(r io.ReaderAt, n int64, platform string) (sizeReport, error) {
	z, err := zip.NewReader(r, n)
	if err != nil {
		return sizeReport{}, fmt.Errorf("not a zip package: %w", err)
	}
	rep := sizeReport{Platform: platform}
	by := map[string]int64{}
	for _, f := range z.File {
		if f.FileInfo().IsDir() {
			continue
		}
		u, c := int64(f.UncompressedSize64), int64(f.CompressedSize64) //nolint:gosec // sizes of one package fit
		rep.TotalBytes += u
		rep.DownloadBytes += c
		by[componentOf(platform, f.Name)] += u
	}
	for k, v := range by {
		rep.Components = append(rep.Components, sizeComponent{Name: k, Bytes: v})
	}
	sort.Slice(rep.Components, func(i, j int) bool {
		a, b := rep.Components[i], rep.Components[j]
		return a.Bytes > b.Bytes || (a.Bytes == b.Bytes && a.Name < b.Name)
	})
	return rep, nil
}

func platformOf(file string) (string, error) {
	switch strings.ToLower(filepath.Ext(file)) {
	case ".apk", ".aab":
		return "android", nil
	case ".ipa":
		return "ios", nil
	}
	return "", errors.New("the package must be an .apk, .aab or .ipa")
}

func sizeUploadCmd(ctx context.Context, file string, args []string, out io.Writer) error {
	var o artifactOpts
	fs := flag.NewFlagSet("size upload", flag.ContinueOnError)
	o.flags(fs)
	appID := fs.String("app-id", "", "bundle or application id")
	version := fs.String("version", "", "app version")
	build := fs.String("build", "", "build number")
	branch := fs.String("branch", os.Getenv("GITHUB_HEAD_REF"), "branch of this build")
	commit := fs.String("commit", os.Getenv("GITHUB_SHA"), "commit of this build")
	base := fs.String("base-branch", "main", "branch to compare with")
	maxBytes := fs.Int64("max-increase-bytes", -1, "fail when the download size grows by more bytes")
	maxPct := fs.Float64("max-increase-pct", -1, "fail when the download size grows by more percent")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := o.check(); err != nil {
		return err
	}
	if *appID == "" {
		return errors.New("--app-id is required")
	}
	platform, err := platformOf(file)
	if err != nil {
		return err
	}
	f, err := os.Open(file) //nolint:gosec // the user names the package
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	rep, err := analyzeSize(f, st.Size(), platform)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{
		"app_id": *appID, "platform": platform, "version": *version, "build": *build, "branch": *branch,
		"commit_sha": *commit, "total_bytes": rep.TotalBytes, "download_bytes": rep.DownloadBytes, "components": rep.Components,
	})
	api := strings.TrimRight(o.api, "/") + "/v1/projects/" + url.PathEscape(o.project) + "/app-builds"
	var created struct {
		ID string `json:"id"`
	}
	if err := sizeCall(ctx, http.MethodPost, api, o.key, body, &created); err != nil {
		return err
	}
	fmt.Fprintf(out, "uploaded %s: download %d bytes, install %d bytes, %d components\n", file, rep.DownloadBytes, rep.TotalBytes, len(rep.Components))
	if *maxBytes < 0 && *maxPct < 0 {
		return nil
	}
	q := url.Values{"base_branch": {*base}}
	if *maxBytes >= 0 {
		q.Set("max_increase_bytes", strconv.FormatInt(*maxBytes, 10))
	}
	if *maxPct >= 0 {
		q.Set("max_increase_pct", strconv.FormatFloat(*maxPct, 'f', -1, 64))
	}
	var cmp struct {
		DownloadDelta int64    `json:"download_delta"`
		Passed        bool     `json:"passed"`
		Reasons       []string `json:"reasons"`
		Base          *struct {
			Version string `json:"version"`
		} `json:"base"`
	}
	if err := sizeCall(ctx, http.MethodGet, api+"/"+url.PathEscape(created.ID)+"/compare?"+q.Encode(), o.key, nil, &cmp); err != nil {
		return err
	}
	if cmp.Base == nil {
		fmt.Fprintf(out, "no earlier build on %s: nothing to compare\n", *base)
		return nil
	}
	fmt.Fprintf(out, "download size change against %s (%s): %+d bytes\n", *base, cmp.Base.Version, cmp.DownloadDelta)
	if !cmp.Passed {
		return fmt.Errorf("size gate failed: %s", strings.Join(cmp.Reasons, "; "))
	}
	return nil
}

func sizeCall(ctx context.Context, method, u, key string, body []byte, into any) error {
	var rd io.Reader = http.NoBody
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := guardedClient(2 * time.Minute).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s: %s", method, resp.Status, strings.TrimSpace(string(b)))
	}
	return json.Unmarshal(b, into)
}
