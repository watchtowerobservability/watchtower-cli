package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const instrumentUsage = `usage: wtctl instrument plan  [--dir .] [--lang go|node|python|java|ruby|php|rust|dotnet]
       wtctl instrument apply [--dir .] [--lang ...] [--force]
       wtctl instrument apply --open-pr --repo owner/name --api <url> --key <key> --project <id> [--dir .]
       (--open-pr needs GITHUB_TOKEN, the project's AI pull requests setting on, and opens a draft PR from a new watchtower/instrument-* branch; it never touches the default branch)`

// detectLang returns the repository's language from its marker files ("" when unknown).
func detectLang(dir string) string {
	for _, m := range langMarkers {
		if _, err := os.Stat(filepath.Join(dir, m.File)); err == nil {
			return m.Lang
		}
	}
	for _, pat := range []string{"*.csproj", "*.sln"} {
		if hits, _ := filepath.Glob(filepath.Join(dir, pat)); len(hits) > 0 {
			return "dotnet"
		}
	}
	return ""
}

// planInstrument picks the template for lang (detected when empty).
func planInstrument(dir, lang string) (instrumentation, error) {
	if lang == "" {
		lang = detectLang(dir)
	}
	in, ok := instrumentTemplates[lang]
	if !ok {
		return instrumentation{}, fmt.Errorf("instrument: cannot tell the language of %s; pass --lang", dir)
	}
	return in, nil
}

// writeInstrument writes the files under dir and returns the paths it wrote. An existing file is
// left alone (returned in skipped) unless force is set.
func writeInstrument(dir string, in instrumentation, force bool) (written, skipped []string, err error) {
	for _, f := range in.Files {
		p := filepath.Join(dir, filepath.FromSlash(f.Path))
		if rel, rerr := filepath.Rel(dir, p); rerr != nil || strings.HasPrefix(rel, "..") {
			return written, skipped, errors.New("instrument: template path escapes the directory")
		}
		if _, serr := os.Stat(p); serr == nil && !force {
			skipped = append(skipped, f.Path)
			continue
		}
		if err = os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return written, skipped, err
		}
		if err = os.WriteFile(p, []byte(f.Content), 0o644); err != nil { //nolint:gosec // source files, not secrets
			return written, skipped, err
		}
		written = append(written, f.Path)
	}
	return written, skipped, nil
}

func printPlan(out io.Writer, in instrumentation) {
	fmt.Fprintf(out, "language: %s\nfiles:\n", in.Lang)
	for _, f := range in.Files {
		fmt.Fprintf(out, "  %s\n", f.Path)
	}
	fmt.Fprintln(out, "environment (set by you, never committed): WT_ENDPOINT, WT_INGEST_KEY")
	fmt.Fprintln(out, "then:")
	for _, n := range in.Next {
		fmt.Fprintf(out, "  %s\n", n)
	}
}

func instrumentMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) < 1 || (args[0] != "plan" && args[0] != "apply") {
		return errors.New(instrumentUsage)
	}
	fs := flag.NewFlagSet("instrument "+args[0], flag.ContinueOnError)
	var dir, lang, repo, api, key, project string
	var force, openPR bool
	fs.StringVar(&dir, "dir", ".", "repository directory")
	fs.StringVar(&lang, "lang", "", "language override")
	fs.BoolVar(&force, "force", false, "overwrite existing files")
	fs.BoolVar(&openPR, "open-pr", false, "open a draft pull request (GitHub)")
	fs.StringVar(&repo, "repo", "", "owner/name")
	fs.StringVar(&api, "api", apiEnv(), "Watchtower API base URL")
	fs.StringVar(&key, "key", os.Getenv("WT_API_KEY"), "Watchtower API key")
	fs.StringVar(&project, "project", "", "Watchtower project id")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	in, err := planInstrument(dir, lang)
	if err != nil {
		return err
	}
	if args[0] == "plan" {
		printPlan(out, in)
		return nil
	}
	if openPR {
		if repo == "" || api == "" || key == "" || project == "" {
			return errors.New(instrumentUsage)
		}
		if err := prAllowed(ctx, guardedClient(0), api, key, project); err != nil {
			return err
		}
	}
	written, skipped, err := writeInstrument(dir, in, force)
	if err != nil {
		return err
	}
	for _, p := range written {
		fmt.Fprintln(out, "wrote", p)
	}
	for _, p := range skipped {
		fmt.Fprintln(out, "kept existing", p, "(use --force to overwrite)")
	}
	if !openPR {
		for _, n := range in.Next {
			fmt.Fprintln(out, "next:", n)
		}
		return nil
	}
	if len(written) == 0 {
		return errors.New("instrument: nothing to commit")
	}
	pr := prOpener{HTTP: guardedClient(0), GitHub: "https://api.github.com", Token: os.Getenv("GITHUB_TOKEN"), Repo: repo, Dir: dir, Git: runGit}
	u, err := pr.Open(ctx, written, in, time.Now())
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "draft pull request:", u)
	return nil
}

// prAllowed enforces the project's opt-in (ai/pr-settings, off by default). A refusal, a missing
// project or any API failure all stop the command.
func prAllowed(ctx context.Context, c *http.Client, api, key, project string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(api, "/")+"/v1/projects/"+url.PathEscape(project)+"/ai/pr-settings", http.NoBody)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := c.Do(req)
	if err != nil {
		return errors.New("instrument: the Watchtower API is unreachable")
	}
	defer func() { _ = resp.Body.Close() }()
	var s struct {
		Allow bool `json:"allow_pr_creation"`
	}
	if resp.StatusCode != http.StatusOK || decodeJSON(resp.Body, &s) != nil || !s.Allow {
		return errors.New("instrument: AI pull requests are not enabled for this project (Settings, AI, pull requests)")
	}
	return nil
}
