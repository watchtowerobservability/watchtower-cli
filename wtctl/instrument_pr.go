package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

//go:embed skillfiles
var skillFiles embed.FS

func decodeJSON(r io.Reader, v any) error {
	return json.NewDecoder(io.LimitReader(r, 1<<20)).Decode(v)
}

var repoRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}$`)

// prOpener opens the draft pull request. Git runs in Dir; GitHub is the REST base URL (a test
// server in tests). The branch is always a new watchtower/instrument-<time> branch: the default
// branch is read from GitHub and the command refuses to push to it or to open a non-draft PR.
type prOpener struct {
	HTTP   *http.Client
	GitHub string
	Token  string
	Repo   string
	Dir    string
	Git    func(ctx context.Context, dir string, args ...string) error
}

// instrumentBranch is the only kind of branch the command creates.
func instrumentBranch(now time.Time) string {
	return "watchtower/instrument-" + now.UTC().Format("20060102-150405")
}

// safeBranch reports whether branch may be pushed: under watchtower/ and not the default branch.
func safeBranch(branch, def string) bool {
	return strings.HasPrefix(branch, "watchtower/") && branch != def && def != ""
}

func (p prOpener) call(ctx context.Context, method, rel string, body any, out any) error {
	var rd io.Reader = http.NoBody
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(p.GitHub, "/")+rel, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return errors.New("instrument: GitHub is unreachable")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("instrument: GitHub answered %d", resp.StatusCode) // the body can echo request data
	}
	return decodeJSON(resp.Body, out)
}

// Open commits files on a new branch, pushes it and opens a draft pull request; it returns the PR URL.
func (p prOpener) Open(ctx context.Context, files []string, in instrumentation, now time.Time) (string, error) {
	if p.Token == "" {
		return "", errors.New("instrument: set GITHUB_TOKEN to open a pull request")
	}
	if !repoRe.MatchString(p.Repo) {
		return "", errors.New("instrument: --repo must be owner/name")
	}
	var repo struct {
		Default string `json:"default_branch"`
	}
	if err := p.call(ctx, http.MethodGet, "/repos/"+p.Repo, nil, &repo); err != nil {
		return "", err
	}
	branch := instrumentBranch(now)
	if !safeBranch(branch, repo.Default) {
		return "", errors.New("instrument: refusing to use the default branch")
	}
	steps := [][]string{{"checkout", "-b", branch}, append([]string{"add", "--"}, files...),
		{"commit", "-m", "chore: add Watchtower OpenTelemetry setup (draft, human review required)"},
		{"push", "origin", branch}}
	for _, s := range steps {
		if err := p.Git(ctx, p.Dir, s...); err != nil {
			return "", fmt.Errorf("instrument: git %s failed", s[0])
		}
	}
	body := "> **AI-generated, human review required.** Opened by `wtctl instrument` as a draft. It adds the " + in.Lang +
		" Watchtower setup; the endpoint and ingestion key come from the environment.\n\nNext steps:\n- " + strings.Join(in.Next, "\n- ")
	var pr struct {
		URL string `json:"html_url"`
	}
	err := p.call(ctx, http.MethodPost, "/repos/"+p.Repo+"/pulls", map[string]any{
		"title": "[AI draft] Add Watchtower OpenTelemetry setup", "head": branch, "base": repo.Default, "body": body, "draft": true,
	}, &pr)
	return pr.URL, err
}

func runGit(ctx context.Context, dir string, args ...string) error {
	c := exec.CommandContext(ctx, "git", args...)
	c.Dir = dir
	return c.Run()
}

// skillsMain implements `wtctl mcp skills install [--dir .claude/skills]`: it writes the published
// agent skill files (instrument, investigate) so coding agents pick them up.
func skillsMain(args []string, out io.Writer) error {
	dir := ".claude/skills"
	switch {
	case len(args) == 1 && args[0] == "install":
	case len(args) == 3 && args[0] == "install" && args[1] == "--dir":
		dir = args[2]
	default:
		return errors.New(mcpUsage)
	}
	return fs.WalkDir(skillFiles, "skillfiles", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := skillFiles.ReadFile(p)
		if err != nil {
			return err
		}
		dst := filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(p, "skillfiles/")))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		fmt.Fprintln(out, "wrote", path.Join(dir, strings.TrimPrefix(p, "skillfiles/")))
		return os.WriteFile(dst, b, 0o644) //nolint:gosec // skill files are not secrets
	})
}
