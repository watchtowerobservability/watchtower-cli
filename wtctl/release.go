package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

type commit struct {
	SHA         string   `json:"sha"`
	AuthorEmail string   `json:"author_email,omitempty"`
	Message     string   `json:"message"`
	Files       []string `json:"files"`
	CommittedAt string   `json:"committed_at,omitempty"`
}

// maxCommits matches the API limit per request.
const maxCommits = 1000

// API limits per commit: files kept and bytes per path.
const (
	maxFiles    = 500
	maxPathByte = 2000
)

// gitCommits lists commits for rng ("auto" = since the previous tag, else everything reachable
// from HEAD; anything else is passed to git log as a revision range), newest first, capped.
func gitCommits(ctx context.Context, dir, rng string) ([]commit, error) {
	if rng == "auto" {
		rng = "HEAD"
		// The nearest tag before HEAD (HEAD itself may be the tag being released).
		if out, err := git(ctx, dir, "describe", "--tags", "--abbrev=0", "HEAD^"); err == nil {
			rng = strings.TrimSpace(out) + "..HEAD"
		}
	}
	out, err := git(ctx, dir, "log", "-n", fmt.Sprint(maxCommits), "--name-only",
		"--format=%x1e%H%x1f%ae%x1f%cI%x1f%s", rng)
	if err != nil {
		return nil, err
	}
	return parseLog(out), nil
}

// parseLog turns the log output above into commits within the API limits.
func parseLog(out string) []commit {
	var cs []commit
	for _, rec := range strings.Split(out, "\x1e")[1:] {
		lines := strings.Split(strings.TrimSpace(rec), "\n")
		f := strings.SplitN(lines[0], "\x1f", 4)
		if len(f) != 4 {
			continue
		}
		c := commit{SHA: f[0], AuthorEmail: f[1], CommittedAt: f[2], Message: f[3], Files: []string{}}
		for _, l := range lines[1:] {
			if l = strings.TrimSpace(l); l != "" && len(l) <= maxPathByte && len(c.Files) < maxFiles {
				c.Files = append(c.Files, l)
			}
		}
		cs = append(cs, c)
	}
	return cs
}

func git(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

func call(ctx context.Context, method, url, key string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := guardedClient(0).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s: %s: %s", method, url, resp.Status, strings.TrimSpace(string(b)))
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

type releaseOpts struct {
	api, key, project, version, ref, url, commits, deploy, dir string
}

// releaseCreate posts the release (idempotent by version) and, with deploy set, a deployment
// to the environment of that name or id.
func releaseCreate(ctx context.Context, o releaseOpts, out io.Writer) error {
	base := strings.TrimRight(o.api, "/") + "/v1/projects/" + o.project
	body := map[string]any{"version": o.version}
	if o.ref != "" {
		body["ref"] = o.ref
	}
	if o.url != "" {
		body["url"] = o.url
	}
	if o.commits != "" {
		cs, err := gitCommits(ctx, o.dir, o.commits)
		if err != nil {
			return err
		}
		body["commits"] = cs
	}
	var rel struct{ ID string }
	if err := call(ctx, http.MethodPost, base+"/releases", o.key, body, &rel); err != nil {
		return err
	}
	fmt.Fprintf(out, "release %s (%s)\n", o.version, rel.ID)
	if o.deploy == "" {
		return nil
	}
	var envs struct {
		Data []struct{ ID, Name string }
	}
	if err := call(ctx, http.MethodGet, base+"/environments?limit=200", o.key, nil, &envs); err != nil {
		return err
	}
	for _, e := range envs.Data {
		if e.Name == o.deploy || e.ID == o.deploy {
			dep := map[string]any{"version": o.version, "env_id": e.ID, "source": "wtctl"}
			if err := call(ctx, http.MethodPost, base+"/deployments", o.key, dep, nil); err != nil {
				return err
			}
			fmt.Fprintf(out, "deployed to %s\n", e.Name)
			return nil
		}
	}
	return errors.New("no environment named " + o.deploy)
}

func releaseMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) < 1 || args[0] != "create" {
		return errors.New("usage: wtctl release create <version> --api <url> --key <key> --project <prj_...> [--commits auto|<range>] [--deploy <env>] [--ref r] [--url u]")
	}
	fs := flag.NewFlagSet("release create", flag.ContinueOnError)
	var o releaseOpts
	fs.StringVar(&o.api, "api", "", "API base URL")
	fs.StringVar(&o.key, "key", os.Getenv("WT_API_KEY"), "API key (project admin); default $WT_API_KEY")
	fs.StringVar(&o.project, "project", "", "project id")
	fs.StringVar(&o.ref, "ref", "", "git ref or tag")
	fs.StringVar(&o.url, "url", "", "release URL")
	fs.StringVar(&o.commits, "commits", "", "auto (since the previous tag) or a git revision range")
	fs.StringVar(&o.deploy, "deploy", "", "environment (name or id) to record a deployment in")
	fs.StringVar(&o.dir, "dir", ".", "git repository")
	// The version comes first; flags follow it.
	if len(args) < 2 || strings.HasPrefix(args[1], "-") {
		return errors.New("release create needs a version")
	}
	o.version = args[1]
	if err := fs.Parse(args[2:]); err != nil {
		return err
	}
	if o.api == "" || o.key == "" || o.project == "" {
		return errors.New("--api, --key and --project are required")
	}
	return releaseCreate(ctx, o, out)
}
