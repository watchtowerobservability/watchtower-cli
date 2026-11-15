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
	"strings"
)

// ciSHAEnv are the commit variables CI systems export, first match wins.
var ciSHAEnv = []string{"GITHUB_SHA", "CI_COMMIT_SHA", "BUILDKITE_COMMIT", "CIRCLE_SHA1", "BITBUCKET_COMMIT", "GIT_COMMIT", "DRONE_COMMIT_SHA"}

func ciSource() string {
	switch {
	case os.Getenv("GITHUB_ACTIONS") != "":
		return "github-actions"
	case os.Getenv("GITLAB_CI") != "":
		return "gitlab-ci"
	case os.Getenv("BUILDKITE") != "":
		return "buildkite"
	case os.Getenv("CIRCLECI") != "":
		return "circleci"
	}
	return "wtctl"
}

// deployMain is `wtctl deploy`: ensure the release for a commit (with its commit info) exists and
// record one deployment per service. Both calls are idempotent, so a CI retry is safe.
func deployMain(ctx context.Context, args []string, out io.Writer) error {
	const usage = "usage: wtctl deploy --services a,b,c [--env production] [--release <sha>] [--status succeeded|failed|started] [--dir .] [--api url --key key --project prj]"
	var o releaseOpts
	var services, envName, status string
	fs := flag.NewFlagSet("deploy", flag.ContinueOnError)
	fs.StringVar(&o.api, "api", apiEnv(), "API base URL; default $WT_API_URL")
	fs.StringVar(&o.key, "key", os.Getenv("WT_API_KEY"), "API key; default $WT_API_KEY")
	fs.StringVar(&o.project, "project", os.Getenv("WT_PROJECT"), "project id; default $WT_PROJECT")
	fs.StringVar(&o.version, "release", "", "release version; default the CI commit sha, else git HEAD")
	fs.StringVar(&o.dir, "dir", ".", "git repository")
	fs.StringVar(&services, "services", "", "comma-separated services shipped")
	fs.StringVar(&envName, "env", "production", "environment name or id")
	fs.StringVar(&status, "status", "succeeded", "started, succeeded or failed")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w\n%s", err, usage)
	}
	var svcs []string
	for _, s := range strings.Split(services, ",") {
		if s = strings.TrimSpace(s); s != "" {
			svcs = append(svcs, s)
		}
	}
	if len(svcs) == 0 || o.api == "" || o.key == "" || o.project == "" {
		return errors.New(usage + "\n--services, --api, --key and --project are required")
	}
	if o.version == "" {
		for _, e := range ciSHAEnv {
			if o.version = os.Getenv(e); o.version != "" {
				break
			}
		}
	}
	if o.version == "" {
		sha, err := git(ctx, o.dir, "rev-parse", "HEAD")
		if err != nil {
			return errors.New("no --release and no commit sha from CI env or git: " + err.Error())
		}
		o.version = strings.TrimSpace(sha)
	}
	base := strings.TrimRight(o.api, "/") + "/v1/projects/" + url.PathEscape(o.project)
	rel := map[string]any{"version": o.version}
	if cs, err := gitCommits(ctx, o.dir, o.version); err == nil && len(cs) > 0 && strings.HasPrefix(cs[0].SHA, o.version[:min(7, len(o.version))]) {
		rel["commits"] = cs[:1]
		fmt.Fprintf(out, "commit %.10s %s <%s>\n", cs[0].SHA, cs[0].Message, cs[0].AuthorEmail)
	}
	if ref := firstEnv("GITHUB_REF_NAME", "CI_COMMIT_REF_NAME", "BUILDKITE_BRANCH", "CIRCLE_BRANCH"); ref != "" {
		rel["ref"] = ref
	}
	if err := call(ctx, http.MethodPost, base+"/releases", o.key, rel, nil); err != nil {
		return fmt.Errorf("release %s: %w", o.version, err)
	}
	envID, err := findEnvID(ctx, base, o.key, envName)
	if err != nil {
		return err
	}
	for _, s := range svcs {
		dep := map[string]any{"version": o.version, "env_id": envID, "service": s, "status": status,
			"source": ciSource(), "external_id": o.version + "/" + s + "/" + envID}
		if err := call(ctx, http.MethodPost, base+"/deployments", o.key, dep, nil); err != nil {
			return fmt.Errorf("deployment of %s: %w", s, err)
		}
		fmt.Fprintf(out, "deployed %s@%.10s to %s (%s)\n", s, o.version, envName, status)
	}
	return nil
}

func findEnvID(ctx context.Context, base, key, name string) (string, error) {
	var envs struct{ Data []struct{ ID, Name string } }
	if err := call(ctx, http.MethodGet, base+"/environments?limit=200", key, nil, &envs); err != nil {
		return "", err
	}
	for _, e := range envs.Data {
		if e.Name == name || e.ID == name {
			return e.ID, nil
		}
	}
	return "", errors.New("no environment named " + name)
}
