package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// Version is the release version, set by the release build with -ldflags "-X main.Version=<v>".
var Version = "dev"

// releaseRepo is the public repository whose GitHub releases carry the wtctl binaries.
const releaseRepo = "watchtowerobservability/watchtower-cli"

// defaultUpdateURL serves the latest release's assets (GitHub redirects to the newest tag).
const defaultUpdateURL = "https://github.com/" + releaseRepo + "/releases/latest/download"

const versionUsage = "usage: wtctl version [--check]   (--check compares with the latest release; $WTCTL_RELEASES_API overrides the lookup)"

func versionMain(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	check := fs.Bool("check", false, "compare with the latest GitHub release")
	if err := fs.Parse(args); err != nil {
		return err
	}
	fmt.Fprintf(out, "wtctl %s (%s/%s, %s)\n", Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
	if !*check {
		return nil
	}
	api := os.Getenv("WTCTL_RELEASES_API")
	if api == "" {
		api = "https://api.github.com/repos/" + releaseRepo + "/releases/latest"
	}
	latest, err := latestRelease(ctx, api)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, versionVerdict(Version, latest))
	return err
}

// latestRelease reads `tag_name` from a GitHub "latest release" answer.
func latestRelease(ctx context.Context, api string) (string, error) {
	b, err := fetch(ctx, api, 1<<20)
	if err != nil {
		return "", err
	}
	var r struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(b, &r); err != nil || r.TagName == "" {
		return "", fmt.Errorf("%s: no tag_name in the answer", api)
	}
	return r.TagName, nil
}

func versionVerdict(current, latest string) string {
	switch {
	case current == "dev":
		return fmt.Sprintf("development build; the latest release is %s", latest)
	case versionLess(current, latest):
		return fmt.Sprintf("%s is available (you have %s): run `wtctl self-update`", latest, current)
	default:
		return fmt.Sprintf("up to date (latest release %s)", latest)
	}
}

// versionLess compares dotted numeric versions (an optional leading v; a pre-release suffix
// after - or + is ignored), so 0.9.1 < 0.10.0.
func versionLess(a, b string) bool {
	parse := func(v string) []int {
		v = strings.TrimPrefix(strings.TrimSpace(v), "v")
		if i := strings.IndexAny(v, "-+"); i >= 0 {
			v = v[:i]
		}
		var out []int
		for _, p := range strings.Split(v, ".") {
			n, _ := strconv.Atoi(p)
			out = append(out, n)
		}
		return out
	}
	x, y := parse(a), parse(b)
	for i := 0; i < max(len(x), len(y)); i++ {
		var p, q int
		if i < len(x) {
			p = x[i]
		}
		if i < len(y) {
			q = y[i]
		}
		if p != q {
			return p < q
		}
	}
	return false
}
