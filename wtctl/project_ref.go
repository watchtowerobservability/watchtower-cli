package main

import (
	"os"
	"regexp"
	"strings"
)

// A project is named by its id, its slug, or `org/slug` (the API takes the last as `org~slug`; the
// alias /v1/orgs/{org}/projects/{slug}/... is the same route). `--project linkhub/linkhub` works
// wherever a project id does, so every command gets the flag value, $WT_PROJECT and a context's
// project rewritten once, before it runs.
var orgSlugRe = regexp.MustCompile(`^[A-Za-z0-9_-]+/[A-Za-z0-9_-]+$`)

// projectRef is org/slug as org~slug; ids, bare slugs and anything else stay.
func projectRef(p string) string {
	if orgSlugRe.MatchString(p) {
		return strings.Replace(p, "/", "~", 1)
	}
	return p
}

// normalizeProjectArgs rewrites the value of --project (and -project, --project=) and $WT_PROJECT.
func normalizeProjectArgs(args []string) []string {
	if v := os.Getenv("WT_PROJECT"); v != "" && projectRef(v) != v {
		_ = os.Setenv("WT_PROJECT", projectRef(v))
	}
	out := make([]string, len(args))
	copy(out, args)
	for i := 0; i < len(out); i++ {
		switch a := out[i]; {
		case a == "--": // the rest is not ours
			return out
		case (a == "--project" || a == "-project") && i+1 < len(out):
			out[i+1] = projectRef(out[i+1])
			i++
		case strings.HasPrefix(a, "--project="):
			out[i] = "--project=" + projectRef(strings.TrimPrefix(a, "--project="))
		case strings.HasPrefix(a, "-project="):
			out[i] = "-project=" + projectRef(strings.TrimPrefix(a, "-project="))
		}
	}
	return out
}
