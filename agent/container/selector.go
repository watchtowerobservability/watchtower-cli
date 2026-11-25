package container

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Selector picks containers by name, image and compose service, on top of the label selector. Every
// non-empty field must match (AND); within a field any entry may match (OR).
type Selector struct {
	// Names are regular expressions (unanchored; use ^ and $) on the container name.
	Names []string `json:"names"`
	// Images are globs (`*`, `?`) on the image reference, with or without its tag or digest, or
	// regular expressions when prefixed `re:`.
	Images []string `json:"images"`
	// Services are globs on the compose service label (com.docker.compose.service).
	Services []string `json:"compose_services"`

	names, images, services []*regexp.Regexp
}

// Active reports whether any field is set.
func (s *Selector) Active() bool {
	return s != nil && len(s.Names)+len(s.Images)+len(s.Services) > 0
}

// SelectorFromEnv adds WT_AGENT_DOCKER_NAMES, _IMAGES and _SERVICES (comma-separated) to s.
func (s *Selector) SelectorFromEnv() {
	for _, e := range []struct {
		env string
		to  *[]string
	}{{"WT_AGENT_DOCKER_NAMES", &s.Names}, {"WT_AGENT_DOCKER_IMAGES", &s.Images}, {"WT_AGENT_DOCKER_SERVICES", &s.Services}} {
		for _, v := range strings.Split(os.Getenv(e.env), ",") {
			if v = strings.TrimSpace(v); v != "" {
				*e.to = append(*e.to, v)
			}
		}
	}
}

// Compile validates the patterns; Match needs it first.
func (s *Selector) Compile() error {
	var err error
	if s.names, err = compileAll(s.Names, false); err != nil {
		return fmt.Errorf("select.names: %w", err)
	}
	if s.images, err = compileAll(s.Images, true); err != nil {
		return fmt.Errorf("select.images: %w", err)
	}
	if s.services, err = compileAll(s.Services, true); err != nil {
		return fmt.Errorf("select.compose_services: %w", err)
	}
	return nil
}

func compileAll(pats []string, glob bool) ([]*regexp.Regexp, error) {
	var out []*regexp.Regexp
	for _, p := range pats {
		g := glob
		if re, ok := strings.CutPrefix(p, "re:"); ok && g {
			p, g = re, false
		}
		if g {
			p = "^" + strings.NewReplacer(`\*`, ".*", `\?`, ".").Replace(regexp.QuoteMeta(p)) + "$"
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, err
		}
		out = append(out, re)
	}
	return out, nil
}

func anyMatch(res []*regexp.Regexp, vs ...string) bool {
	if len(res) == 0 {
		return true
	}
	for _, re := range res {
		for _, v := range vs {
			if re.MatchString(v) {
				return true
			}
		}
	}
	return false
}

// Match reports whether a container passes; an inactive selector passes everything.
func (s *Selector) Match(name, image string, labels map[string]string) bool {
	if !s.Active() {
		return true
	}
	bare := image
	if i := strings.IndexByte(bare, '@'); i >= 0 {
		bare = bare[:i]
	}
	if i := strings.LastIndexByte(bare, ':'); i > strings.LastIndexByte(bare, '/') {
		bare = bare[:i]
	}
	if len(s.services) > 0 && labels[ComposeServiceLabel] == "" {
		return false
	}
	return anyMatch(s.names, name) && anyMatch(s.images, image, bare) && anyMatch(s.services, labels[ComposeServiceLabel])
}
