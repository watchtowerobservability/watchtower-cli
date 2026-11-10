package lsp

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is watchtower.yaml in the repository root.
type Config struct {
	Service      string   `yaml:"service"`
	PathPrefixes []string `yaml:"path_prefixes"`
	Project      string   `yaml:"project"`
}

// LoadConfig reads root/watchtower.yaml. A missing file is not an error: nothing maps.
func LoadConfig(root string) (*Config, error) {
	b, err := os.ReadFile(filepath.Join(root, "watchtower.yaml"))
	if os.IsNotExist(err) {
		return &Config{}, nil
	}
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("watchtower.yaml: %w", err)
	}
	return &c, nil
}

// ServiceFor returns the service for a repo-relative path. No prefixes means the whole repo.
func (c *Config) ServiceFor(rel string) (string, bool) {
	if c == nil || c.Service == "" {
		return "", false
	}
	if len(c.PathPrefixes) == 0 {
		return c.Service, true
	}
	rel = path.Clean(filepath.ToSlash(rel))
	for _, p := range c.PathPrefixes {
		p = strings.TrimSuffix(filepath.ToSlash(p), "/")
		if rel == p || strings.HasPrefix(rel, p+"/") {
			return c.Service, true
		}
	}
	return "", false
}

// Func is a function declaration found in source (0-based line).
type Func struct {
	Name string
	Line int
}

var tsRe = regexp.MustCompile(`^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)|^\s*(?:export\s+)?const\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(`)

// shortcut: one regex per language, not a parser; upgrade to tree-sitter for nested or generated code.
var funcRe = map[string]*regexp.Regexp{
	".go":   regexp.MustCompile(`^func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)`),
	".rs":   regexp.MustCompile(`^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:const\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_]\w*)`),
	".ts":   tsRe,
	".tsx":  tsRe,
	".js":   tsRe,
	".jsx":  tsRe,
	".mjs":  tsRe,
	".py":   regexp.MustCompile(`^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)`),
	".java": regexp.MustCompile(`^\s*(?:(?:public|protected|private|static|final|synchronized|abstract)\s+)+[\w<>\[\],.? ]+\s+([A-Za-z_]\w*)\s*\([^;]*$`),
	".kt":   regexp.MustCompile(`^\s*(?:(?:public|private|protected|internal|override|suspend|inline|open|abstract|operator)\s+)*fun\s+(?:<[^>]*>\s*)?(?:[\w.<>?]+\.)?([A-Za-z_]\w*)\s*\(`),
	".cs":   regexp.MustCompile(`^\s*(?:(?:public|protected|private|internal|static|async|virtual|override|sealed)\s+)+[\w<>\[\],.?]+\s+([A-Za-z_]\w*)\s*\([^;]*$`),
}

// Functions lists function names with their lines for the file extension of name.
func Functions(name, text string) []Func {
	re := funcRe[strings.ToLower(filepath.Ext(name))]
	if re == nil {
		return nil
	}
	var out []Func
	seen := map[string]bool{}
	for i, line := range strings.Split(text, "\n") {
		m := re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		for _, n := range m[1:] {
			if n != "" && !seen[n] {
				seen[n] = true
				out = append(out, Func{Name: n, Line: i})
				break
			}
		}
	}
	return out
}
