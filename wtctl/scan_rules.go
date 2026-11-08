package main

// Open SAST rule set for `wtctl scan` (D2 Code Security). A small, portable set of regex rules
// over source text; each hit becomes a SARIF result that the server ingests as a `code` finding.
// shortcut: these are line-level regex rules, not a dataflow engine, so they find obvious sinks
// and secrets, not taint across functions. Upgrade by shelling out to Semgrep/CodeQL and
// uploading its SARIF to the same endpoint (the server accepts any SARIF).

import (
	"io/fs"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"strings"
)

// scanRule is one open rule. severity is the GitHub `security-severity` 0..10 convention.
type scanRule struct {
	id       string
	name     string
	severity string
	exts     []string // file extensions it applies to; empty = all text files
	re       *regexp.Regexp
}

// rules is the built-in rule set. Patterns are deliberately conservative to keep noise low.
var rules = []scanRule{
	{"sast/eval-user-input", "Dynamic code evaluation", "8.8", []string{".js", ".ts", ".py", ".rb", ".php"},
		regexp.MustCompile(`(?i)\b(eval|exec)\s*\(`)},
	{"sast/sql-string-concat", "SQL built by string concatenation", "8.1", []string{".js", ".ts", ".py", ".go", ".rb", ".php", ".java"},
		regexp.MustCompile(`(?i)(select|insert|update|delete)\s+.*(\+\s*|%s|\$\{|f")`)},
	{"sast/command-injection", "Shell command from a variable", "9.1", []string{".js", ".ts", ".py", ".go", ".rb", ".php", ".java"},
		regexp.MustCompile(`(?i)(exec\.command|child_process|os\.system|subprocess\.|Runtime\.getRuntime)`)},
	{"sast/weak-hash", "Weak hash (MD5/SHA1)", "4.0", nil,
		regexp.MustCompile(`(?i)\b(md5|sha1)\b`)},
	{"sast/hardcoded-secret", "Hardcoded secret", "7.5", nil,
		regexp.MustCompile(`(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*["'][A-Za-z0-9/\+_\-]{16,}["']`)},
	{"sast/insecure-random", "Insecure randomness for a security value", "5.3", []string{".js", ".ts", ".py", ".java"},
		regexp.MustCompile(`(?i)math\.random\s*\(|random\.random\s*\(`)},
}

// skipDir names directories a scan never descends into.
var skipDir = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "target": true,
	"dist": true, "build": true, ".venv": true, "testdata": true,
}

// textExt is the set of extensions scanned when a rule has no extension filter.
var textExt = map[string]bool{
	".js": true, ".ts": true, ".jsx": true, ".tsx": true, ".py": true, ".go": true,
	".rb": true, ".php": true, ".java": true, ".cs": true, ".rs": true, ".kt": true,
	".scala": true, ".c": true, ".cc": true, ".cpp": true, ".h": true,
}

const maxFileBytes = 1 << 20 // 1 MiB: scan source, not generated blobs.

// scanSource runs the rule set over the text of one file and returns its results. Exposed for the
// unit test; the walker calls it per file.
func scanSource(path, content string) []sarifResult {
	ext := strings.ToLower(filepath.Ext(path))
	var out []sarifResult
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		for _, r := range rules {
			if len(r.exts) > 0 && !contains(r.exts, ext) {
				continue
			}
			if r.re.MatchString(line) {
				out = append(out, sarifResult{
					RuleID:  r.id,
					Level:   "warning",
					Message: sarifMessage{Text: r.name},
					Locations: []sarifLocation{{Physical: sarifPhysical{
						Artifact: sarifArtifact{URI: path},
						Region:   sarifRegion{StartLine: i + 1},
					}}},
				})
			}
		}
	}
	return out
}

// scanTree walks root and scans every eligible source file, returning a full SARIF log. Unreadable
// files are skipped, not fatal: a scan reports what it can.
func scanTree(root string, read func(string) ([]byte, error), walk walkFn) (sarifLog, error) {
	var results []sarifResult
	goPkgs, jsPkgs, pyPkgs := map[string][]taintFile{}, map[string][]taintFile{}, map[string][]taintFile{}
	err := walk(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip the unreadable entry, keep scanning
		}
		if d.IsDir() {
			if skipDir[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if !textExt[ext] {
			return nil
		}
		b, rerr := read(path)
		if rerr != nil || len(b) > maxFileBytes {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)
		results = append(results, scanSource(rel, string(b))...)
		if ext == ".go" && !strings.HasSuffix(rel, "_test.go") {
			goPkgs[pathpkg.Dir(rel)] = append(goPkgs[pathpkg.Dir(rel)], taintFile{rel, string(b)})
		}
		base := pathpkg.Base(rel)
		if ext == ".js" && !strings.HasSuffix(base, ".test.js") && !strings.HasSuffix(base, ".spec.js") {
			jsPkgs[pathpkg.Dir(rel)] = append(jsPkgs[pathpkg.Dir(rel)], taintFile{rel, string(b)})
		}
		if ext == ".py" && !strings.HasPrefix(base, "test_") && !strings.HasSuffix(base, "_test.py") {
			pyPkgs[pathpkg.Dir(rel)] = append(pyPkgs[pathpkg.Dir(rel)], taintFile{rel, string(b)})
		}
		return nil
	})
	if err != nil {
		return sarifLog{}, err
	}
	for _, files := range goPkgs {
		results = append(results, taintScan(files)...)
	}
	for _, files := range jsPkgs {
		results = append(results, taintScanJS(files)...)
	}
	for _, files := range pyPkgs {
		results = append(results, taintScanPy(files)...)
	}
	return newSarifLog(results), nil
}

type walkFn func(root string, fn fs.WalkDirFunc) error

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// --- SARIF v2.1.0 (just the fields the server reads) ---

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name  string          `json:"name"`
	Rules []sarifRuleMeta `json:"rules"`
}

type sarifRuleMeta struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	Properties sarifRuleProps `json:"properties"`
}

type sarifRuleProps struct {
	SecuritySeverity string `json:"security-severity"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	Physical sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	Artifact sarifArtifact `json:"artifactLocation"`
	Region   sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// newSarifLog wraps results in a run whose driver declares every built-in rule (with its
// security-severity), so the server ranks findings by severity.
func newSarifLog(results []sarifResult) sarifLog {
	meta := make([]sarifRuleMeta, 0, len(rules))
	for _, r := range rules {
		meta = append(meta, sarifRuleMeta{ID: r.id, Name: r.name,
			Properties: sarifRuleProps{SecuritySeverity: r.severity}})
	}
	for _, r := range taintRules {
		meta = append(meta, sarifRuleMeta{ID: r.id, Name: r.name,
			Properties: sarifRuleProps{SecuritySeverity: r.severity}})
	}
	return sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: "wtctl-scan", Rules: meta}},
			Results: results,
		}},
	}
}
