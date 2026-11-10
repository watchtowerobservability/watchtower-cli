package main

// Secret scanning for `wtctl scan` (D2 Code Security): provider token patterns, a Shannon-entropy
// check for generic credentials, and an opt-in scan of git history (`--history`).
//
// Validity is structural, not live: a GitHub token's CRC32 checksum is verified, placeholders and
// low-entropy values are dropped, and the rest are reported as likely. No provider is called, since
// a live check would send the secret to a third party from CI.
// shortcut: no live validity call; add an opt-in `--verify-secrets` per provider if triage needs it.

import (
	"bufio"
	"context"
	"fmt"
	"hash/crc32"
	"math"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type secretRule struct {
	id       string
	name     string
	severity string
	re       *regexp.Regexp
	// check drops a match that is not a real secret (nil: every match counts). It gets the matched text.
	check func(match string) bool
}

const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// githubChecksumOK verifies the trailing six characters of a ghp_/gho_/ghu_/ghs_/ghr_ token: the
// base62 form of the CRC32 of the 30 random characters before them.
func githubChecksumOK(token string) bool {
	if len(token) != 40 {
		return false
	}
	body := token[4:]
	rnd, sum := body[:30], body[30:]
	n := crc32.ChecksumIEEE([]byte(rnd))
	enc := make([]byte, 6)
	for i := 5; i >= 0; i-- {
		enc[i] = base62[n%62]
		n /= 62
	}
	return string(enc) == sum
}

// entropy is the Shannon entropy of s in bits per character.
func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]float64{}
	for _, r := range s {
		freq[r]++
	}
	n := float64(len([]rune(s)))
	var h float64
	for _, c := range freq {
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

var placeholder = regexp.MustCompile(`(?i)example|changeme|change_me|your[_-]|xxxx|<[a-z_ -]+>|\$\{|\{\{|dummy|placeholder|redacted|\*{4}`)

// realSecret is true for a value that looks random enough and is not an obvious placeholder.
func realSecret(v string, minEntropy float64) bool {
	return !placeholder.MatchString(v) && entropy(v) >= minEntropy
}

// lastQuoted returns the quoted value at the end of a "name = 'value'" match.
func lastQuoted(m string) string {
	m = strings.TrimRight(m, `"'`)
	if i := strings.LastIndexAny(m, `"'`); i >= 0 {
		return m[i+1:]
	}
	return m
}

var secretRules = []secretRule{
	{"secret/github-token", "GitHub token", "9.0", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36}\b`), githubChecksumOK},
	{"secret/github-fine-grained", "GitHub fine-grained token", "9.0", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{82}\b`), nil},
	{"secret/gitlab-token", "GitLab personal access token", "9.0", regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{20}\b`), nil},
	{"secret/slack-token", "Slack token", "8.5", regexp.MustCompile(`\bxox[abposr]-[0-9A-Za-z\-]{10,72}`), nil},
	{"secret/slack-webhook", "Slack incoming webhook", "7.0", regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}`), nil},
	{"secret/stripe-live-key", "Stripe live key", "9.0", regexp.MustCompile(`\b[sr]k_live_[0-9A-Za-z]{24,}`), nil},
	{"secret/google-api-key", "Google API key", "7.5", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`), nil},
	{"secret/sendgrid-key", "SendGrid API key", "8.5", regexp.MustCompile(`\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b`), nil},
	{"secret/npm-token", "npm access token", "8.5", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`), nil},
	{"secret/pypi-token", "PyPI upload token", "8.5", regexp.MustCompile(`\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}`), nil},
	{"secret/anthropic-key", "Anthropic API key", "9.0", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{80,}`), nil},
	{"secret/openai-key", "OpenAI API key", "9.0", regexp.MustCompile(`\bsk-(proj-)?[A-Za-z0-9_\-]{40,}`),
		func(m string) bool { return !strings.HasPrefix(m, "sk-ant-") && realSecret(m, 3.8) }},
	{"secret/twilio-key", "Twilio API key", "8.0", regexp.MustCompile(`\bSK[0-9a-f]{32}\b`), func(m string) bool { return realSecret(m, 3.0) }},
	{"secret/shopify-token", "Shopify access token", "8.0", regexp.MustCompile(`\bshpat_[0-9a-f]{32}\b`), nil},
	{"secret/aws-secret-key", "AWS secret access key", "9.0",
		regexp.MustCompile(`(?i)aws[A-Za-z0-9_.\-]{0,20}(secret|private)[A-Za-z0-9_.\-]{0,20}["']?\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}\b`),
		func(m string) bool { return realSecret(m[len(m)-40:], 4.0) }},
	{"secret/high-entropy", "High-entropy credential assigned to a secret-like name", "7.5",
		regexp.MustCompile(`(?i)\b[A-Za-z0-9_\-]*(secret|token|passw(or)?d|api[_-]?key|credential|auth[_-]?key)[A-Za-z0-9_\-]*["']?\s*[:=]\s*["'][A-Za-z0-9/+=_\-.]{20,}["']`),
		func(m string) bool { return realSecret(lastQuoted(m), 3.5) }},
}

// secretExt lists configuration files that carry credentials but are not source, so only the
// secret rules run on them (the SAST rules would flag every `sha1` in a lockfile).
var secretExt = map[string]bool{
	".env": true, ".yml": true, ".yaml": true, ".json": true, ".properties": true, ".toml": true,
	".ini": true, ".conf": true, ".cfg": true, ".tf": true, ".sh": true, ".txt": true,
}

// lockfile names whose hashes look like secrets but are not.
func isLockfile(path string) bool {
	b := filepath.Base(path)
	return strings.HasSuffix(b, "-lock.json") || strings.HasSuffix(b, ".lock") || b == "pnpm-lock.yaml" ||
		b == "go.sum" || b == "package-lock.json" || b == "composer.lock"
}

// secretFile says whether the secret rules apply to a file (source and configuration, not lockfiles).
func secretFile(path string) bool {
	if isLockfile(path) {
		return false
	}
	ext := strings.ToLower(filepath.Ext(path))
	return textExt[ext] || secretExt[ext] || strings.HasPrefix(filepath.Base(path), ".env")
}

// secretHits runs the secret rules over one line and returns the rule and matched text of each hit.
func secretHits(line string) (hits []struct {
	rule  secretRule
	match string
}) {
	for _, r := range secretRules {
		for _, m := range r.re.FindAllString(line, -1) {
			if r.check == nil || r.check(m) {
				hits = append(hits, struct {
					rule  secretRule
					match string
				}{r, m})
				break
			}
		}
	}
	return hits
}

func secretResult(r secretRule, path string, line int, note string) sarifResult {
	return sarifResult{
		RuleID:  r.id,
		Level:   "error",
		Message: sarifMessage{Text: r.name + note},
		Locations: []sarifLocation{{Physical: sarifPhysical{
			Artifact: sarifArtifact{URI: path},
			Region:   sarifRegion{StartLine: line},
		}}},
	}
}

// scanSecrets finds secrets in one file's text. The secret itself is never put in the result.
func scanSecrets(path, content string) []sarifResult {
	if !secretFile(path) {
		return nil
	}
	var out []sarifResult
	for i, line := range strings.Split(content, "\n") {
		if len(line) > 2000 { // minified or generated: not a credential line
			continue
		}
		for _, h := range secretHits(line) {
			out = append(out, secretResult(h.rule, path, i+1, ""))
		}
	}
	return out
}

// historyScan reads `git log -p` text (see gitHistory) and returns a result for every secret on an
// added line, once per (rule, file, secret), naming the commit that introduced it.
func historyScan(patch *bufio.Scanner) []sarifResult {
	var (
		out        []sarifResult
		commit     string
		path       string
		line       int
		seen       = map[string]bool{}
		hunk       = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)`)
		skipBinary bool
	)
	for patch.Scan() {
		t := patch.Text()
		switch {
		case strings.HasPrefix(t, "\x00"):
			commit = strings.TrimPrefix(t, "\x00")
		case strings.HasPrefix(t, "+++ b/"):
			path = strings.TrimPrefix(t, "+++ b/")
			skipBinary = !secretFile(path)
		case strings.HasPrefix(t, "+++ "): // +++ /dev/null: a deletion
			path, skipBinary = "", true
		case strings.HasPrefix(t, "@@"):
			if m := hunk.FindStringSubmatch(t); m != nil {
				line, _ = strconv.Atoi(m[1])
			}
		case strings.HasPrefix(t, "+") && !skipBinary && path != "":
			text := t[1:]
			if len(text) <= 2000 {
				for _, h := range secretHits(text) {
					k := h.rule.id + "\x00" + path + "\x00" + h.match
					if !seen[k] {
						seen[k] = true
						short := commit
						if len(short) > 8 {
							short = short[:8]
						}
						out = append(out, secretResult(h.rule, path, line, fmt.Sprintf(" (in history, commit %s)", short)))
					}
				}
			}
			line++
		}
	}
	return out
}

// gitHistory scans the added lines of the last `depth` commits of every ref under dir.
func gitHistory(ctx context.Context, dir string, depth int) ([]sarifResult, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", dir, "log", "--all", "-p", "-U0", "--no-color",
		"--no-ext-diff", "-n", strconv.Itoa(depth), "--pretty=format:%x00%H")
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("git log: %w", err)
	}
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	res := historyScan(sc)
	if err := cmd.Wait(); err != nil {
		return res, fmt.Errorf("git log: %w", err)
	}
	return res, nil
}
