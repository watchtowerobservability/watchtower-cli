package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type ruleTestReport struct {
	Passed bool `json:"passed"`
	Tests  []struct {
		Name     string   `json:"name"`
		Passed   bool     `json:"passed"`
		Failures []string `json:"failures"`
	} `json:"tests"`
}

// ruleTestFiles reads the rule files a promtool test file names (`rule_files`, globs allowed,
// relative to the test file). None: the server tests the project's stored groups.
func ruleTestFiles(testFile string, src []byte) ([]string, error) {
	var doc struct {
		RuleFiles []string `yaml:"rule_files"`
	}
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, err
	}
	out := []string{}
	for _, pat := range doc.RuleFiles {
		if !filepath.IsAbs(pat) {
			pat = filepath.Join(filepath.Dir(testFile), pat)
		}
		matches, err := filepath.Glob(pat)
		if err != nil {
			return nil, err
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("rule_files: %s matches no file", pat)
		}
		for _, m := range matches {
			b, err := os.ReadFile(m)
			if err != nil {
				return nil, err
			}
			out = append(out, string(b))
		}
	}
	return out, nil
}

// rulesTest is `wtctl rules test <test.yaml>`: promtool-style rule unit tests run by the API
// (POST rule-groups:test). Prints one line per test case and fails when any case fails.
func rulesTest(ctx context.Context, args []string, out io.Writer) error {
	var o rulesOpts
	file, err := o.parse(o.flags("rules test"), args)
	if err != nil {
		return err
	}
	src, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	rules, err := ruleTestFiles(file, src)
	if err != nil {
		return err
	}
	u := strings.TrimRight(o.api, "/") + "/v1/projects/" + url.PathEscape(o.project) + "/rule-groups:test"
	var rep ruleTestReport
	body := map[string]any{"rule_files": rules, "tests": string(src)}
	if err := call(ctx, http.MethodPost, u, o.key, body, &rep); err != nil {
		return err
	}
	for _, c := range rep.Tests {
		status := "PASS"
		if !c.Passed {
			status = "FAIL"
		}
		fmt.Fprintf(out, "%s %s\n", status, c.Name)
		for _, f := range c.Failures {
			fmt.Fprintf(out, "    %s\n", f)
		}
	}
	if !rep.Passed {
		return errors.New("rule tests failed")
	}
	return nil
}
