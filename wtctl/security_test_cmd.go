package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const securityUsage = "usage: wtctl security test <rule.yaml> <sample.ndjson> --api <url> --key <key> --project <id> [--expect-signals N]\n" +
	"  rule.yaml: a SecurityRule manifest (or just its spec): query, detection, cases, group_by, params.\n" +
	"  sample.ndjson: one {\"ts\": <unix seconds>, \"attrs\": {\"key\": \"value\"}} per line."

type securityTestResult struct {
	Matched int `json:"matched"`
	Signals []struct {
		Entity   string `json:"entity"`
		Severity string `json:"severity"`
		Hits     uint64 `json:"hits"`
	} `json:"signals"`
}

// securityMain is `wtctl security ...`.
func securityMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) < 1 || args[0] != "test" {
		return errors.New(securityUsage)
	}
	return securityTest(ctx, args[1:], out)
}

// ruleSpec reads a rule file: a full manifest (spec: ...) or the bare spec. Only the fields the
// test route takes are kept.
func ruleSpec(src []byte) (map[string]any, error) {
	var doc map[string]any
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, err
	}
	if s, ok := doc["spec"].(map[string]any); ok {
		doc = s
	}
	spec := map[string]any{}
	for _, k := range []string{"query", "detection", "cases", "group_by", "params"} {
		if v, ok := doc[k]; ok {
			spec[k] = v
		}
	}
	if spec["query"] == nil || spec["detection"] == nil {
		return nil, errors.New("the rule needs query and detection")
	}
	return spec, nil
}

// sampleEvents reads NDJSON events; blank lines are skipped.
func sampleEvents(r io.Reader) ([]map[string]any, error) {
	var evs []map[string]any
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var e map[string]any
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("sample line %d: %w", n, err)
		}
		evs = append(evs, e)
	}
	return evs, sc.Err()
}

func securityTest(ctx context.Context, args []string, out io.Writer) error {
	var o rulesOpts
	fs := o.flags("security test")
	expect := fs.Int("expect-signals", -1, "fail unless exactly this many signals are raised")
	if len(args) < 2 || strings.HasPrefix(args[0], "-") || strings.HasPrefix(args[1], "-") {
		return errors.New(securityUsage)
	}
	if err := fs.Parse(args[2:]); err != nil {
		return err
	}
	if o.api == "" || o.key == "" || o.project == "" {
		return errors.New("--api, --key and --project are required")
	}
	src, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	spec, err := ruleSpec(src)
	if err != nil {
		return err
	}
	f, err := os.Open(args[1])
	if err != nil {
		return err
	}
	defer f.Close()
	evs, err := sampleEvents(f)
	if err != nil {
		return err
	}
	spec["events"] = evs
	var res securityTestResult
	u := strings.TrimRight(o.api, "/") + "/v1/projects/" + url.PathEscape(o.project) + "/security/rules/test"
	if err := call(ctx, http.MethodPost, u, o.key, spec, &res); err != nil {
		return err
	}
	fmt.Fprintf(out, "%d of %d events matched the query\n", res.Matched, len(evs))
	for _, s := range res.Signals {
		fmt.Fprintf(out, "SIGNAL %s entity=%s hits=%d\n", s.Severity, s.Entity, s.Hits)
	}
	if *expect >= 0 && len(res.Signals) != *expect {
		return fmt.Errorf("expected %d signals, the rule raised %d", *expect, len(res.Signals))
	}
	return nil
}
