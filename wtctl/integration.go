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
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"

	"github.com/watchtowerobservability/watchtower-cli/agent/integrations"
	"github.com/watchtowerobservability/watchtower-cli/agent/sink"
)

const integrationUsage = "usage: wtctl integration new <name> [--dir integrations]\n" +
	"       wtctl integration validate <manifest.yaml|integration dir|integrations root> [--strict]\n" +
	"       wtctl integration test <manifest.yaml|integration dir> --fixture <recorded payload | fixture dir> [--timeout 2s]"

// integrationMain is `wtctl integration new|validate|test`, the authoring kit for agent
// integration manifests (docs/integrations/authoring.md).
func integrationMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) < 2 {
		return errors.New(integrationUsage)
	}
	fl := flag.NewFlagSet("integration "+args[0], flag.ContinueOnError)
	fl.SetOutput(io.Discard)
	dir := fl.String("dir", "integrations", "new: the integrations root")
	fixture := fl.String("fixture", "", "test: a recorded response of the product (Prometheus text, Jolokia JSON or a status document)")
	strict := fl.Bool("strict", false, "validate: undocumented metrics in queries are errors, not warnings")
	timeout := fl.Duration("timeout", 2*time.Second, "test: how long the collector may run")
	rest := args[2:]
	// the target comes first, flags after it
	if err := fl.Parse(rest); err != nil {
		return fmt.Errorf("%w\n%s", err, integrationUsage)
	}
	switch args[0] {
	case "new":
		return integrationNew(args[1], *dir, out)
	case "validate":
		return integrationValidate(args[1], *strict, out)
	case "test":
		return integrationTest(ctx, args[1], *fixture, *timeout, out)
	}
	return errors.New(integrationUsage)
}

const integrationTemplate = `name: %[1]s
version: "0.1.0"
discovery:
  process_names: ["%[1]s"]
  ports: []
  k8s_labels: {"app.kubernetes.io/name": "%[1]s"}
module:
  kind: prometheus
  config_defaults: {"targets": [{"url": "http://127.0.0.1:9100/metrics", "interval": "30s"}]}
metrics:
  - {name: "%[1]s_up", unit: "1", description: "1 while the product answers."}
dashboards:
  - {"version": 1, "variables": [], "panels": [{"id": "p0", "title": "Up", "type": "timeseries", "grid": {"x": 0, "y": 0, "w": 12, "h": 8}, "query": {"kind": "promql", "text": "max by (host_name) ({__name__=\"%[1]s_up\"})"}, "options": {"unit": "short"}}]}
alerts:
  - name: "%[1]s down"
    rule: {"name": "%[1]s down", "kind": "metric", "query": {"promql": "max by (host_name) ({__name__=\"%[1]s_up\"})"}, "condition": {"threshold": {"op": "lt", "value": 1}}, "every_s": 60, "window_s": 300, "for_s": 180, "severity": "high", "no_data": "ok", "labels": {}, "annotations": {"summary": "%[1]s down", "runbook_url": ""}}
    threshold_rationale: "Three minutes without a healthy answer is an outage, not a blip."
    runbook_url: ""
    default_enabled: true
depends_on: [{"parent_kind": "host", "equal_labels": ["host_name"]}]
logs: {"paths": ["/var/log/%[1]s/*.log"], "pipeline": {"version": 1, "stages": [{"type": "parse_json", "target": "body", "when": "starts_with(body, \"{\")"}]}}
`

func integrationNew(name, root string, out io.Writer) error {
	dir := filepath.Join(root, name)
	if _, err := os.Stat(dir); err == nil {
		return fmt.Errorf("%s already exists", dir)
	}
	text := fmt.Sprintf(integrationTemplate, name)
	if _, err := integrations.Parse([]byte(text)); err != nil {
		return fmt.Errorf("name %q: %w", name, err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.yaml"), []byte(text), 0o644); err != nil {
		return err
	}
	fix := fmt.Sprintf("# TYPE %[1]s_up gauge\n%[1]s_up 1\n", name)
	if err := os.WriteFile(filepath.Join(dir, "fixture.txt"), []byte(fix), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "created %s/manifest.yaml and fixture.txt\nnext: wtctl integration validate %s && wtctl integration test %s --fixture %s\n",
		dir, dir, dir, filepath.Join(dir, "fixture.txt"))
	return nil
}

var nameInQuery = regexp.MustCompile(`__name__\s*=~?\s*\\?"([^"\\]+)\\?"`)

// manifestFiles resolves a manifest file, an integration dir or an integrations root.
func manifestFiles(target string) ([]string, error) {
	st, err := os.Stat(target)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return []string{target}, nil
	}
	if _, err := os.Stat(filepath.Join(target, "manifest.yaml")); err == nil {
		return []string{filepath.Join(target, "manifest.yaml")}, nil
	}
	ms, _ := filepath.Glob(filepath.Join(target, "*", "manifest.yaml"))
	sort.Strings(ms)
	if len(ms) == 0 {
		return nil, fmt.Errorf("no manifest.yaml under %s", target)
	}
	return ms, nil
}

func loadManifest(path string) (*integrations.Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m, err := integrations.Parse(b)
	if err != nil {
		return nil, err
	}
	if base := filepath.Base(filepath.Dir(path)); filepath.Base(path) == "manifest.yaml" && base != m.Name {
		return nil, fmt.Errorf("name %q differs from the directory %q", m.Name, base)
	}
	return m, nil
}

// checkManifest is what `validate` adds to Parse: the module's defaults must be a valid config
// for its kind (errors), and the dashboards and alerts should only query metrics the manifest
// documents (warnings; some shipped manifests predate the rule).
func checkIntegrationManifest(m *integrations.Manifest) (problems, warnings []string) {
	if cfg, err := json.Marshal(m.Module.ConfigDefaults); err == nil {
		if err := integrations.ValidateConfig(m.Module.Kind, cfg); err != nil && !strings.Contains(err.Error(), "is not validated here") {
			problems = append(problems, "module.config_defaults: "+err.Error())
		}
	}
	known := map[string]bool{"wt.integration.up": true}
	for _, d := range m.Metrics {
		known[d.Name] = true
	}
	var docs []string
	for _, d := range m.Dashboards {
		b, _ := json.Marshal(d)
		docs = append(docs, string(b))
	}
	for _, a := range m.Alerts {
		b, _ := json.Marshal(a.Rule["query"])
		docs = append(docs, string(b))
	}
	seen := map[string]bool{}
	for _, doc := range docs {
		for _, sm := range nameInQuery.FindAllStringSubmatch(doc, -1) {
			if !known[sm[1]] && !seen[sm[1]] {
				seen[sm[1]] = true
				warnings = append(warnings, fmt.Sprintf("queries metric %q that metrics: does not document", sm[1]))
			}
		}
	}
	return problems, warnings
}

func integrationValidate(target string, strict bool, out io.Writer) error {
	files, err := manifestFiles(target)
	if err != nil {
		return err
	}
	bad := 0
	for _, f := range files {
		m, err := loadManifest(f)
		var problems, warnings []string
		if err != nil {
			problems = []string{err.Error()}
		} else {
			problems, warnings = checkIntegrationManifest(m)
		}
		if strict {
			problems, warnings = append(problems, warnings...), nil
		}
		for _, p := range problems {
			bad++
			fmt.Fprintf(out, "%s: %s\n", f, p)
		}
		for _, w := range warnings {
			fmt.Fprintf(out, "warning: %s: %s\n", f, w)
		}
	}
	if bad > 0 {
		return fmt.Errorf("%d problem(s) in %d manifest(s)", bad, len(files))
	}
	fmt.Fprintf(out, "ok: %d manifest(s) valid\n", len(files))
	return nil
}

// integrationTest replays a recorded payload through the manifest's collector and compares what
// it emits with what the manifest documents.
func integrationTest(ctx context.Context, target, fixture string, timeout time.Duration, out io.Writer) error {
	files, err := manifestFiles(target)
	if err != nil || len(files) != 1 {
		return errors.New("test takes one manifest or integration directory")
	}
	m, err := loadManifest(files[0])
	if err != nil {
		return err
	}
	var body []byte
	if st, err := os.Stat(fixture); err != nil {
		return err
	} else if !st.IsDir() {
		if body, err = os.ReadFile(fixture); err != nil {
			return err
		}
	}
	rec := &sink.Recorder{}
	up := -1.0
	if st, err := os.Stat(fixture); err == nil && st.IsDir() { // several endpoints or tools: a fixture directory
		if err := replayDir(ctx, m, fixture, timeout, rec); err != nil {
			return err
		}
	} else if m.Module.Kind == "prometheus" { // the generic scraper: parse the recorded text the way it would
		tp := expfmt.NewTextParser(model.UTF8Validation)
		fams, err := tp.TextToMetricFamilies(bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("fixture is not Prometheus text: %w", err)
		}
		integrations.EmitFamilies(rec, fams, nil, time.Now())
		up = 1
	} else if err := replay(ctx, m, body, timeout, rec); err != nil {
		return err
	}
	return compareMetrics(m, rec, up, out)
}

// replay serves body from a local server and runs the manifest's URL-driven collector against it.
func replay(ctx context.Context, m *integrations.Manifest, body []byte, timeout time.Duration, rec *sink.Recorder) error {
	run := integrations.CollectorFor(m.Module.Kind)
	if run == nil {
		return fmt.Errorf("module kind %q is not URL-driven; pass a fixture directory (METHOD_path files, see docs/integrations/authoring.md) or test it with a Go fixture test", m.Module.Kind)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	defer srv.Close()
	cfg := map[string]any{}
	for k, v := range m.Module.ConfigDefaults {
		cfg[k] = v
	}
	cfg["url"], cfg["interval"] = srv.URL, "5s"
	raw, _ := json.Marshal(cfg)
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	_ = run(rctx, raw, rec)
	return nil
}

func compareMetrics(m *integrations.Manifest, rec *sink.Recorder, up float64, out io.Writer) error {
	got := rec.Names()
	var missing, extra []string
	for _, d := range m.Metrics {
		if !got[d.Name] {
			missing = append(missing, d.Name)
		}
		delete(got, d.Name)
	}
	delete(got, "wt.integration.up")
	for n := range got {
		extra = append(extra, n)
	}
	sort.Strings(extra)
	for _, s := range rec.Samples {
		if s.Name == "wt.integration.up" {
			up = s.Value
		}
	}
	fmt.Fprintf(out, "%s: collector %s emitted %d series, up=%v\n", m.Name, m.Module.Kind, len(rec.Samples), up)
	if len(extra) > 0 {
		fmt.Fprintf(out, "note: emitted but not documented in metrics: %s\n", strings.Join(extra, ", "))
	}
	if up != 1 {
		return errors.New("the collector did not run clean against the fixture (up != 1)")
	}
	if len(missing) > 0 {
		return fmt.Errorf("documented but not emitted from the fixture: %s", strings.Join(missing, ", "))
	}
	fmt.Fprintln(out, "ok: every documented metric came out of the fixture")
	return nil
}
