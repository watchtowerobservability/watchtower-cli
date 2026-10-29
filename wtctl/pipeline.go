package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"github.com/watchtowerobservability/watchtower-cli/internal/netguard"

	"gopkg.in/yaml.v3"

	"github.com/watchtowerobservability/watchtower-cli/internal/ascode"
)

const pipelineUsage = "usage: wtctl pipeline validate <config.json|yaml> --project <id> [--api <url>] [--key <key>]\n" +
	"       wtctl pipeline test <config.json|yaml> --samples <records.json> [--signal logs|spans|metrics] --project <id>\n" +
	"       wtctl pipeline diff --id <pipeline> --from <n> --to <n> --project <id>\n" +
	"       wtctl pipeline impact --id <pipeline> --version <n> --project <id>\n" +
	"       wtctl pipeline tap --id <pipeline> --project <id>"

type pipelineOpts struct {
	api, key, project, id, samples, signal string
	from, to, version                      int
}

// pipelineMain is `wtctl pipeline validate|test|diff|impact|tap`: the pipeline editor's checks
// from a terminal or CI, against the same API the editor uses.
func pipelineMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) < 1 {
		return errors.New(pipelineUsage)
	}
	var o pipelineOpts
	fs := flag.NewFlagSet("pipeline "+args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.api, "api", os.Getenv("WT_API"), "API base URL; default $WT_API")
	fs.StringVar(&o.key, "key", os.Getenv("WT_API_KEY"), "API key; default $WT_API_KEY")
	fs.StringVar(&o.project, "project", os.Getenv("WT_PROJECT"), "project id; default $WT_PROJECT")
	fs.StringVar(&o.id, "id", "", "pipeline id")
	fs.StringVar(&o.samples, "samples", "", "JSON file with an array of sample records")
	fs.StringVar(&o.signal, "signal", "logs", "logs, spans or metrics")
	fs.IntVar(&o.from, "from", 0, "version to compare from")
	fs.IntVar(&o.to, "to", 0, "version to compare to")
	fs.IntVar(&o.version, "version", 0, "version number")
	// the config file is the one positional argument, allowed before or after the flags
	var file string
	rest := args[1:]
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		file, rest = rest[0], rest[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return fmt.Errorf("%w\n%s", err, pipelineUsage)
	}
	c, err := ascode.New(o.api, o.key, o.project, netguard.Guarded("wtctl", 0))
	if err != nil {
		return err
	}
	switch args[0] {
	case "validate":
		return pipelineSimulate(ctx, c, file, "", o.signal, out, true)
	case "test":
		return pipelineSimulate(ctx, c, file, o.samples, o.signal, out, false)
	case "diff":
		return pipelineDiff(ctx, c, o, out)
	case "impact":
		return pipelineImpact(ctx, c, o, out)
	case "tap":
		return pipelineTap(ctx, c, o, out)
	}
	return errors.New(pipelineUsage)
}

// loadAny reads a JSON or YAML file into a value the API accepts as JSON.
func loadAny(path string) (any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v any
	if strings.EqualFold(filepath.Ext(path), ".json") {
		err = json.Unmarshal(b, &v)
	} else {
		err = yaml.Unmarshal(b, &v)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return v, nil
}

func pipelineSimulate(ctx context.Context, c *ascode.Client, file, samples, signal string, out io.Writer, validateOnly bool) error {
	if file == "" {
		return errors.New("a config file is required\n" + pipelineUsage)
	}
	cfg, err := loadAny(file)
	if err != nil {
		return err
	}
	records := []any{}
	if !validateOnly {
		if samples == "" {
			return errors.New("--samples is required\n" + pipelineUsage)
		}
		v, err := loadAny(samples)
		if err != nil {
			return err
		}
		list, ok := v.([]any)
		if !ok {
			return fmt.Errorf("%s: want an array of records", samples)
		}
		records = list
	}
	var res struct {
		Diffs []struct {
			Index     int     `json:"index"`
			DroppedBy *string `json:"dropped_by"`
			Aborted   bool    `json:"aborted"`
			Changes   []struct {
				Field  string  `json:"field"`
				Before *string `json:"before"`
				After  *string `json:"after"`
			} `json:"changes"`
		} `json:"diffs"`
	}
	body := map[string]any{"signal": signal, "config": cfg, "records": records}
	if err := c.Do(ctx, http.MethodPost, "pipelines/simulate", nil, body, &res); err != nil {
		return err
	}
	if validateOnly {
		fmt.Fprintln(out, "valid")
		return nil
	}
	dropped := 0
	for _, d := range res.Diffs {
		switch {
		case d.DroppedBy != nil:
			dropped++
			fmt.Fprintf(out, "record %d: dropped by %s\n", d.Index, *d.DroppedBy)
		case len(d.Changes) == 0:
			fmt.Fprintf(out, "record %d: unchanged\n", d.Index)
		default:
			fmt.Fprintf(out, "record %d:\n", d.Index)
			for _, ch := range d.Changes {
				fmt.Fprintf(out, "  %s: %s -> %s\n", ch.Field, show(ch.Before), show(ch.After))
			}
		}
	}
	fmt.Fprintf(out, "%d records, %d dropped\n", len(res.Diffs), dropped)
	return nil
}

func show(s *string) string {
	if s == nil {
		return "(none)"
	}
	return fmt.Sprintf("%q", *s)
}

func pipelineDiff(ctx context.Context, c *ascode.Client, o pipelineOpts, out io.Writer) error {
	if o.id == "" || o.from <= 0 || o.to <= 0 {
		return errors.New("--id, --from and --to are required\n" + pipelineUsage)
	}
	var res struct {
		Stages []struct {
			Index  int    `json:"index"`
			Change string `json:"change"`
			Before any    `json:"before"`
			After  any    `json:"after"`
		} `json:"stages"`
	}
	rel := fmt.Sprintf("pipelines/%s/diff?from=%d&to=%d", url.PathEscape(o.id), o.from, o.to)
	if err := c.Do(ctx, http.MethodGet, rel, nil, nil, &res); err != nil {
		return err
	}
	if len(res.Stages) == 0 {
		fmt.Fprintln(out, "no differences")
		return nil
	}
	for _, s := range res.Stages {
		b, _ := json.Marshal(s.After)
		if s.After == nil {
			b, _ = json.Marshal(s.Before)
		}
		fmt.Fprintf(out, "stage %d: %s %s\n", s.Index, s.Change, b)
	}
	return nil
}

func pipelineImpact(ctx context.Context, c *ascode.Client, o pipelineOpts, out io.Writer) error {
	if o.id == "" || o.version <= 0 {
		return errors.New("--id and --version are required\n" + pipelineUsage)
	}
	var res struct {
		Effects []struct {
			Key    string `json:"key"`
			Effect string `json:"effect"`
		} `json:"effects"`
		References []struct {
			Kind string   `json:"kind"`
			Name string   `json:"name"`
			Keys []string `json:"keys"`
		} `json:"references"`
	}
	rel := fmt.Sprintf("pipelines/%s/versions/%d/impact", url.PathEscape(o.id), o.version)
	if err := c.Do(ctx, http.MethodGet, rel, nil, nil, &res); err != nil {
		return err
	}
	for _, e := range res.Effects {
		fmt.Fprintf(out, "%s %s\n", e.Effect, e.Key)
	}
	sort.SliceStable(res.References, func(i, j int) bool { return res.References[i].Kind < res.References[j].Kind })
	for _, r := range res.References {
		fmt.Fprintf(out, "used by %s %q (%s)\n", r.Kind, r.Name, strings.Join(r.Keys, ", "))
	}
	if len(res.References) == 0 {
		fmt.Fprintln(out, "nothing references the changed attributes")
	}
	return nil
}

// pipelineTap prints the SSE tap until the server ends it or ctx is cancelled.
func pipelineTap(ctx context.Context, c *ascode.Client, o pipelineOpts, out io.Writer) error {
	if o.id == "" {
		return errors.New("--id is required\n" + pipelineUsage)
	}
	u := strings.TrimRight(c.API.Server, "/") + "/v1/projects/" + url.PathEscape(c.Project) + "/pipelines/" + url.PathEscape(o.id) + "/tap"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	for _, ed := range c.API.RequestEditors {
		if err := ed(ctx, req); err != nil {
			return err
		}
	}
	resp, err := c.API.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("tap: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	event := ""
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:") && event == "sample":
			fmt.Fprintln(out, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		case strings.HasPrefix(line, "data:") && event == "end":
			return nil
		}
	}
	if err := sc.Err(); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}
