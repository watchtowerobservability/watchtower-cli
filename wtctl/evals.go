package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const evalsUsage = "usage: wtctl evals run --dataset <name> --prompt <name>@<label> --evaluators a,b [--fail-under \"accuracy=0.8\"] [--baseline <experiment> | --pairwise <name>@<label>] [--repetitions N] [--from-traces id,id] [--comment-out file.md] --api <url> --key <key> --project <id>\n" +
	"       wtctl evals promote --evaluator <name> [--target trace|span|run|session] [--sample-rate 0.1] [--filter key=value,...] --api <url> --key <key> --project <id>\n" +
	"exit codes: 0 pass, 1 threshold or regression failed, 2 infrastructure error"

type evalsOpts struct {
	api, key, project, dataset, prompt, evaluators, failUnder, baseline, name string
	// pairwise is a second prompt (name@label) run as the baseline experiment on the same dataset;
	// fromTraces seeds the dataset from production traces; commentOut gets the PR comment markdown.
	pairwise, fromTraces, commentOut string
	repetitions                      int
	poll, timeout                    time.Duration
}

func (o *evalsOpts) base() string {
	return strings.TrimRight(o.api, "/") + "/v1/projects/" + url.PathEscape(o.project) + "/llm"
}

// evalsMain is `wtctl evals run`. Failures to reach or use the API are exit 2; a run that
// completes but misses a threshold or regresses against the baseline is exit 1.
func evalsMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) >= 1 && args[0] == "promote" {
		return promoteMain(ctx, args[1:], out)
	}
	if len(args) < 1 || args[0] != "run" {
		return errors.New(evalsUsage)
	}
	var o evalsOpts
	fs := flag.NewFlagSet("evals run", flag.ContinueOnError)
	fs.StringVar(&o.api, "api", "", "API base URL")
	fs.StringVar(&o.key, "key", os.Getenv("WT_API_KEY"), "API key; default $WT_API_KEY")
	fs.StringVar(&o.project, "project", "", "project id")
	fs.StringVar(&o.dataset, "dataset", "", "dataset name")
	fs.StringVar(&o.prompt, "prompt", "", "prompt as name@label (folder/name@label for a folder)")
	fs.StringVar(&o.evaluators, "evaluators", "", "comma-separated evaluator names")
	fs.StringVar(&o.failUnder, "fail-under", "", "evaluator=min pairs, comma-separated")
	fs.StringVar(&o.baseline, "baseline", "", "baseline experiment name or id; a regression fails the run")
	fs.StringVar(&o.name, "name", "", "experiment name (default ci-<unix time>)")
	fs.StringVar(&o.pairwise, "pairwise", "", "baseline prompt name@label: run it first on the same dataset and compare pairwise")
	fs.StringVar(&o.fromTraces, "from-traces", "", "comma-separated trace ids copied into the dataset first (created when missing)")
	fs.StringVar(&o.commentOut, "comment-out", "", "write the pull request comment (with bootstrap intervals) to this file")
	fs.IntVar(&o.repetitions, "repetitions", 1, "repetitions per item (1 to 50)")
	fs.DurationVar(&o.poll, "poll", 5*time.Second, "poll interval")
	fs.DurationVar(&o.timeout, "timeout", 30*time.Minute, "give up waiting after this long")
	if err := fs.Parse(args[1:]); err != nil {
		return exitCode(2)
	}
	if o.baseline != "" && o.pairwise != "" {
		fmt.Fprintln(os.Stderr, "evals: use --baseline or --pairwise, not both")
		return exitCode(2)
	}
	if o.api == "" || o.key == "" || o.project == "" || o.dataset == "" || o.prompt == "" || o.evaluators == "" {
		fmt.Fprintln(os.Stderr, evalsUsage)
		return exitCode(2)
	}
	thresholds, err := parseThresholds(o.failUnder)
	if err != nil {
		fmt.Fprintln(os.Stderr, "evals:", err)
		return exitCode(2)
	}
	failed, err := evalsRun(ctx, o, thresholds, out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "evals: infrastructure error:", err)
		return exitCode(2)
	}
	if failed {
		return exitCode(1)
	}
	return nil
}

func parseThresholds(s string) (map[string]float64, error) {
	m := map[string]float64{}
	for _, p := range strings.Split(s, ",") {
		if strings.TrimSpace(p) == "" {
			continue
		}
		k, v, ok := strings.Cut(p, "=")
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if !ok || err != nil {
			return nil, fmt.Errorf("--fail-under %q: want evaluator=number", p)
		}
		m[strings.TrimSpace(k)] = f
	}
	return m, nil
}

var errNotFound = errors.New("not found")

// idByName pages a list route until an item has the name (or id).
func idByName(ctx context.Context, key, listURL, name string) (string, error) {
	cursor := ""
	for {
		var page struct {
			Data []struct{ ID, Name string } `json:"data"`
			Next string                      `json:"next_cursor"`
		}
		u := listURL + "?limit=200"
		if cursor != "" {
			u += "&cursor=" + url.QueryEscape(cursor)
		}
		if err := call(ctx, http.MethodGet, u, key, nil, &page); err != nil {
			return "", err
		}
		for _, d := range page.Data {
			if d.Name == name || d.ID == name {
				return d.ID, nil
			}
		}
		if page.Next == "" {
			return "", fmt.Errorf("%w: %q at %s", errNotFound, name, listURL)
		}
		cursor = page.Next
	}
}

type summaryRow struct {
	Mean float64 `json:"mean"`
	N    int     `json:"n"`
}

// experiment is the part of GET experiments/{id} this command reads (P5-E4: status is queued,
// running, done, failed or cancelled; scores come from GET experiments/{id}/scores).
type experiment struct {
	ID      string                `json:"id"`
	Status  string                `json:"status"`
	Summary map[string]summaryRow `json:"-"`
}

// compareRow is one entry of GET experiments/{id}/compare?to= (a is this experiment, b the baseline).
type compareRow struct {
	Name           string     `json:"evaluator"`
	MeanA          float64    `json:"mean_a"`
	MeanB          float64    `json:"mean_b"`
	Delta          float64    `json:"delta"`
	CI95           [2]float64 `json:"ci95"`
	Regression     bool       `json:"regression"`
	RegressedItems []string   `json:"regressed_items"`
}

// regressed is the server's verdict: the candidate is worse and the 95% interval excludes zero.
func (c compareRow) regressed() bool { return c.Regression }

// promptRef resolves name@label (folder/name@label for a folder) to the prompt id.
func promptRef(ctx context.Context, o evalsOpts, base, prompt string) (id, label string, err error) {
	pname, label, _ := strings.Cut(prompt, "@")
	folder := ""
	if i := strings.LastIndex(pname, "/"); i >= 0 {
		folder, pname = pname[:i], pname[i+1:]
	}
	q := url.Values{"name": {pname}, "folder": {folder}}
	if label != "" {
		q.Set("label", label)
	}
	var res struct {
		PromptID string `json:"prompt_id"`
	}
	if err := call(ctx, http.MethodGet, base+"/prompts:resolve?"+q.Encode(), o.key, nil, &res); err != nil {
		return "", "", err
	}
	return res.PromptID, label, nil
}

// startExperiment queues one experiment of a prompt over the dataset.
func startExperiment(ctx context.Context, o evalsOpts, base, dsID string, evalIDs []string, prompt, name, baseID string) (experiment, error) {
	pid, label, err := promptRef(ctx, o, base, prompt)
	if err != nil {
		return experiment{}, err
	}
	body := map[string]any{
		"name": name, "dataset_id": dsID, "evaluator_ids": evalIDs, "repetitions": o.repetitions,
		"target": map[string]any{"prompt": map[string]any{"id": pid, "label": label}},
	}
	if baseID != "" {
		body["baseline_experiment_id"] = baseID
	}
	var made experiment
	err = call(ctx, http.MethodPost, base+"/experiments", o.key, body, &made)
	return made, err
}

// datasetFromTraces finds the dataset by name (creating it when missing) and copies the traces'
// inputs and outputs into it, so a CI gate can run on what production actually saw.
func datasetFromTraces(ctx context.Context, o evalsOpts, base string) (string, error) {
	id, err := idByName(ctx, o.key, base+"/datasets", o.dataset)
	if errors.Is(err, errNotFound) {
		var made struct {
			ID string `json:"id"`
		}
		err = call(ctx, http.MethodPost, base+"/datasets", o.key,
			map[string]any{"name": o.dataset, "description": "seeded from production traces"}, &made)
		id = made.ID
	}
	if err != nil {
		return "", err
	}
	var ids []string
	for _, t := range strings.Split(o.fromTraces, ",") {
		if t = strings.TrimSpace(t); t != "" {
			ids = append(ids, t)
		}
	}
	err = call(ctx, http.MethodPost, base+"/datasets/"+url.PathEscape(id)+"/items:from-traces", o.key,
		map[string]any{"trace_ids": ids, "split": "test"}, nil)
	return id, err
}

func evalsRun(ctx context.Context, o evalsOpts, thresholds map[string]float64, out io.Writer) (bool, error) {
	base := o.base()
	var dsID string
	var err error
	if o.fromTraces != "" {
		dsID, err = datasetFromTraces(ctx, o, base)
	} else {
		dsID, err = idByName(ctx, o.key, base+"/datasets", o.dataset)
	}
	if err != nil {
		return false, err
	}
	var evalIDs []string
	for _, n := range strings.Split(o.evaluators, ",") {
		id, err := idByName(ctx, o.key, base+"/evaluators", strings.TrimSpace(n))
		if err != nil {
			return false, err
		}
		evalIDs = append(evalIDs, id)
	}
	if o.name == "" {
		o.name = "ci-" + strconv.FormatInt(time.Now().Unix(), 10)
	}
	baseID := ""
	switch {
	case o.pairwise != "":
		// the same dataset, evaluators and repetitions, so the paired comparison is like for like
		b, err := startExperiment(ctx, o, base, dsID, evalIDs, o.pairwise, o.name+"-base", "")
		if err != nil {
			return false, err
		}
		be, err := waitExperiment(ctx, o, base+"/experiments/"+b.ID)
		if err != nil {
			return false, err
		}
		if be.Status != "done" {
			return false, fmt.Errorf("baseline experiment %s ended %s", b.ID, be.Status)
		}
		baseID = b.ID
	case o.baseline != "":
		if baseID, err = idByName(ctx, o.key, base+"/experiments", o.baseline); err != nil {
			return false, err
		}
	}
	made, err := startExperiment(ctx, o, base, dsID, evalIDs, o.prompt, o.name, baseID)
	if err != nil {
		return false, err
	}
	exp, err := waitExperiment(ctx, o, base+"/experiments/"+made.ID)
	if err != nil {
		return false, err
	}
	failed := exp.Status != "done"
	if failed {
		fmt.Fprintf(out, "experiment %s ended %s\n", exp.ID, exp.Status)
	}
	if !failed { // a failed or cancelled experiment has nothing to wait for
		if exp.Summary, err = waitScores(ctx, o, base+"/experiments/"+made.ID+"/scores", len(evalIDs)); err != nil {
			return false, err
		}
	}
	var cmp []compareRow
	if baseID != "" {
		var c struct {
			Evaluators []compareRow `json:"evaluators"`
		}
		if err := call(ctx, http.MethodGet, base+"/experiments/"+made.ID+"/compare?to="+url.QueryEscape(baseID), o.key, nil, &c); err != nil {
			return false, err
		}
		cmp = c.Evaluators
	}
	failed = printEvalTable(out, exp, thresholds, cmp) || failed
	if o.commentOut != "" {
		body := evalCommentBody(commentRows(exp, thresholds, cmp), o.repetitions, o.name)
		if err := os.WriteFile(o.commentOut, []byte(body), 0o600); err != nil {
			return false, err
		}
	}
	return failed, nil
}

// commentRows maps the result table to the PR comment rows; the interval is the server's paired
// bootstrap over items (and repetitions) against the baseline experiment.
func commentRows(e experiment, thresholds map[string]float64, cmp []compareRow) []evalRow {
	byName := map[string]compareRow{}
	for _, c := range cmp {
		byName[c.Name] = c
	}
	names := make([]string, 0, len(e.Summary))
	for n := range e.Summary {
		names = append(names, n)
	}
	sort.Strings(names)
	rows := make([]evalRow, 0, len(names))
	for _, n := range names {
		r := e.Summary[n]
		row := evalRow{Evaluator: n, Mean: r.Mean, N: r.N}
		if lim, ok := thresholds[n]; ok && r.Mean < lim {
			row.Verdict = fmt.Sprintf("below %.3f", lim)
		}
		if c, ok := byName[n]; ok {
			d := c.Delta
			row.Delta, row.CI95, row.Regressed = &d, c.CI95, c.regressed()
		}
		rows = append(rows, row)
	}
	return rows
}

// waitExperiment polls until the experiment is terminal; a wedged one is an infrastructure error.
func waitExperiment(ctx context.Context, o evalsOpts, u string) (experiment, error) {
	deadline := time.Now().Add(o.timeout)
	for {
		var e experiment
		if err := call(ctx, http.MethodGet, u, o.key, nil, &e); err != nil {
			return e, err
		}
		switch e.Status {
		case "done", "failed", "cancelled":
			return e, nil
		}
		if time.Now().After(deadline) {
			return e, fmt.Errorf("experiment %s still %s after %s", e.ID, e.Status, o.timeout)
		}
		select {
		case <-ctx.Done():
			return e, ctx.Err()
		case <-time.After(o.poll):
		}
	}
}

// waitScores reads the per-evaluator means. Evaluators score after the runs finish, so it polls
// until every requested evaluator has a score and the counts stop growing (or the timeout).
func waitScores(ctx context.Context, o evalsOpts, u string, want int) (map[string]summaryRow, error) {
	deadline := time.Now().Add(o.timeout)
	total := -1
	for {
		var r struct {
			Evaluators []struct {
				Evaluator string  `json:"evaluator"`
				Mean      float64 `json:"mean"`
				N         int     `json:"n"`
			} `json:"evaluators"`
		}
		if err := call(ctx, http.MethodGet, u, o.key, nil, &r); err != nil {
			return nil, err
		}
		got, n := map[string]summaryRow{}, 0
		for _, e := range r.Evaluators {
			got[e.Evaluator] = summaryRow{Mean: e.Mean, N: e.N}
			n += e.N
		}
		if (len(got) >= want && n == total) || time.Now().After(deadline) {
			return got, nil
		}
		total = n
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(o.poll):
		}
	}
}

// printEvalTable writes one row per evaluator and reports whether a threshold or the baseline failed.
func printEvalTable(out io.Writer, e experiment, thresholds map[string]float64, cmp []compareRow) bool {
	names := make([]string, 0, len(e.Summary))
	for n := range e.Summary {
		names = append(names, n)
	}
	sort.Strings(names)
	byName := map[string]compareRow{}
	for _, c := range cmp {
		byName[c.Name] = c
	}
	failed := false
	fmt.Fprintf(out, "%-24s %8s %6s %10s  %s\n", "evaluator", "mean", "n", "vs base", "result")
	for _, n := range names {
		r := e.Summary[n]
		verdict, vs := "ok", "-"
		if lim, ok := thresholds[n]; ok && r.Mean < lim {
			verdict, failed = fmt.Sprintf("FAIL under %.3f", lim), true
		}
		if c, ok := byName[n]; ok {
			vs = fmt.Sprintf("%+.3f", c.Delta)
			if c.regressed() {
				verdict, failed = fmt.Sprintf("REGRESSED (%d items)", len(c.RegressedItems)), true
			}
		}
		fmt.Fprintf(out, "%-24s %8.3f %6d %10s  %s\n", n, r.Mean, r.N, vs, verdict)
	}
	for n := range thresholds {
		if _, ok := e.Summary[n]; !ok {
			fmt.Fprintf(out, "%-24s no scores for a --fail-under evaluator\n", n)
			failed = true
		}
	}
	return failed
}

// promoteMain is `wtctl evals promote`: after a merge, turn the evaluator the PR gate used into
// an online `llm_score` rule so production traffic keeps being scored with it.
func promoteMain(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("evals promote", flag.ContinueOnError)
	var api, key, project, evaluator, target, filter string
	var rate float64
	fs.StringVar(&api, "api", "", "API base URL")
	fs.StringVar(&key, "key", os.Getenv("WT_API_KEY"), "API key; default $WT_API_KEY")
	fs.StringVar(&project, "project", "", "project id")
	fs.StringVar(&evaluator, "evaluator", "", "evaluator name")
	fs.StringVar(&target, "target", "trace", "trace, span, run or session")
	fs.StringVar(&filter, "filter", "", "key=value pairs, comma-separated (service, model, operation, outcome, prompt_name)")
	fs.Float64Var(&rate, "sample-rate", 0.1, "share of traces scored, 0 to 1")
	if err := fs.Parse(args); err != nil {
		return exitCode(2)
	}
	if api == "" || key == "" || project == "" || evaluator == "" {
		fmt.Fprintln(os.Stderr, evalsUsage)
		return exitCode(2)
	}
	f := map[string]any{}
	for _, p := range strings.Split(filter, ",") {
		if k, v, ok := strings.Cut(p, "="); ok {
			f[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	base := strings.TrimRight(api, "/") + "/v1/projects/" + url.PathEscape(project) + "/llm"
	id, err := idByName(ctx, key, base+"/evaluators", evaluator)
	var rule struct {
		ID string `json:"id"`
	}
	if err == nil {
		err = call(ctx, http.MethodPost, base+"/eval-rules", key,
			map[string]any{"evaluator_id": id, "target": target, "filter": f, "sample_rate": rate}, &rule)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "evals: infrastructure error:", err)
		return exitCode(2)
	}
	fmt.Fprintf(out, "online rule %s scores %s at %.0f%% of %ss\n", rule.ID, evaluator, rate*100, target)
	return nil
}
