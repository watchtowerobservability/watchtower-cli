package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"github.com/watchtowerobservability/watchtower-cli/internal/repofile"

	"gopkg.in/yaml.v3"
)

// evalsServer fakes the registry and experiment routes; mean is what the evaluator scored.
func evalsServer(mean float64) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/v1/projects/prj_1/llm")
		switch {
		case strings.HasSuffix(p, "/datasets"):
			_, _ = w.Write([]byte(`{"data":[{"id":"ds1","name":"golden"}],"next_cursor":null}`))
		case strings.HasSuffix(p, "/evaluators"):
			_, _ = w.Write([]byte(`{"data":[{"id":"ev1","name":"accuracy"}],"next_cursor":null}`))
		case p == "/prompts:resolve":
			_, _ = w.Write([]byte(`{"prompt_id":"pr1"}`))
		case r.Method == http.MethodPost && p == "/experiments":
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"id":"ex1","status":"running"}`))
		case p == "/experiments/ex1":
			_, _ = w.Write([]byte(`{"id":"ex1","status":"done","summary":{"runs":10,"failed":0}}`))
		case p == "/experiments/ex1/scores":
			_, _ = w.Write([]byte(`{"evaluators":[{"evaluator":"accuracy","mean":` + strconv.FormatFloat(mean, 'f', -1, 64) + `,"n":10}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
}

func runEvals(t *testing.T, api string, extra ...string) (int, string) {
	t.Helper()
	args := append([]string{"run", "--api", api, "--key", "k", "--project", "prj_1", "--dataset", "golden",
		"--prompt", "support@staging", "--evaluators", "accuracy", "--poll", "1ms"}, extra...)
	var out bytes.Buffer
	err := evalsMain(context.Background(), args, &out)
	var ec exitCode
	if errors.As(err, &ec) {
		return int(ec), out.String()
	}
	if err != nil {
		t.Fatal(err)
	}
	return 0, out.String()
}

func TestFailUnderExitCode1(t *testing.T) {
	srv := evalsServer(0.6)
	defer srv.Close()
	code, out := runEvals(t, srv.URL, "--fail-under", "accuracy=0.8")
	if code != 1 || !strings.Contains(out, "FAIL under 0.800") {
		t.Fatalf("code %d out %q", code, out)
	}
	if code, _ = runEvals(t, srv.URL, "--fail-under", "accuracy=0.5"); code != 0 {
		t.Fatalf("passing run exited %d", code)
	}
}

func TestInfraErrorExitCode2(t *testing.T) {
	srv := evalsServer(1)
	srv.Close() // nothing listens
	if code, _ := runEvals(t, srv.URL); code != 2 {
		t.Fatalf("code %d, want 2", code)
	}
	if code, _ := runEvals(t, "http://127.0.0.1:1", "--fail-under", "bogus"); code != 2 {
		t.Fatalf("bad threshold code %d, want 2", code)
	}
}

func TestRegressionFailsWithBaseline(t *testing.T) {
	var c struct {
		Evaluators []compareRow `json:"evaluators"`
	}
	raw := `{"evaluators":[{"evaluator":"accuracy","delta":-0.1,"ci95":[-0.2,-0.05],"regression":true,"regressed_items":["i1"]},` +
		`{"evaluator":"tone","delta":-0.1,"ci95":[-0.2,0.05],"regression":false,"regressed_items":[]}]}`
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatal(err)
	}
	if !c.Evaluators[0].regressed() || c.Evaluators[1].regressed() {
		t.Fatal("the server's regression flag decides")
	}
}

func TestActionYamlValid(t *testing.T) {
	b, err := os.ReadFile(repofile.Path("integrations/github-action/watchtower-evals/action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var a struct {
		Name   string         `yaml:"name"`
		Inputs map[string]any `yaml:"inputs"`
		Runs   struct {
			Using string           `yaml:"using"`
			Steps []map[string]any `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(b, &a); err != nil {
		t.Fatal(err)
	}
	if a.Name == "" || a.Runs.Using != "composite" || len(a.Runs.Steps) == 0 {
		t.Fatalf("unexpected action: %+v", a)
	}
	for _, in := range []string{"api", "key", "project", "dataset", "prompt", "evaluators"} {
		if a.Inputs[in] == nil {
			t.Errorf("missing input %s", in)
		}
	}
}

// pairwiseServer fakes two experiments; the second (candidate) regresses against the first.
func pairwiseServer(t *testing.T, posted *[]map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/v1/projects/prj_1/llm")
		switch {
		case strings.HasSuffix(p, "/datasets"):
			_, _ = w.Write([]byte(`{"data":[{"id":"ds1","name":"golden"}],"next_cursor":null}`))
		case strings.HasSuffix(p, "/evaluators"):
			_, _ = w.Write([]byte(`{"data":[{"id":"ev1","name":"accuracy"}],"next_cursor":null}`))
		case p == "/prompts:resolve":
			_, _ = w.Write([]byte(`{"prompt_id":"pr-` + r.URL.Query().Get("label") + `"}`))
		case r.Method == http.MethodPost && p == "/experiments":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			*posted = append(*posted, body)
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"id":"ex` + strconv.Itoa(len(*posted)) + `","status":"running"}`))
		case strings.HasSuffix(p, "/compare"):
			if r.URL.Query().Get("to") != "ex1" {
				http.Error(w, "wrong baseline", http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"evaluators":[{"evaluator":"accuracy","delta":-0.1,"ci95":[-0.2,-0.05],"regression":true,"regressed_items":["i1"]}]}`))
		case strings.HasSuffix(p, "/scores"):
			_, _ = w.Write([]byte(`{"evaluators":[{"evaluator":"accuracy","mean":0.7,"n":10}]}`))
		case strings.HasPrefix(p, "/experiments/ex"):
			_, _ = w.Write([]byte(`{"id":"` + strings.TrimPrefix(p, "/experiments/") + `","status":"done"}`))
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestPairwiseAndRepetitions(t *testing.T) {
	var posted []map[string]any
	srv := pairwiseServer(t, &posted)
	defer srv.Close()
	code, out := runEvals(t, srv.URL, "--pairwise", "support@prod", "--repetitions", "3")
	if code != 1 || !strings.Contains(out, "REGRESSED") {
		t.Fatalf("code %d out %q", code, out)
	}
	if len(posted) != 2 {
		t.Fatalf("%d experiments posted, want baseline then candidate", len(posted))
	}
	for i, b := range posted {
		if b["repetitions"] != float64(3) {
			t.Fatalf("experiment %d repetitions = %v", i, b["repetitions"])
		}
	}
	if posted[0]["baseline_experiment_id"] != nil || posted[1]["baseline_experiment_id"] != "ex1" {
		t.Fatalf("pairing wrong: %v / %v", posted[0]["baseline_experiment_id"], posted[1]["baseline_experiment_id"])
	}
	tp := func(b map[string]any) any { return b["target"].(map[string]any)["prompt"].(map[string]any)["id"] }
	if tp(posted[0]) != "pr-prod" || tp(posted[1]) != "pr-staging" {
		t.Fatalf("prompts = %v / %v", tp(posted[0]), tp(posted[1]))
	}
}

func TestPRCommentHasBootstrapCI(t *testing.T) {
	var posted []map[string]any
	srv := pairwiseServer(t, &posted)
	defer srv.Close()
	file := filepath.Join(t.TempDir(), "comment.md")
	runEvals(t, srv.URL, "--pairwise", "support@prod", "--comment-out", file)
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"<!-- watchtower-evals -->", "paired bootstrap", "-0.100 [-0.200, -0.050]", "**regressed**"} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("comment lacks %q:\n%s", want, b)
		}
	}
}

func TestPromoteCreatesOnlineRule(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/evaluators"):
			_, _ = w.Write([]byte(`{"data":[{"id":"ev1","name":"accuracy"}],"next_cursor":null}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/eval-rules"):
			_ = json.NewDecoder(r.Body).Decode(&got)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"rule1"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	var out bytes.Buffer
	err := evalsMain(context.Background(), []string{"promote", "--api", srv.URL, "--key", "k", "--project", "prj_1",
		"--evaluator", "accuracy", "--target", "session", "--filter", "service=api", "--sample-rate", "0.2"}, &out)
	if err != nil || got["evaluator_id"] != "ev1" || got["target"] != "session" || !strings.Contains(out.String(), "rule1") {
		t.Fatalf("err %v body %v out %q", err, got, out.String())
	}
	if got["filter"].(map[string]any)["service"] != "api" {
		t.Fatalf("filter = %v", got["filter"])
	}
}
