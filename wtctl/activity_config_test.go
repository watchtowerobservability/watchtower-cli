package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestResolveSecretsFromTheEnvironment(t *testing.T) {
	doc := map[string]any{
		"activity_rules": map[string]any{"storm": map[string]any{"channel": map[string]any{
			"kind": "webhook", "url": "https://x.example/h",
			"secrets": []any{"${NEW_SECRET}", "${OLD_SECRET}"},
		}}},
		"hooks": map[string]any{"digest": map[string]any{"url": "https://x.example/d", "secret": "${DIGEST_SECRET}"}},
	}
	env := map[string]string{"NEW_SECRET": "n-1234567890123456", "OLD_SECRET": "o-1234567890123456", "DIGEST_SECRET": "d-1234567890123456"}
	if err := resolveSecrets(doc, func(k string) string { return env[k] }); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(doc)
	for _, want := range env {
		if !strings.Contains(string(b), want) {
			t.Errorf("%s not resolved in %s", want, b)
		}
	}
	delete(env, "OLD_SECRET")
	doc["activity_rules"].(map[string]any)["storm"].(map[string]any)["channel"].(map[string]any)["secrets"] = []any{"${NEW_SECRET}", "${OLD_SECRET}"}
	err := resolveSecrets(doc, func(k string) string { return env[k] })
	if err == nil || !strings.Contains(err.Error(), "OLD_SECRET") || strings.Contains(err.Error(), "n-1234") {
		t.Fatalf("an unset variable must be named, and no value printed: %v", err)
	}
}

// fakeConfigAPI answers PUT .../config: `changed` says whether the stored config differs.
func fakeConfigAPI(t *testing.T, changed bool, status int) (*httptest.Server, *[]string) {
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, r.URL.RawQuery+" "+string(b))
		if status != 200 {
			http.Error(w, `{"code":"WT422"}`, status)
			return
		}
		changes := `[]`
		if changed {
			changes = `[{"kind":"activity_rule","name":"storm","op":"update","fields":["secret"]}]`
		}
		_, _ = io.WriteString(w, `{"mode":"plan","applied":false,"changed":`+map[bool]string{true: "true", false: "false"}[changed]+`,"changes":`+changes+`}`)
	}))
	t.Cleanup(srv.Close)
	return srv, &bodies
}

func TestConfigPlanExitCodes(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "activity.json")
	_ = os.WriteFile(f, []byte(`{"activity_rules":{"storm":{"channel":{"kind":"webhook","url":"https://x.example/h","secret":"${CFG_TEST_SECRET}"}}}}`), 0o600)
	t.Setenv("CFG_TEST_SECRET", "the-secret-value-123")
	run := func(srv *httptest.Server, extra ...string) (error, string) {
		var out bytes.Buffer
		err := activityMain(context.Background(), append([]string{"config", "plan", "--file", f, "--detailed-exitcode", "--api", srv.URL, "--key", "k", "--project", "prj_1"}, extra...), &out)
		return err, out.String()
	}

	srv, bodies := fakeConfigAPI(t, false, 200)
	if err, out := run(srv); err != nil || !strings.Contains(out, "no changes") {
		t.Fatalf("equal config must exit 0: %v %q", err, out)
	}
	if !strings.Contains((*bodies)[0], "mode=plan") || !strings.Contains((*bodies)[0], "the-secret-value-123") {
		t.Errorf("the request must be a plan carrying the resolved secret: %v", *bodies)
	}

	srv, _ = fakeConfigAPI(t, true, 200)
	err, out := run(srv)
	var ec exitCode
	if !errors.As(err, &ec) || int(ec) != 2 {
		t.Fatalf("drift must exit 2, got %v", err)
	}
	if strings.Contains(out, "the-secret-value-123") || !strings.Contains(out, "~ activity_rule storm (secret)") {
		t.Errorf("the plan names the field and never a value: %q", out)
	}

	// without --detailed-exitcode drift still prints and exits 0 (the convention of wtctl plan);
	// -f is the same as --file; --exit-code is the alias of the flag
	var plain bytes.Buffer
	args := []string{"config", "plan", "-f", f, "--api", srv.URL, "--key", "k", "--project", "prj_1"}
	if err := activityMain(context.Background(), args, &plain); err != nil || !strings.Contains(plain.String(), "~ activity_rule storm") {
		t.Fatalf("drift without the flag must exit 0 and print: %v %q", err, plain.String())
	}
	if err := activityMain(context.Background(), append(args, "--exit-code"), &plain); !errors.As(err, &ec) || int(ec) != 2 {
		t.Fatalf("--exit-code must exit 2 on drift, got %v", err)
	}

	// --json is exactly the server's document
	err, out = run(srv, "--json")
	var got, want map[string]any
	if json.Unmarshal([]byte(out), &got) != nil || json.Unmarshal([]byte(`{"mode":"plan","applied":false,"changed":true,"changes":[{"kind":"activity_rule","name":"storm","op":"update","fields":["secret"]}]}`), &want) != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("--json must print the server's plan document: %q", out)
	}
	if !errors.As(err, &ec) || int(ec) != 2 {
		t.Fatalf("--json keeps the exit code, got %v", err)
	}

	srv, _ = fakeConfigAPI(t, false, 422)
	if err, _ := run(srv); err == nil || errors.As(err, &ec) {
		t.Fatalf("an API error must be a plain error (exit 1), got %v", err)
	}
}

func TestConfigPlanFailsOnSampleProblems(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"changed":false,"changes":[],"validation":[{"action":"a.b","result":{"ok":true,"warnings":[],"missing_template":true}}]}`)
	}))
	defer srv.Close()
	doc := map[string]any{"samples": map[string]any{"a.b": map[string]any{}}}
	var out bytes.Buffer
	err := runConfig(context.Background(), "plan", srv.URL, "k", doc, configFlags{}, &out)
	if err == nil || !strings.Contains(out.String(), "no display template") {
		t.Fatalf("a missing template must fail the plan: %v %q", err, out.String())
	}
	if err := runConfig(context.Background(), "plan", srv.URL, "k", doc, configFlags{lenient: true}, &out); err != nil {
		t.Fatalf("--lenient accepts it: %v", err)
	}
	// apply validates the samples first and writes nothing when they fail
	err = runConfig(context.Background(), "apply", srv.URL, "k", doc, configFlags{}, &out)
	if err == nil || !strings.Contains(err.Error(), "nothing was applied") {
		t.Fatalf("apply must stop on a failed sample: %v", err)
	}
}
