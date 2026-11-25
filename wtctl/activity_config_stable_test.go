package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigPlanOutputIsStable(t *testing.T) {
	answers := []string{
		`{"changed":true,"changes":[{"kind":"hook","name":"digest","op":"create"},{"kind":"activity_rule","name":"b","op":"update","fields":["threshold","match"]},{"kind":"schema","name":"z.z","op":"create"},{"kind":"activity_rule","name":"a","op":"delete"},{"kind":"schema","name":"a.a","op":"update"}],
		  "warnings":[{"path":"actions.z","message":"m"},{"path":"actions.a","message":"m"}],"validation":[{"action":"z.z","result":{"ok":true,"warnings":["w2","w1"]}},{"action":"a.a","result":{"ok":true}}]}`,
		`{"changed":true,"changes":[{"kind":"schema","name":"a.a","op":"update"},{"kind":"activity_rule","name":"a","op":"delete"},{"kind":"schema","name":"z.z","op":"create"},{"kind":"activity_rule","name":"b","op":"update","fields":["match","threshold"]},{"kind":"hook","name":"digest","op":"create"}],
		  "warnings":[{"path":"actions.a","message":"m"},{"path":"actions.z","message":"m"}],"validation":[{"action":"a.a","result":{"ok":true}},{"action":"z.z","result":{"ok":true,"warnings":["w1","w2"]}}]}`,
	}
	var outs []string
	for _, a := range answers {
		body := a
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) }))
		var out bytes.Buffer
		_ = runConfig(context.Background(), "plan", srv.URL, "k", map[string]any{"samples": map[string]any{"a.a": map[string]any{}}}, configFlags{lenient: true}, &out)
		srv.Close()
		outs = append(outs, out.String())
	}
	if outs[0] != outs[1] {
		t.Fatalf("the same plan must print the same bytes whatever order the server lists it in:\n%s\n--- vs ---\n%s", outs[0], outs[1])
	}
	want := "~ schema a.a\n+ schema z.z\n- activity_rule a\n~ activity_rule b (match, threshold)\n+ hook digest\n"
	if !strings.HasPrefix(outs[0], want) {
		t.Fatalf("changes are listed by section then name:\n%s", outs[0])
	}
}

// A secret of the document, from the environment or literal, is sent to the API and printed
// nowhere: not by plan, not by apply, not in an error that names a missing variable.
func TestConfigNeverPrintsSuppliedSecrets(t *testing.T) {
	t.Setenv("CFG_SECRET_NEW", "env-secret-new-0123456789")
	t.Setenv("CFG_SECRET_OLD", "env-secret-old-0123456789")
	doc := `{"activity_rules":{"storm":{"channel":{"kind":"webhook","url":"https://x.example/h","secrets":["${CFG_SECRET_NEW}","${CFG_SECRET_OLD}"]}}},
		"hooks":{"digest":{"url":"https://x.example/d","secret":"literal-secret-0123456789"}}}`
	f := filepath.Join(t.TempDir(), "activity.json")
	_ = os.WriteFile(f, []byte(doc), 0o600)
	var sent []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		sent = append(sent, string(b))
		_, _ = io.WriteString(w, `{"applied":true,"changed":true,"changes":[{"kind":"activity_rule","name":"storm","op":"update","fields":["secret"]},{"kind":"hook","name":"digest","op":"update","fields":["secret"]}]}`)
	}))
	defer srv.Close()
	args := func(verb string) []string {
		return []string{"config", verb, "-f", f, "--api", srv.URL, "--key", "k", "--project", "prj_1"}
	}
	for _, verb := range []string{"plan", "apply"} {
		var out bytes.Buffer
		_ = activityMain(context.Background(), args(verb), &out)
		for _, secret := range []string{"env-secret-new-0123456789", "env-secret-old-0123456789", "literal-secret-0123456789"} {
			if strings.Contains(out.String(), secret) {
				t.Errorf("%s printed a secret: %s", verb, out.String())
			}
		}
	}
	if len(sent) != 2 || !strings.Contains(sent[0], "env-secret-new-0123456789") || strings.Contains(sent[0], "${CFG_SECRET_NEW}") {
		t.Fatalf("the API gets the resolved values: %v", sent)
	}
	os.Unsetenv("CFG_SECRET_OLD")
	var out bytes.Buffer
	err := activityMain(context.Background(), args("plan"), &out)
	if err == nil || !strings.Contains(err.Error(), "CFG_SECRET_OLD") || strings.Contains(err.Error()+out.String(), "env-secret-new-0123456789") || len(sent) != 2 {
		t.Fatalf("an unset variable stops before any request and is named without a value: %v", err)
	}
}

func TestConfigPlanPrintsKeyDiffRetentionAndWarningCode(t *testing.T) {
	var r configResult
	if err := json.Unmarshal([]byte(`{"changed":true,"changes":[
	 {"kind":"retention","name":"project","op":"update"},
	 {"kind":"theme","name":"project","op":"update","changed_keys":["actions","showMetadata","showIp"],
	  "key_changes":[{"key":"showMetadata","previous":true,"next":null},{"key":"showIp","previous":null,"next":false}]}],
	 "warnings":[{"code":"metadata_hidden","path":"detailFields[0]","message":"hidden"}]}`), &r); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	printConfig(&out, r)
	want := "~ theme project\n    theme  showIp: absent \u2192 false\n    theme  showMetadata: true \u2192 absent\n    theme  actions: changed\n~ retention project\nwarning [metadata_hidden]: detailFields[0]: hidden\n"
	if out.String() != want {
		t.Fatalf("got:\n%s\nwant:\n%s", out.String(), want)
	}
}
