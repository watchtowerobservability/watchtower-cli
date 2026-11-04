package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseLcovPerTest(t *testing.T) {
	lcov := `TN:unit::a
SF:src/a.ts
DA:1,1
DA:2,0
end_of_record
SF:src/unused.ts
DA:1,0
end_of_record
TN:b
SF:src/b.ts
FNDA:3,f
end_of_record
TN:
SF:src/anon.ts
DA:1,5
end_of_record
`
	m, err := parseLcovPerTest(strings.NewReader(lcov))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{"unit::a": {"src/a.ts"}, "b": {"src/b.ts"}}
	if !reflect.DeepEqual(m, want) {
		t.Fatalf("got %v", m)
	}
	root := filepath.Join(t.TempDir(), "repo")
	cwd := filepath.Join(root, "web")
	m["b"] = append(m["b"], filepath.Join(root, "lib", "x.ts"), filepath.Join(t.TempDir(), "dep.js"))
	got := toCoverage(m, "vitest", root, cwd)
	if len(got) != 2 || got[0].Suite != "unit" || got[0].Test != "a" || got[0].Files[0] != "web/src/a.ts" {
		t.Fatalf("a: %+v", got)
	}
	if got[1].Suite != "vitest" || !reflect.DeepEqual(got[1].Files, []string{"web/src/b.ts", "lib/x.ts"}) {
		t.Fatalf("b: %+v", got[1])
	}
}

func TestTestsSelectPrintsSkipList(t *testing.T) {
	var seen map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/projects/prj_1/tia/select" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&seen)
		_, _ = w.Write([]byte(`{"run_all":false,"reasons":[],"run":["p::TestA"],"skip":["p::TestB","p::TestC/sub"],"unknown_files":[]}`))
	}))
	defer srv.Close()
	ids := filepath.Join(t.TempDir(), "ids.txt")
	if err := os.WriteFile(ids, []byte("p::TestA\n\np::TestNew\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	flags := []string{"--api", srv.URL, "--key", "k", "--project", "prj_1", "--changed-files", "a.go, b.go", "--tests-file", ids}
	var out, errOut bytes.Buffer
	if err := testsSelectMain(context.Background(), append(flags, "--format", "skip"), &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if out.String() != "p::TestB\np::TestC/sub\n" {
		t.Fatalf("skip: %q", out.String())
	}
	if !reflect.DeepEqual(seen["changed_files"], []any{"a.go", "b.go"}) || !reflect.DeepEqual(seen["tests"], []any{"p::TestA", "p::TestNew"}) {
		t.Fatalf("body %v", seen)
	}
	out.Reset()
	if err := testsSelectMain(context.Background(), append(flags, "--format", "go-skip"), &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if out.String() != "^(TestB)$\n" {
		t.Fatalf("go-skip: %q", out.String())
	}
	if err := testsSelectMain(context.Background(), flags[:6], &out, &errOut); err == nil {
		t.Fatal("accepted no diff source")
	}
}

func TestCoveredGoFiles(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo")
	mods := map[string]string{"example.com/m": filepath.Join(root, "go"), "example.com/m/sub": filepath.Join(root, "sub")}
	prof := `mode: set
example.com/m/a/a.go:1.1,2.2 1 1
example.com/m/a/b.go:1.1,2.2 1 0
example.com/m/sub/c.go:3.1,4.2 2 4
github.com/dep/x.go:1.1,2.2 1 1
`
	got := coveredGoFiles(strings.NewReader(prof), mods, root)
	if !reflect.DeepEqual(got, []string{"go/a/a.go", "sub/c.go"}) {
		t.Fatalf("got %v", got)
	}
	ev := `{"Action":"run","Test":"TestA"}
{"Action":"run","Test":"TestA/sub"}
{"Action":"run","Test":"TestB"}
{"Action":"pass","Test":"TestA"}
not json
`
	if n := goTopLevelTests(strings.NewReader(ev)); !reflect.DeepEqual(n, []string{"TestA", "TestB"}) {
		t.Fatalf("tests %v", n)
	}
}

func TestVersionCheck(t *testing.T) {
	if !versionLess("0.9.1", "v0.10.0") || versionLess("1.2.0", "1.2") || versionLess("v1.0.0", "1.0.0-rc1") {
		t.Fatal("versionLess")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v0.2.0"}`))
	}))
	defer srv.Close()
	got, err := latestRelease(context.Background(), srv.URL)
	if err != nil || got != "v0.2.0" {
		t.Fatalf("latest %q %v", got, err)
	}
	if v := versionVerdict("0.1.0", got); !strings.Contains(v, "self-update") {
		t.Fatal(v)
	}
	if v := versionVerdict("0.2.0", got); !strings.HasPrefix(v, "up to date") {
		t.Fatal(v)
	}
	if updateAsset() == "" || !strings.HasPrefix(updateAsset(), "wtctl_") {
		t.Fatal(updateAsset())
	}
}
