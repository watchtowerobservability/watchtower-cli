package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const goJSON = `{"Action":"run","Package":"wt/a","Test":"TestOk"}
{"Action":"output","Package":"wt/a","Test":"TestOk","Output":"=== RUN   TestOk\n"}
{"Action":"pass","Package":"wt/a","Test":"TestOk","Elapsed":0.01}
{"Action":"output","Package":"wt/a","Test":"TestFlaky","Output":"a_test.go:9: boom\n"}
{"Action":"fail","Package":"wt/a","Test":"TestFlaky","Elapsed":0.2}
{"Action":"skip","Package":"wt/a","Test":"TestLater","Elapsed":0}
{"Action":"fail","Package":"wt/a","Elapsed":0.3}
# wt/b [build failed]
{"Action":"fail","Package":"wt/b","Elapsed":0}
{"Action":"skip","Package":"wt/c","Output":"?   \twt/c\t[no test files]\n"}
`

func TestGoTestJunitIDsAndPackageFailures(t *testing.T) {
	var echo bytes.Buffer
	doc, err := goTestJunit(strings.NewReader(goJSON), &echo)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(echo.String(), "a_test.go:9: boom") || !strings.Contains(echo.String(), "# wt/b [build failed]") {
		t.Errorf("echo = %q", echo.String())
	}
	if !strings.Contains(string(doc), "a_test.go:9: boom") {
		t.Errorf("failure output missing: %s", doc)
	}
	r, err := parseJunitIDs(bytes.NewReader(doc), "")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, x := range r {
		got = append(got, x.ID+map[bool]string{true: " F", false: ""}[x.Failed])
	}
	// wt/a failed because of TestFlaky, so only wt/b (no test ran) gets a package case
	want := "wt/a::TestOk|wt/a::TestFlaky F|wt/a::TestLater|wt/b::(package) F"
	if strings.Join(got, "|") != want {
		t.Errorf("ids = %v", got)
	}
	if _, err := goTestJunit(strings.NewReader("not json\n"), io.Discard); err == nil {
		t.Error("no events must fail")
	}
}

func TestCiGotestUploadsAndRespectsQuarantine(t *testing.T) {
	var uploaded string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/projects/prj_1/test-runs":
			f, _, err := r.FormFile("file")
			if err == nil {
				b, _ := io.ReadAll(f)
				uploaded = string(b)
			}
			w.WriteHeader(http.StatusCreated)
		case "/v1/projects/prj_1/tests/plan":
			_, _ = w.Write([]byte(`{"quarantined":[{"id":"wt/a::TestFlaky"}],"disabled":["wt/b::(package)"]}`))
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	args := []string{"--api", srv.URL, "--key", "k", "--project", "prj_1", "--run-id", "r1", "--respect-quarantine"}
	var out bytes.Buffer
	if err := ciGotestMain(context.Background(), args, strings.NewReader(goJSON), &out); err != nil {
		t.Fatalf("quarantined and disabled failures must pass: %v\n%s", err, out.String())
	}
	if !strings.Contains(uploaded, `<testsuite name="wt/a">`) || !strings.Contains(out.String(), "quarantined  wt/a::TestFlaky") {
		t.Errorf("uploaded = %q\nout = %q", uploaded, out.String())
	}
	// without the plan the same stream fails
	var ec exitCode
	err := ciGotestMain(context.Background(), nil, strings.NewReader(goJSON), io.Discard)
	if !errors.As(err, &ec) || ec != 1 {
		t.Errorf("err = %v", err)
	}
	if err := ciGotestMain(context.Background(), []string{"--run-id", "r1"}, strings.NewReader(goJSON), io.Discard); err == nil {
		t.Error("--run-id without --api/--key/--project must fail")
	}
}

func TestGoSkipPattern(t *testing.T) {
	got := goSkipPattern([]string{"wt/a::TestA", "wt/b::TestA", "wt/a::TestB/sub", "x", "wt/a::Test.C"})
	if got != `^(TestA|Test\.C)$` {
		t.Errorf("pattern = %q", got)
	}
	if goSkipPattern(nil) != "" {
		t.Error("empty list must give an empty pattern")
	}
}

func TestParseJunitIDsReadsXunitAndNunit(t *testing.T) {
	x := `<assemblies><assembly name="C:\b\T.dll"><collection name="c">
	  <test name="Ns.C.Ok" result="Pass"/><test name="Ns.C.Bad" result="Fail"><failure/></test></collection></assembly></assemblies>`
	n := `<test-run><test-suite type="Assembly" name="N.dll"><test-suite type="TestFixture" name="C">
	  <test-case name="E" fullname="Ns.C.E" result="Failed"/><test-case name="Ok" fullname="Ns.C.Ok" result="Passed"/>
	</test-suite></test-suite></test-run>`
	s := `<testsuite name="it"><testcase classname="a.B" name="f"><flakyFailure/></testcase></testsuite>`
	var got []string
	for _, doc := range []string{x, n, s} {
		r, err := parseJunitIDs(strings.NewReader(doc), "")
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range r {
			got = append(got, c.ID+map[bool]string{true: " F", false: ""}[c.Failed])
		}
	}
	want := "T.dll::Ns.C.Ok|T.dll::Ns.C.Bad F|N.dll::Ns.C.E F|N.dll::Ns.C.Ok|it::a.B.f"
	if strings.Join(got, "|") != want {
		t.Errorf("ids = %v", got)
	}
}
