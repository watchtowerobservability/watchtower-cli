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
	"strings"
	"testing"
)

const quarantineXML = `<testsuites><testsuite name="unit">
  <testcase classname="pkg.A" name="flaky"><failure message="boom"/></testcase>
  <testcase classname="pkg.A" name="off"><error/></testcase>
  <testcase classname="pkg.A" name="steady"/>
</testsuite></testsuites>`

func planServer(t *testing.T, seen *map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/projects/prj_1/tests/plan" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if seen != nil {
			_ = json.NewDecoder(r.Body).Decode(seen)
		}
		_, _ = w.Write([]byte(`{"quarantined":[{"id":"unit::pkg.A.flaky","ticket_url":"https://jira/T-1"}],
			"disabled":["unit::pkg.A.off"],"skippable":["unit::pkg.B.x","unit::pkg.A.off"],"new_tests":[],"efd_retries":5}`))
	}))
}

func writeXML(t *testing.T, xml string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "r.xml")
	if err := os.WriteFile(p, []byte(xml), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseJunitIDsMatchesTheAPI(t *testing.T) {
	r, err := parseJunitIDs(strings.NewReader(quarantineXML), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(r) != 3 || r[0].ID != "unit::pkg.A.flaky" || !r[0].Failed || !r[1].Failed || r[2].Failed {
		t.Fatalf("results = %+v", r)
	}
	r, _ = parseJunitIDs(strings.NewReader(`<testcase name="x"/>`), "")
	if r[0].ID != "default::x" {
		t.Errorf("no suite = %q", r[0].ID)
	}
	if _, err := parseJunitIDs(strings.NewReader(`<testsuite/>`), ""); err == nil {
		t.Error("no testcase must fail")
	}
}

func TestCiJunitRespectQuarantineExitsZeroOnlyForQuarantined(t *testing.T) {
	srv := planServer(t, nil)
	defer srv.Close()
	p := writeXML(t, quarantineXML)
	var out bytes.Buffer
	args := []string{"junit", p, "--respect-quarantine", "--api", srv.URL, "--key", "k", "--project", "prj_1"}
	if err := ciMain(context.Background(), args, &out); err != nil {
		t.Fatalf("only quarantined/disabled failures must pass: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "https://jira/T-1") || !strings.Contains(out.String(), "disabled     unit::pkg.A.off") {
		t.Errorf("out = %q", out.String())
	}
	// without the flag the same results fail
	out.Reset()
	var ec exitCode
	if err := ciMain(context.Background(), []string{"junit", p}, &out); !errors.As(err, &ec) || ec != 1 {
		t.Errorf("err = %v", err)
	}
	// a failure that is not quarantined fails even with the flag
	p2 := writeXML(t, `<testsuite name="unit"><testcase classname="pkg.A" name="steady"><failure/></testcase></testsuite>`)
	out.Reset()
	args[1] = p2
	if err := ciMain(context.Background(), args, &out); !errors.As(err, &ec) || ec != 1 {
		t.Errorf("err = %v, out = %q", err, out.String())
	}
}

func TestCiPlanSkipListSendsChangedFiles(t *testing.T) {
	var seen map[string]any
	srv := planServer(t, &seen)
	defer srv.Close()
	var out bytes.Buffer
	args := []string{"plan", "--api", srv.URL, "--key", "k", "--project", "prj_1",
		"--changed-files", "src/a.py, src/b.py", "--skip-list"}
	if err := ciMain(context.Background(), args, &out); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "unit::pkg.A.off\nunit::pkg.B.x\n" {
		t.Errorf("skip list = %q", got)
	}
	files, _ := seen["changed_files"].([]any)
	if len(files) != 2 || files[1] != "src/b.py" {
		t.Errorf("sent = %v", seen)
	}
	if err := ciMain(context.Background(), []string{"plan", "--api", srv.URL}, &out); err == nil {
		t.Error("missing key/project must fail")
	}
}
