package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanSourceFindsSinks(t *testing.T) {
	src := "const x = eval(req.query.code);\n" + // dynamic eval
		"const h = crypto.createHash('md5');\n" + // weak hash
		"const greeting = 'hello world';\n" // clean line
	res := scanSource("app.js", src)
	got := map[string]int{}
	for _, r := range res {
		got[r.RuleID] = r.Locations[0].Physical.Region.StartLine
	}
	if got["sast/eval-user-input"] != 1 {
		t.Fatalf("expected eval finding on line 1, got %v", got)
	}
	if got["sast/weak-hash"] != 2 {
		t.Fatalf("expected weak-hash finding on line 2, got %v", got)
	}
	if len(res) != 2 {
		t.Fatalf("clean line should not match: %+v", res)
	}
}

func TestScanTreeSkipsAndBuildsSarif(t *testing.T) {
	files := map[string]string{
		"src/db.js":                "query('SELECT * FROM users WHERE id=' + id)\n",
		"node_modules/pkg/evil.js": "eval(bad)\n",           // must be skipped
		"README.md":                "eval(this is prose)\n", // not a source ext
	}
	read := func(p string) ([]byte, error) { return []byte(files[filepath.ToSlash(p)]), nil }
	walk := func(root string, fn fs.WalkDirFunc) error {
		// Deterministic fake tree: dirs then files.
		entries := []struct {
			path string
			dir  bool
			name string
		}{
			{"src", true, "src"},
			{"node_modules", true, "node_modules"},
			{"src/db.js", false, "db.js"},
			{"README.md", false, "README.md"},
		}
		for _, e := range entries {
			if err := fn(e.path, fakeEntry{e.name, e.dir}, nil); err != nil {
				if err == filepath.SkipDir {
					// Drop anything under the skipped dir.
					continue
				}
				return err
			}
		}
		return nil
	}
	log, err := scanTree(".", read, walk)
	if err != nil {
		t.Fatal(err)
	}
	results := log.Runs[0].Results
	if len(results) != 1 || results[0].RuleID != "sast/sql-string-concat" {
		t.Fatalf("expected one SQL finding from src/db.js, got %+v", results)
	}
	if results[0].Locations[0].Physical.Artifact.URI != "src/db.js" {
		t.Fatalf("path should be relative to root: %+v", results[0])
	}
	// The driver declares the rule set with severities, so the server can rank.
	if len(log.Runs[0].Tool.Driver.Rules) != len(rules)+len(taintRules) {
		t.Fatalf("driver must declare every rule")
	}
}

type fakeEntry struct {
	name string
	dir  bool
}

func (f fakeEntry) Name() string               { return f.name }
func (f fakeEntry) IsDir() bool                { return f.dir }
func (f fakeEntry) Type() fs.FileMode          { return 0 }
func (f fakeEntry) Info() (fs.FileInfo, error) { return nil, nil }

func TestTaintTracesRequestInputThroughHelper(t *testing.T) {
	b, err := os.ReadFile("testdata/taint/handler.go")
	if err != nil {
		t.Fatal(err)
	}
	res := taintScan([]taintFile{{"handler.go", string(b)}})
	// One finding: the helper's SQL line (19). The constant call and the bound parameter add none.
	if len(res) != 1 || res[0].RuleID != "sast/taint-sql-injection" ||
		res[0].Locations[0].Physical.Region.StartLine != 19 {
		t.Fatalf("want exactly the helper sink at line 19, got %+v", res)
	}
	// With only the constant caller, nothing is reported.
	clean := strings.Replace(string(b), `runQuery(db, name) // user input into the helper`, `runQuery(db, "x")`, 1)
	if got := taintScan([]taintFile{{"handler.go", clean}}); len(got) != 0 {
		t.Fatalf("constant input must not be reported, got %+v", got)
	}
}

func TestTaintScanJSAndPython(t *testing.T) {
	for _, c := range []struct {
		file string
		scan func([]taintFile) []sarifResult
		sink int // line of the helper's SQL sink
		from string
	}{
		{"handler.js", taintScanJS, 15, `runQuery(db, name); // user input into the helper`},
		{"handler.py", taintScanPy, 12, `run_query(cur, name)  # user input into the helper`},
	} {
		b, err := os.ReadFile("testdata/taint/" + c.file)
		if err != nil {
			t.Fatal(err)
		}
		// One finding: the helper's SQL line. The constant call, the bound parameter and the
		// int()/parseInt() conversion add none.
		res := c.scan([]taintFile{{c.file, string(b)}})
		if len(res) != 1 || res[0].RuleID != "sast/taint-sql-injection" ||
			res[0].Locations[0].Physical.Region.StartLine != c.sink {
			t.Fatalf("%s: want exactly the helper sink at line %d, got %+v", c.file, c.sink, res)
		}
		clean := strings.Replace(string(b), c.from, strings.Replace(c.from, "name", `"x"`, 1), 1)
		if clean == string(b) {
			t.Fatalf("%s: fixture call not found", c.file)
		}
		if got := c.scan([]taintFile{{c.file, clean}}); len(got) != 0 {
			t.Fatalf("%s: constant input must not be reported, got %+v", c.file, got)
		}
	}
}

func TestMoreRulesCatchPythonFstringSQL(t *testing.T) {
	src := "cur.execute(f\"SELECT * FROM users WHERE id = {uid}\")\n" +
		"q = f\"DELETE FROM t WHERE a = '{a}'\"\n" +
		"cur.execute(\"SELECT * FROM users WHERE id = %s\", (uid,))\n" // parameterised: clean
	got := map[string][]int{}
	for _, r := range scanSource("app/db.py", src) {
		got[r.RuleID] = append(got[r.RuleID], r.Locations[0].Physical.Region.StartLine)
	}
	if len(got["sast/py-fstring-sql"]) != 1 || got["sast/py-fstring-sql"][0] != 1 {
		t.Fatalf("f-string execute: %v", got)
	}
	if len(got["sast/py-fstring-sql-var"]) != 1 || got["sast/py-fstring-sql-var"][0] != 2 {
		t.Fatalf("f-string assignment: %v", got)
	}
	for _, id := range []string{"sast/py-fstring-sql", "sast/py-fstring-sql-var"} {
		for _, l := range got[id] {
			if l == 3 {
				t.Fatalf("parameterised query flagged by %s", id)
			}
		}
	}
	if len(rules) < 25 {
		t.Fatalf("rule set shrank: %d", len(rules))
	}
}
