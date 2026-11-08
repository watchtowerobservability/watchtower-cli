package main

import (
	"reflect"
	"sort"
	"testing"
)

func TestImportToPackageMapping(t *testing.T) {
	mods := map[string]string{"github.com/a/b": "1.0.0", "github.com/a/b/v2": "2.0.0"}
	for imp, want := range map[string]string{
		"github.com/a/b/sub": "github.com/a/b", "github.com/a/b/v2/x": "github.com/a/b/v2", "fmt": "",
	} {
		if got := goImportModule(imp, mods); got != want {
			t.Errorf("go %s = %q want %q", imp, got, want)
		}
	}
	for spec, want := range map[string]string{
		"lodash/fp": "lodash", "@s/n/sub": "@s/n", "./x": "", "node:fs": "", "express": "express",
	} {
		if got := jsPackage(spec); got != want {
			t.Errorf("js %s = %q want %q", spec, got, want)
		}
	}
	for mod, want := range map[string]string{"yaml": "pyyaml", "Foo_Bar.baz": "foo-bar", "requests.auth": "requests"} {
		if got := pyDist(mod); got != want {
			t.Errorf("py %s = %q want %q", mod, got, want)
		}
	}
}

func sorted(s []string) []string { sort.Strings(s); return s }

func TestSymbolExtraction(t *testing.T) {
	got := goSymbols("package x\nimport (\n\tyaml \"gopkg.in/yaml.v3\"\n\t\"fmt\"\n)\nfunc f(){ yaml.Unmarshal(nil,nil); fmt.Println() }",
		map[string]string{"gopkg.in/yaml.v3": "3.0.1"})
	if !reflect.DeepEqual(got["gopkg.in/yaml.v3"], []string{"Unmarshal"}) || len(got) != 1 {
		t.Errorf("go: %v", got)
	}
	js := jsSymbols("import _, {merge as m, pick} from 'lodash/fp'\nconst {template} = require('lodash')\n_.chain(1); m(1); template('x')\nimport './rel'")
	if !reflect.DeepEqual(sorted(js["lodash"]), []string{"chain", "merge", "template"}) {
		t.Errorf("js: %v", js)
	}
	py := pySymbols("import yaml\nfrom requests import get, post\nyaml.safe_load('')\n")
	if !reflect.DeepEqual(py["pyyaml"], []string{"safe_load"}) || !reflect.DeepEqual(py["requests"], []string{"get", "post"}) {
		t.Errorf("py: %v", py)
	}
}

func TestManifests(t *testing.T) {
	g := parseGoMod("module m\n\ngo 1.22\n\nrequire (\n\tgithub.com/a/b v1.2.3 // indirect\n)\nrequire x.io/y v0.1.0\n")
	if g["github.com/a/b"] != "1.2.3" || g["x.io/y"] != "0.1.0" || len(g) != 2 {
		t.Errorf("gomod: %v", g)
	}
	if p := parsePackageJSON([]byte(`{"dependencies":{"a":"^1.2.3","b":"file:../b"}}`)); p["a"] != "1.2.3" || len(p) != 1 {
		t.Errorf("pkgjson: %v", p)
	}
	if r := parseRequirements("Foo_Bar[x]==2.0 ; python_version>'3'\n# c\nbaz>=1\n"); r["foo-bar"] != "2.0" || len(r) != 1 {
		t.Errorf("req: %v", r)
	}
}
