package main

import "testing"

func TestLockfiles(t *testing.T) {
	pl := parsePackageLock([]byte(`{"packages":{"":{"version":"1.0.0"},
		"node_modules/lodash":{"version":"4.17.20"},
		"node_modules/a/node_modules/@s/b":{"version":"2.0.1"}}}`))
	if pl["lodash"] != "4.17.20" || pl["@s/b"] != "2.0.1" || len(pl) != 2 {
		t.Fatalf("package-lock: %v", pl)
	}
	y := parseYarnLock([]byte("# yarn\n\nlodash@^4.17.0, lodash@^4.17.5:\n  version \"4.17.21\"\n\n\"@s/b@^2\":\n  version \"2.0.1\"\n"))
	if y["lodash"] != "4.17.21" || y["@s/b"] != "2.0.1" {
		t.Fatalf("yarn: %v", y)
	}
	c := parseTOMLPackages([]byte("[[package]]\nname = \"serde\"\nversion = \"1.0.1\"\n\n[[package]]\nname = \"tokio\"\nversion = \"1.2.3\"\n"))
	if c["serde"] != "1.0.1" || c["tokio"] != "1.2.3" {
		t.Fatalf("toml: %v", c)
	}
	g := parseGoSum([]byte("github.com/x/y v1.2.3 h1:abc\ngithub.com/x/y v1.2.3/go.mod h1:def\n"))
	if g["github.com/x/y"] != "1.2.3" || len(g) != 1 {
		t.Fatalf("go.sum: %v", g)
	}
	pf := parsePipfileLock([]byte(`{"default":{"Django_X":{"version":"==3.0.1"}}}`))
	if pf["django-x"] != "3.0.1" {
		t.Fatalf("pipfile: %v", pf)
	}
}
