package main

import (
	"os"
	"reflect"
	"testing"
)

func TestProjectRefAcceptsOrgSlug(t *testing.T) {
	t.Setenv("WT_PROJECT", "linkhub/linkhub")
	got := normalizeProjectArgs([]string{"--project", "acme/web", "--api", "https://x", "-project=a/b", "--project=prj_01m6", "--", "--project", "x/y"})
	want := []string{"--project", "acme~web", "--api", "https://x", "-project=a~b", "--project=prj_01m6", "--", "--project", "x/y"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
	if v := os.Getenv("WT_PROJECT"); v != "linkhub~linkhub" {
		t.Fatalf("WT_PROJECT = %q", v)
	}
	for in, want := range map[string]string{"web": "web", "prj_01m6": "prj_01m6", "https://x/y": "https://x/y", "a/b/c": "a/b/c"} {
		if projectRef(in) != want {
			t.Fatalf("projectRef(%q) = %q", in, projectRef(in))
		}
	}
}
