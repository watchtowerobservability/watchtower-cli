package main

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
)

func zipOf(t *testing.T, files map[string]int) *bytes.Reader {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, n := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(strings.Repeat("a", n))); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(buf.Bytes())
}

func TestSizeAnalyzeApkGroupsAbisAndDex(t *testing.T) {
	r := zipOf(t, map[string]int{
		"classes.dex": 300, "classes2.dex": 200, "lib/arm64-v8a/libapp.so": 1000, "lib/x86_64/libapp.so": 900,
		"res/drawable/a.png": 50, "resources.arsc": 70,
	})
	rep, err := analyzeSize(r, r.Size(), "android")
	if err != nil {
		t.Fatal(err)
	}
	if rep.TotalBytes != 2520 || rep.DownloadBytes <= 0 || rep.DownloadBytes >= rep.TotalBytes {
		t.Fatalf("sizes %+v", rep)
	}
	want := []sizeComponent{{"lib/arm64-v8a", 1000}, {"lib/x86_64", 900}, {"dex", 500}, {"resources.arsc", 70}, {"res", 50}}
	if len(rep.Components) != len(want) {
		t.Fatalf("components %+v", rep.Components)
	}
	for i, c := range want {
		if rep.Components[i] != c {
			t.Fatalf("component %d = %+v, want %+v", i, rep.Components[i], c)
		}
	}
}

func TestSizeComponentOfIpaAndAab(t *testing.T) {
	cases := map[[2]string]string{
		{"ios", "Payload/Shop.app/Frameworks/Pay.framework/Pay"}: "Frameworks/Pay.framework",
		{"ios", "Payload/Shop.app/Shop"}:                         "Shop",
		{"ios", "Payload/Shop.app/Assets.car"}:                   "Assets.car",
		{"android", "base/lib/arm64-v8a/libx.so"}:                "base/lib/arm64-v8a",
		{"android", "base/dex/classes.dex"}:                      "base/dex",
	}
	for in, want := range cases {
		if got := componentOf(in[0], in[1]); got != want {
			t.Errorf("componentOf(%q) = %q, want %q", in[1], got, want)
		}
	}
	if _, err := platformOf("app.zip"); err == nil {
		t.Fatal("a .zip is not a mobile package")
	}
	if _, err := analyzeSize(bytes.NewReader([]byte("nope")), 4, "ios"); err == nil {
		t.Fatal("not a zip")
	}
}
