package main

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

const pwDir = "../uptime/testdata/pw/"

func TestPlaywrightImportSubset(t *testing.T) {
	file := pwDir + "login.spec.ts"
	src, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	mons, err := importPlaywright(file, string(src))
	if err != nil || len(mons) != 1 {
		t.Fatalf("mons = %v, err = %v", mons, err)
	}
	mon := mons[0]
	if mon.Kind != "browser" || mon.Name != "sign in and reach the dashboard" {
		t.Errorf("monitor = %s %q", mon.Kind, mon.Name)
	}
	steps := mon.Config["steps"].([]map[string]any)
	want := []map[string]any{
		{"action": "goto", "url": "https://app.example.com/login"},
		{"action": "fill", "selector": `role=textbox[name="Email"]`, "value": "user@example.com"},
		{"action": "fill", "selector": "#password", "value": "{{secret.PW}}"},
		{"action": "click", "selector": "text=Remember me"},
		{"action": "select", "selector": "select#region", "value": "eu"},
		{"action": "click", "selector": `role=button[name="Sign in"]`},
		{"action": "press", "selector": "#password", "key": "Enter"},
		{"action": "assert_url", "value": "https://app.example.com/dashboard", "match": "equals"},
		{"action": "assert_url", "value": `dashboard\/?$`, "match": "regex"},
		{"action": "assert_text", "selector": "h1", "text": "Welcome"},
		{"action": "assert_visible", "selector": `role=button[name="Log out"]`},
	}
	if len(steps) != len(want) {
		t.Fatalf("got %d steps, want %d: %v", len(steps), len(want), steps)
	}
	for i := range want {
		if !reflect.DeepEqual(steps[i], want[i]) {
			t.Errorf("step %d = %v, want %v", i+1, steps[i], want[i])
		}
	}
}

func TestPlaywrightImportRejectsUnsupportedWithLine(t *testing.T) {
	file := pwDir + "unsupported.spec.ts"
	src, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	_, err = importPlaywright(file, string(src))
	if err == nil || !strings.HasSuffix(err.Error(), "unsupported.spec.ts:6: unsupported waitForTimeout") {
		t.Fatalf("err = %v", err)
	}
}

func TestPlaywrightImportOneMonitorPerTest(t *testing.T) {
	file := pwDir + "two.spec.ts"
	src, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	mons, err := importPlaywright(file, string(src))
	if err != nil || len(mons) != 2 {
		t.Fatalf("mons = %v, err = %v", mons, err)
	}
	if mons[0].Name != "home loads" || mons[1].Name != "docs load" {
		t.Errorf("names = %q, %q", mons[0].Name, mons[1].Name)
	}
	for _, m := range mons {
		if n := len(m.Config["steps"].([]map[string]any)); n != 2 {
			t.Errorf("%s has %d steps", m.Name, n)
		}
	}
}

func TestPlaywrightImportRejectsSilentlyDroppedConstructs(t *testing.T) {
	file := pwDir + "hooks.spec.ts"
	src, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	_, err = importPlaywright(file, string(src))
	if err == nil {
		t.Fatal("accepted")
	}
	for _, want := range []string{
		"hooks.spec.ts:3: unsupported export const",
		"hooks.spec.ts:5: unsupported test.use",
		"hooks.spec.ts:9: unsupported test.beforeEach",
		"hooks.spec.ts:14: unsupported test.skip",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in:\n%v", want, err)
		}
	}
}
