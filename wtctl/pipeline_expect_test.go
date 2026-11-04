package main

import (
	"strings"
	"testing"
)

func TestPipelineExpectFailures(t *testing.T) {
	drop, core := "filter", "core"
	diffs := []simDiff{{Index: 0, DroppedBy: &drop}, {Index: 1}}
	diffs[1].Changes = append(diffs[1].Changes, struct {
		Field  string  `json:"field"`
		Before *string `json:"before"`
		After  *string `json:"after"`
	}{Field: "attrs.team", After: &core})
	one, yes := 1, true
	var e pipelineExpect
	e.Kept = &one
	e.Records = append(e.Records, struct {
		Index   int               `json:"index"`
		Dropped *bool             `json:"dropped"`
		Changes map[string]string `json:"changes"`
	}{Index: 0, Dropped: &yes}, struct {
		Index   int               `json:"index"`
		Dropped *bool             `json:"dropped"`
		Changes map[string]string `json:"changes"`
	}{Index: 1, Changes: map[string]string{"attrs.team": "core"}})
	if f := expectFailures(e, diffs); len(f) != 0 {
		t.Fatalf("want no failures, got %v", f)
	}
	e.Records[1].Changes["attrs.team"] = "edge"
	f := expectFailures(e, diffs)
	if len(f) != 1 || !strings.Contains(f[0], `want "edge"`) {
		t.Fatalf("failures = %v", f)
	}
}
