package main

import (
	"strings"
	"testing"
)

func TestMergeRetryMarksFlaky(t *testing.T) {
	run := runDoc{Tag: "ci", Status: "failed", Results: []runResult{
		{MonitorID: "a", Name: "A", Status: "passed"},
		{MonitorID: "b", Name: "B", Status: "failed", Error: "x"},
		{MonitorID: "c", Name: "C", Status: "failed", Error: "y"},
	}}
	mergeRetry(&run, runDoc{Results: []runResult{{MonitorID: "b", Name: "B", Status: "passed"}, {MonitorID: "c", Name: "C", Status: "failed", Error: "z"}}})
	if run.Status != "failed" || !run.Results[1].Flaky || run.Results[2].Flaky || run.Results[2].Error != "z" {
		t.Fatalf("%+v", run)
	}
	mergeRetry(&run, runDoc{Results: []runResult{{MonitorID: "c", Name: "C", Status: "passed"}}})
	if run.Status != "passed" || !run.Results[2].Flaky {
		t.Fatalf("%+v", run)
	}
	x, err := junit(run)
	if err != nil || strings.Count(string(x), "<flakyFailure") != 2 || strings.Contains(string(x), "<failure") {
		t.Fatalf("%v %s", err, x)
	}
}
