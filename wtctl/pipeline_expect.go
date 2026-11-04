package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

// simDiff is one record of a pipelines/simulate result.
type simDiff struct {
	Index     int     `json:"index"`
	DroppedBy *string `json:"dropped_by"`
	Aborted   bool    `json:"aborted"`
	Changes   []struct {
		Field  string  `json:"field"`
		Before *string `json:"before"`
		After  *string `json:"after"`
	} `json:"changes"`
}

// pipelineExpect is the `--expect` file of `wtctl pipeline test`: unit-test assertions in the
// spirit of declarative pipeline tests, so CI fails when a config stops doing what it should.
type pipelineExpect struct {
	// Kept, when set, is the number of records that must survive.
	Kept *int `json:"kept"`
	// Records asserts per input index: dropped or not, and attributes changed to a value.
	Records []struct {
		Index   int               `json:"index"`
		Dropped *bool             `json:"dropped"`
		Changes map[string]string `json:"changes"`
	} `json:"records"`
}

func checkExpect(path string, diffs []simDiff, out io.Writer) error {
	raw, err := loadAny(path)
	if err != nil {
		return err
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	var e pipelineExpect
	if err := json.Unmarshal(b, &e); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	fails := expectFailures(e, diffs)
	for _, f := range fails {
		fmt.Fprintln(out, "FAIL", f)
	}
	if len(fails) > 0 {
		return fmt.Errorf("%d expectation(s) failed", len(fails))
	}
	fmt.Fprintln(out, "all expectations passed")
	return nil
}

func expectFailures(e pipelineExpect, diffs []simDiff) []string {
	var fails []string
	byIndex := map[int]simDiff{}
	kept := 0
	for _, d := range diffs {
		byIndex[d.Index] = d
		if d.DroppedBy == nil {
			kept++
		}
	}
	if e.Kept != nil && *e.Kept != kept {
		fails = append(fails, fmt.Sprintf("kept %d records, want %d", kept, *e.Kept))
	}
	for _, r := range e.Records {
		d, ok := byIndex[r.Index]
		if !ok {
			fails = append(fails, fmt.Sprintf("record %d: not in the result", r.Index))
			continue
		}
		if r.Dropped != nil && *r.Dropped != (d.DroppedBy != nil) {
			fails = append(fails, fmt.Sprintf("record %d: dropped = %t, want %t", r.Index, d.DroppedBy != nil, *r.Dropped))
		}
		got := map[string]string{}
		for _, c := range d.Changes {
			if c.After != nil {
				got[c.Field] = *c.After
			}
		}
		fields := make([]string, 0, len(r.Changes))
		for f := range r.Changes {
			fields = append(fields, f)
		}
		sort.Strings(fields)
		for _, f := range fields {
			if v, ok := got[f]; !ok || v != r.Changes[f] {
				fails = append(fails, fmt.Sprintf("record %d: %s = %s, want %q", r.Index, f, show(ptrIf(v, ok)), r.Changes[f]))
			}
		}
	}
	return fails
}

func ptrIf(v string, ok bool) *string {
	if !ok {
		return nil
	}
	return &v
}
