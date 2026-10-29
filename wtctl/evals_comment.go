package main

import (
	"fmt"
	"strings"
)

// The PR comment of `evals run --comment-out`, rendered client-side so the CLI needs no server packages.

// evalCommentMarker identifies the evals comment (one per PR, edited in place by the action).
const evalCommentMarker = "<!-- watchtower-evals -->"

// evalRow is one evaluator of a CI eval run. Delta and CI95 are set against a baseline: the
// difference of means with its 95% interval from a paired bootstrap over dataset items.
type evalRow struct {
	Evaluator string
	Mean      float64
	N         int
	Delta     *float64
	CI95      [2]float64
	Regressed bool
	// Verdict is a failed threshold ("below 0.800"), empty when none failed.
	Verdict string
}

// evalCommentBody is the pull request comment of `wtctl evals run --comment-out`.
func evalCommentBody(rows []evalRow, repetitions int, name string) string {
	var b strings.Builder
	b.WriteString(evalCommentMarker + "\n### Watchtower evals\n\n")
	fmt.Fprintf(&b, "Run `%s`, %d repetition(s) per item. The change column is the difference from the baseline with its 95%% confidence interval (paired bootstrap over items); an interval that excludes zero is a real change.\n\n", cell(name), max(repetitions, 1))
	b.WriteString("| Evaluator | Mean | Items | Change vs baseline (95% CI) | Result |\n|---|---:|---:|---|---|\n")
	for i, r := range rows {
		if i >= 25 {
			fmt.Fprintf(&b, "\nand %d more evaluators.\n", len(rows)-i)
			break
		}
		change, result := "n/a", "ok"
		if r.Delta != nil {
			change = fmt.Sprintf("%+.3f [%+.3f, %+.3f]", *r.Delta, r.CI95[0], r.CI95[1])
		}
		switch {
		case r.Regressed:
			result = "**regressed**"
		case r.Verdict != "":
			result = "**" + cell(r.Verdict) + "**"
		}
		fmt.Fprintf(&b, "| %s | %.3f | %d | %s | %s |\n", cell(r.Evaluator), r.Mean, r.N, change, result)
	}
	return b.String()
}

func cell(s string) string {
	s = strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t':
			return ' '
		case '[', ']', '<', '>', '`', '|':
			return -1
		}
		return r
	}, s)
	s = strings.ReplaceAll(s, "@", "@​")
	if r := []rune(s); len(r) > 80 {
		s = string(r[:80]) + "..."
	}
	return s
}
