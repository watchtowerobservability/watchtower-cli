package main

import "testing"

func TestStatusFor(t *testing.T) {
	pass := statusForState(&ciGateResult{Passed: true})
	if pass != "success" {
		t.Fatalf("passed gate = %q, want success", pass)
	}
	skip := statusForState(&ciGateResult{Skipped: true})
	if skip != "success" {
		t.Fatalf("skipped gate = %q, want success", skip)
	}
	state, desc := statusFor(&ciGateResult{Breaches: []gateBreach{{Message: "3 failed tests (max 0)"}}})
	if state != "failure" {
		t.Fatalf("breached gate = %q, want failure", state)
	}
	if desc != "3 failed tests (max 0)" {
		t.Fatalf("desc = %q, want the first breach message", desc)
	}
}

func statusForState(r *ciGateResult) string {
	s, _ := statusFor(r)
	return s
}

func TestShort(t *testing.T) {
	if short("0123456789") != "01234567" {
		t.Fatalf("short did not truncate to 8")
	}
	if short("abc") != "abc" {
		t.Fatalf("short changed a short sha")
	}
}
