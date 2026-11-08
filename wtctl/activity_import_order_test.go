package main

import "testing"

// Sub-second ties must order by instant, not by the RFC3339Nano string: lexically ".5Z" > ".500001Z"
// though 0.5 s < 0.500001 s, so a string sort would reverse these two events.
func TestImportSortsSubSecondByInstant(t *testing.T) {
	rows := []map[string]string{
		{"id": "later", "action": "x", "actor_id": "u", "account_id": "acme", "occurred_at": "2024-01-01T00:00:00.500001Z"},
		{"id": "earlier", "action": "x", "actor_id": "u", "account_id": "acme", "occurred_at": "2024-01-01T00:00:00.5Z"},
	}
	evs, skipped := buildImportEvents("workos-csv", rows, "")
	if len(evs) != 2 || len(skipped) != 0 {
		t.Fatalf("got %d events, %d skipped", len(evs), len(skipped))
	}
	if evs[0]["occurred_at"] != "2024-01-01T00:00:00.5Z" || evs[1]["occurred_at"] != "2024-01-01T00:00:00.500001Z" {
		t.Fatalf("out of order: %v then %v", evs[0]["occurred_at"], evs[1]["occurred_at"])
	}
}
