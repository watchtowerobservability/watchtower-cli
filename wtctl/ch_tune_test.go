package main

import "testing"

func TestChTuneDiffOnlyDiffering(t *testing.T) {
	want := chTuneProfiles["logs"]
	engine := "MergeTree ORDER BY (project_id, ts) SETTINGS index_granularity = 8192, min_age_to_force_merge_seconds = 3600\n"
	got := chTuneDiff(engine, want)
	if len(got) != 1 || got[0][0] != "max_bytes_to_merge_at_max_space_in_pool" || got[0][1] != "" {
		t.Fatalf("diff = %v", got)
	}
	engine += ", max_bytes_to_merge_at_max_space_in_pool = 161061273600"
	if got := chTuneDiff(engine, want); len(got) != 0 {
		t.Fatalf("second run must be a no-op, got %v", got)
	}
}
