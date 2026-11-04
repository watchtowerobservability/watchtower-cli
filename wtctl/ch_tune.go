package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
)

const chTuneUsage = "usage: wtctl ch tune --profile logs [--dry-run]   (needs WT_CH_URL; prints the setting diff)"

// chTuneProfiles mirrors wt_store_ch::settings::LOGS_PROFILE (stable-log merge policy for logs_v1).
var chTuneProfiles = map[string][][2]string{
	"logs": {
		{"min_age_to_force_merge_seconds", "3600"},
		{"max_bytes_to_merge_at_max_space_in_pool", "161061273600"},
	},
}

func chMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "tune" {
		return errors.New(chTuneUsage)
	}
	fs := flag.NewFlagSet("ch tune", flag.ContinueOnError)
	profile := fs.String("profile", "logs", "settings profile (logs)")
	dry := fs.Bool("dry-run", false, "print the diff without altering the table")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	want, ok := chTuneProfiles[*profile]
	if !ok {
		return fmt.Errorf("unknown profile %q (have: logs)", *profile)
	}
	engine, err := chExec(ctx, "SELECT engine_full FROM system.tables WHERE database = currentDatabase() AND name = 'logs_v1' FORMAT TSV")
	if err != nil {
		return err
	}
	changes := chTuneDiff(engine, want)
	if len(changes) == 0 {
		fmt.Fprintln(out, "logs_v1: settings already match profile", *profile)
		return nil
	}
	set := make([]string, 0, len(changes))
	for _, c := range changes {
		fmt.Fprintf(out, "%s: %q -> %s\n", c[0], c[1], c[2])
		set = append(set, c[0]+" = "+c[2])
	}
	if *dry {
		return nil
	}
	_, err = chExec(ctx, "ALTER TABLE logs_v1 MODIFY SETTING "+strings.Join(set, ", "))
	return err
}

// chTuneDiff returns (name, current, wanted) for each wanted setting the engine_full text lacks.
func chTuneDiff(engine string, want [][2]string) [][3]string {
	var out [][3]string
	for _, kv := range want {
		cur := ""
		if _, rest, ok := strings.Cut(engine, kv[0]+" = "); ok {
			cur, _, _ = strings.Cut(rest, ",")
			if f := strings.Fields(cur); len(f) > 0 {
				cur = strings.Trim(f[0], `\`)
			}
		}
		if cur != kv[1] {
			out = append(out, [3]string{kv[0], cur, kv[1]})
		}
	}
	return out
}
