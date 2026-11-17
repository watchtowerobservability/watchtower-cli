package main

import (
	"context"
	"fmt"
	"io"

	"github.com/watchtowerobservability/watchtower-cli/internal/ascode"
)

// planMain is `wtctl plan`: the diff against the live project; exit 0 unless --detailed-exitcode
// is set and changes are planned (then 2, like terraform plan).
func planMain(ctx context.Context, args []string, out io.Writer) error {
	var o asCodeOpts
	fs := o.flags("plan")
	detailed := fs.Bool("detailed-exitcode", false, "exit 2 when the plan has changes")
	exitAlias := fs.Bool("exit-code", false, "alias of --detailed-exitcode")
	c, err := o.client(fs, args)
	if err != nil {
		return err
	}
	plan, err := o.plan(ctx, c)
	if err != nil {
		return err
	}
	fmt.Fprint(out, ascode.Summary(plan))
	if (*detailed || *exitAlias) && ascode.Count(plan) > 0 {
		return exitCode(2)
	}
	return nil
}
