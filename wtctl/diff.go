package main

import (
	"context"
	"fmt"
	"io"

	"github.com/watchtowerobservability/watchtower-cli/internal/ascode"
)

// diffMain is `wtctl diff`: the plan, with exit status 1 when anything differs.
func diffMain(ctx context.Context, args []string, out io.Writer) error {
	var o asCodeOpts
	c, err := o.client(o.flags("diff"), args)
	if err != nil {
		return err
	}
	plan, err := o.plan(ctx, c)
	if err != nil {
		return err
	}
	fmt.Fprint(out, ascode.Summary(plan))
	if ascode.Count(plan) > 0 {
		return exitCode(1)
	}
	return nil
}
