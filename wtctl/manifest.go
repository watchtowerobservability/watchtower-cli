package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/watchtowerobservability/watchtower-cli/internal/ascode"
)

const manifestUsage = "usage: wtctl manifest plan|apply|drift --file watchtower.yaml --project <id> [--repo owner/name] [--fail-on-drift] [--api <url>] [--key <key>]"

// manifestMain is `wtctl manifest plan|apply|drift`. apply never deletes: objects the file no
// longer names are listed as orphans. `plan --fail-on-drift` and `drift` exit 2 when anything differs.
func manifestMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || (args[0] != "plan" && args[0] != "apply" && args[0] != "drift") {
		return errors.New(manifestUsage)
	}
	sub := args[0]
	var api, key, project, file, repo string
	var failOnDrift bool
	fs := flag.NewFlagSet("manifest "+sub, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&api, "api", apiEnv(), "API base URL; default $WT_API_URL")
	fs.StringVar(&key, "key", os.Getenv("WT_API_KEY"), "API key; default $WT_API_KEY")
	fs.StringVar(&project, "project", os.Getenv("WT_PROJECT"), "project id; default $WT_PROJECT")
	fs.StringVar(&file, "file", "watchtower.yaml", "manifest file")
	fs.StringVar(&repo, "repo", os.Getenv("GITHUB_REPOSITORY"), "repository, for the managed-by label")
	fs.BoolVar(&failOnDrift, "fail-on-drift", false, "plan: exit 2 when the file and the project differ")
	if err := fs.Parse(args[1:]); err != nil {
		return fmt.Errorf("%w\n%s", err, manifestUsage)
	}
	src, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	m, err := ascode.ParseManifest(src, repo, file)
	if err != nil {
		return err
	}
	c, err := ascode.New(api, key, project, guardedClient(0))
	if err != nil {
		return err
	}
	c.ManagedBy = ascode.ManagedBy(repo, file)
	plan, err := c.PlanManifest(ctx, m)
	if err != nil {
		return err
	}
	drift := ascode.Drifts(plan)
	if sub == "apply" {
		done, err := c.ApplyManifest(ctx, m, plan, secretOut)
		for _, ch := range done {
			if ch.Changed() {
				fmt.Fprintln(out, ch)
			}
		}
		for _, d := range drift {
			if d.Op == ascode.DriftOrphan {
				fmt.Fprintf(out, "orphan %s/%s (not deleted)\n", d.Kind, d.Key)
			}
		}
		return err
	}
	for _, d := range drift {
		fmt.Fprintf(out, "%s %s/%s\n", d.Op, d.Kind, d.Key)
		for _, f := range d.Fields {
			fmt.Fprintf(out, "    %s\n", f)
		}
	}
	fmt.Fprintf(out, "%d drift item(s)\n", len(drift))
	if len(drift) > 0 && (sub == "drift" || failOnDrift) {
		return exitCode(2)
	}
	return nil
}
