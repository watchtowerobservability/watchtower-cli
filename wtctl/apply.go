package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/watchtowerobservability/watchtower-cli/internal/ascode"
)

const asCodeUsage = "usage: wtctl apply -f <dir|file> --project <id> [--dry-run] [--prune] [--watch] [--interval 5s] [--api <url>] [--key <key>]\n" +
	"       wtctl diff -f <dir|file> --project <id> [--prune]\n" +
	"       wtctl export --project <id> [--kinds AlertRule,Monitor] [--out <dir>]"

// secretOut receives secrets the API shows once; a variable so tests can capture it.
var secretOut io.Writer = os.Stderr

type asCodeOpts struct {
	api, key, project, file, kinds, outDir string
	dryRun, prune                          bool
}

func (o *asCodeOpts) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.StringVar(&o.api, "api", os.Getenv("WT_API"), "API base URL; default $WT_API")
	fs.StringVar(&o.key, "key", os.Getenv("WT_API_KEY"), "API key; default $WT_API_KEY")
	fs.StringVar(&o.project, "project", os.Getenv("WT_PROJECT"), "project id; default $WT_PROJECT")
	fs.StringVar(&o.file, "f", "", "manifest file or directory")
	fs.BoolVar(&o.prune, "prune", false, "also delete live resources of the manifests' kinds that no manifest names")
	return fs
}

func (o *asCodeOpts) client(fs *flag.FlagSet, args []string) (*ascode.Client, error) {
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return nil, fmt.Errorf("%w\n%s", err, asCodeUsage)
	}
	return ascode.New(o.api, o.key, o.project, guardedClient(0))
}

// plan loads the manifests and plans them against the live project.
func (o *asCodeOpts) plan(ctx context.Context, c *ascode.Client) ([]ascode.Change, error) {
	if o.file == "" {
		return nil, errors.New("-f <dir|file> is required")
	}
	docs, err := ascode.LoadDocs(o.file)
	if err != nil {
		return nil, err
	}
	return c.Plan(ctx, docs, o.prune)
}

// applyMain is `wtctl apply`: create or update every manifest, delete extras only with --prune.
func applyMain(ctx context.Context, args []string, out io.Writer) error {
	var o asCodeOpts
	fs := o.flags("apply")
	fs.BoolVar(&o.dryRun, "dry-run", false, "show what would change and write nothing")
	watch := fs.Bool("watch", false, "keep running and apply again whenever the files change")
	every := fs.Duration("interval", 5*time.Second, "how often --watch looks at the files")
	c, err := o.client(fs, args)
	if err != nil {
		return err
	}
	if *watch {
		// A bad edit is reported and the next good one applies: the provisioning loop of C01.
		return watchLoop(ctx, o.file, *every, out, func(ctx context.Context) error { return o.applyOnce(ctx, c, out) })
	}
	return o.applyOnce(ctx, c, out)
}

// applyOnce plans and applies the manifests one time.
func (o *asCodeOpts) applyOnce(ctx context.Context, c *ascode.Client, out io.Writer) error {
	plan, err := o.plan(ctx, c)
	if err != nil {
		return err
	}
	done, err := c.Apply(ctx, plan, o.dryRun, secretOut)
	for _, ch := range done {
		if ch.Changed() {
			fmt.Fprintln(out, ch)
		}
	}
	if err != nil {
		return err
	}
	verb := "applied"
	if o.dryRun {
		verb = "would apply"
	}
	fmt.Fprintf(out, "%s %d change(s)\n", verb, ascode.Count(done))
	return nil
}
