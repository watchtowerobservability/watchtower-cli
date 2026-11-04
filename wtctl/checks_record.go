package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	ossignal "os/signal"
	"strings"

	"github.com/watchtowerobservability/watchtower-cli/internal/recorder"
)

// Recording and OpenAPI import are server-side import jobs (checks-record, checks-openapi): the
// CLI captures raw browser events locally (the browser must run on the user's machine) or reads the
// spec file, uploads it and prints the monitor the server built. Selectors, step collapsing and
// the spec reader never ship here.

const (
	recordUsage  = "usage: wtctl checks record <url> [--out check.json] [--name <name>] [--apply] (--api --key --project or $WT_API, $WT_API_KEY, $WT_PROJECT)"
	openapiUsage = "usage: wtctl checks import-openapi <spec.yaml|json> --base-url <url> [--auth-secret <NAME>] [--name <name>] [--out monitor.json] [--apply]"
)

// checksRecord opens a visible Chromium, records until Ctrl+C, uploads the raw events and writes
// the monitor the server derived. Password fields are never captured; the server writes
// {{secret.PASSWORD}} in their place.
func checksRecord(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("record", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	file := fs.String("out", "check.json", "output file")
	name := fs.String("name", "recorded check", "monitor name")
	c := addImportFlags(fs)
	if err := fs.Parse(reorderFlags(args)); err != nil || fs.NArg() != 1 {
		return errors.New(recordUsage)
	}
	if err := c.check(); err != nil {
		return err
	}
	u, err := url.Parse(fs.Arg(0))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return errors.New("the url must be http or https")
	}
	rctx, stop := ossignal.NotifyContext(ctx, os.Interrupt)
	defer stop()
	fmt.Fprintln(out, "recording; use the browser, then press Ctrl+C here to finish")
	events, err := recorder.Record(rctx, fs.Arg(0), os.Getenv("WT_CHROME"))
	if err != nil {
		return fmt.Errorf("cannot record: %v", err)
	}
	if len(events) == 0 {
		return errors.New("nothing was recorded")
	}
	raw, _ := json.Marshal(events)
	v, err := uploadImport(ctx, c.api, c.key, c.project, "checks-record", *c.apply, map[string]string{"events": string(raw), "name": *name}, nil)
	return finishChecks(out, v, err, *file)
}

// checksImportOpenAPI uploads the spec; the server maps each operation to a multistep step.
func checksImportOpenAPI(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("import-openapi", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	base := fs.String("base-url", "", "base URL of the API under test")
	secret := fs.String("auth-secret", "", "vault secret sent as a Bearer token")
	name := fs.String("name", "", "monitor name (default: the spec file)")
	file := fs.String("out", "", "also write the monitor JSON here")
	c := addImportFlags(fs)
	if err := fs.Parse(reorderFlags(args)); err != nil || fs.NArg() != 1 || *base == "" {
		return errors.New(openapiUsage)
	}
	if err := c.check(); err != nil {
		return err
	}
	n := *name
	if n == "" {
		n = fs.Arg(0)
	}
	v, err := uploadImport(ctx, c.api, c.key, c.project, "checks-openapi", *c.apply,
		map[string]string{"base_url": *base, "auth_secret": *secret, "name": n}, map[string]string{"spec": fs.Arg(0)})
	return finishChecks(out, v, err, *file)
}

func finishChecks(out io.Writer, v importJobView, err error, file string) error {
	fmt.Fprint(out, v.Result.Output)
	if err != nil {
		return err
	}
	if file != "" && len(v.Result.Monitor) > 0 {
		var b strings.Builder
		b.Write(v.Result.Monitor)
		b.WriteByte('\n')
		if err := os.WriteFile(file, []byte(b.String()), 0o644); err != nil {
			return err
		}
		fmt.Fprintf(out, "wrote the monitor to %s; replace {{secret.*}} placeholders with vault secrets before applying\n", file)
	}
	return nil
}

type importConn struct {
	api, key, project string
	apply             *bool
}

func addImportFlags(fs *flag.FlagSet) *importConn {
	c := &importConn{}
	fs.StringVar(&c.api, "api", os.Getenv("WT_API"), "")
	fs.StringVar(&c.key, "key", os.Getenv("WT_API_KEY"), "")
	fs.StringVar(&c.project, "project", os.Getenv("WT_PROJECT"), "")
	c.apply = fs.Bool("apply", false, "create the monitor (dry run otherwise)")
	return c
}

func (c *importConn) check() error {
	if c.api == "" || c.key == "" || c.project == "" {
		return errors.New("--api, --key and --project are required (or $WT_API, $WT_API_KEY, $WT_PROJECT)")
	}
	return nil
}

// reorderFlags moves flags before the positional arguments so `record <url> --out f` parses.
func reorderFlags(args []string) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		if len(args[i]) > 1 && args[i][0] == '-' {
			flags = append(flags, args[i])
			if !strings.Contains(args[i], "=") && args[i] != "--apply" && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		pos = append(pos, args[i])
	}
	return append(flags, pos...)
}
