package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// metricsMain handles `wtctl metrics import`: upload OpenMetrics text, for example from
// `promtool tsdb dump-openmetrics`, into a project.
func metricsMain(ctx context.Context, args []string, out io.Writer) error {
	const usage = "usage: wtctl metrics import --project <id> --file <path|-> [--api <url>] [--key <key>]"
	if len(args) == 0 || args[0] != "import" {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet("metrics import", flag.ContinueOnError)
	api := fs.String("api", apiEnv(), "API base URL; default $WT_API_URL")
	key := fs.String("key", os.Getenv("WT_API_KEY"), "API key; default $WT_API_KEY")
	project := fs.String("project", "", "project id")
	file := fs.String("file", "", "OpenMetrics file, or - for stdin")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *api == "" || *key == "" || *project == "" || *file == "" {
		return errors.New(usage)
	}
	var body []byte
	var err error
	if *file == "-" {
		body, err = io.ReadAll(os.Stdin)
	} else {
		body, err = os.ReadFile(*file)
	}
	if err != nil {
		return err
	}
	target := strings.TrimRight(*api, "/") + "/v1/projects/" + url.PathEscape(*project) + "/metrics/import"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+*key)
	req.Header.Set("Content-Type", "application/openmetrics-text")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	text, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("import failed: %s: %s", resp.Status, text)
	}
	fmt.Fprintf(out, "%s\n", bytes.TrimSpace(text))
	return nil
}
