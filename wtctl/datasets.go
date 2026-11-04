package main

import (
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

const datasetsUsage = "usage: wtctl datasets import <file> --dataset <name> --api <url> --key <key> --project <id> [--format jsonl|csv|langfuse|phoenix] [--mapping '{\"input\":\"col\"}'] [--create]\n" +
	"       wtctl datasets pull --dataset <name> --api <url> --key <key> --project <id> [--format jsonl|csv] [--version N] [--split s] [--out file]"

type datasetOpts struct {
	api, key, project, dataset, format, mapping, split, out string
	version                                                 int
	create                                                  bool
}

func (o *datasetOpts) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.StringVar(&o.api, "api", "", "API base URL")
	fs.StringVar(&o.key, "key", os.Getenv("WT_API_KEY"), "API key; default $WT_API_KEY")
	fs.StringVar(&o.project, "project", "", "project id")
	fs.StringVar(&o.dataset, "dataset", "", "dataset name")
	fs.StringVar(&o.format, "format", "jsonl", "file format")
	fs.StringVar(&o.mapping, "mapping", "", "CSV column mapping as JSON")
	fs.StringVar(&o.split, "split", "", "split for items without one (push) or the split to read (pull)")
	fs.StringVar(&o.out, "out", "", "pull: output file (default stdout)")
	fs.IntVar(&o.version, "version", 0, "pull: dataset version (default current)")
	fs.BoolVar(&o.create, "create", false, "push: create the dataset if it does not exist")
	return fs
}

// datasetsMain is `wtctl datasets import|pull` (push is the old name of import).
func datasetsMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) < 1 || (args[0] != "import" && args[0] != "push" && args[0] != "pull") {
		return errors.New(datasetsUsage)
	}
	var o datasetOpts
	fs := o.flags("datasets " + args[0])
	rest := args[1:]
	file := ""
	if args[0] != "pull" {
		if len(rest) < 1 || strings.HasPrefix(rest[0], "-") {
			return errors.New(datasetsUsage)
		}
		file, rest = rest[0], rest[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if o.api == "" || o.key == "" || o.project == "" || o.dataset == "" {
		return errors.New("--api, --key, --project and --dataset are required")
	}
	if args[0] != "pull" {
		return datasetsPush(ctx, o, file, out)
	}
	return datasetsPull(ctx, o, out)
}

func (o *datasetOpts) base() string {
	return strings.TrimRight(o.api, "/") + "/v1/projects/" + url.PathEscape(o.project) + "/llm/datasets"
}

// datasetID finds the dataset by name; with create it makes a missing one.
func datasetID(ctx context.Context, o datasetOpts, create bool) (string, error) {
	cursor := ""
	for {
		var page struct {
			Data []struct {
				ID, Name string
			} `json:"data"`
			Next string `json:"next_cursor"`
		}
		u := o.base() + "?limit=200"
		if cursor != "" {
			u += "&cursor=" + url.QueryEscape(cursor)
		}
		if err := call(ctx, http.MethodGet, u, o.key, nil, &page); err != nil {
			return "", err
		}
		for _, d := range page.Data {
			if d.Name == o.dataset {
				return d.ID, nil
			}
		}
		if page.Next == "" {
			break
		}
		cursor = page.Next
	}
	if !create {
		return "", fmt.Errorf("dataset %q not found (use --create)", o.dataset)
	}
	var made struct {
		ID string `json:"id"`
	}
	if err := call(ctx, http.MethodPost, o.base(), o.key, map[string]any{"name": o.dataset}, &made); err != nil {
		return "", err
	}
	return made.ID, nil
}

func datasetsPush(ctx context.Context, o datasetOpts, file string, out io.Writer) error {
	fields := map[string]string{"dataset": o.dataset, "mapping": o.mapping, "split": o.split}
	if o.create {
		fields["create"] = "true"
	}
	// the server converts the export (jsonl, csv, langfuse, phoenix) and appends the items
	v, err := uploadImport(ctx, o.api, o.key, o.project, "dataset-"+o.format, true, fields, map[string]string{"file": file})
	fmt.Fprint(out, v.Result.Output)
	return err
}

func datasetsPull(ctx context.Context, o datasetOpts, out io.Writer) error {
	id, err := datasetID(ctx, o, false)
	if err != nil {
		return err
	}
	q := url.Values{"format": {o.format}}
	if o.version > 0 {
		q.Set("version", fmt.Sprint(o.version))
	}
	if o.split != "" {
		q.Set("split", o.split)
	}
	res, err := rawCall(ctx, http.MethodGet, o.base()+"/"+id+"/export?"+q.Encode(), o.key, nil)
	if err != nil {
		return err
	}
	if o.out != "" {
		return os.WriteFile(o.out, res, 0o600)
	}
	_, err = out.Write(res)
	return err
}

// rawCall sends a non-JSON body and returns the raw response (up to 100 MiB, an export).
func rawCall(ctx context.Context, method, u, key string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	if body != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	resp, err := guardedClient(0).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 100<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("%s %s: %s: %s", method, u, resp.Status, strings.TrimSpace(string(b)))
	}
	return b, nil
}
