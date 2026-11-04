package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const rulesUsage = "usage: wtctl rules import <rules.yaml> --api <url> --key <key> --project <id>\n" +
	"       wtctl rules test <tests.yaml> --api <url> --key <key> --project <id>\n" +
	"       wtctl routing import-alertmanager <alertmanager.yaml> --api <url> --key <key> --project <id> [--apply]"

type rulesOpts struct {
	api, key, project string
	apply             bool
}

func (o *rulesOpts) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.StringVar(&o.api, "api", "", "API base URL")
	fs.StringVar(&o.key, "key", os.Getenv("WT_API_KEY"), "API key (alert manager); default $WT_API_KEY")
	fs.StringVar(&o.project, "project", "", "project id")
	return fs
}

// parseFlags reads <file> then the flags that follow it.
func (o *rulesOpts) parse(fs *flag.FlagSet, args []string) (string, error) {
	if len(args) < 1 || strings.HasPrefix(args[0], "-") {
		return "", errors.New(rulesUsage)
	}
	if err := fs.Parse(args[1:]); err != nil {
		return "", err
	}
	if o.api == "" || o.key == "" || o.project == "" {
		return "", errors.New("--api, --key and --project are required")
	}
	return args[0], nil
}

// rulesMain is `wtctl rules ...`: each group of a Prometheus rule file is PUT as JSON.
func rulesMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) >= 1 && args[0] == "test" {
		return rulesTest(ctx, args[1:], out)
	}
	if len(args) < 1 || args[0] != "import" {
		return errors.New(rulesUsage)
	}
	var o rulesOpts
	file, err := o.parse(o.flags("rules import"), args[1:])
	if err != nil {
		return err
	}
	src, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	groups, err := ruleGroups(src)
	if err != nil {
		return err
	}
	for _, g := range groups {
		name, _ := g["name"].(string)
		if name == "" {
			return errors.New("a group has no name")
		}
		var res any
		u := strings.TrimRight(o.api, "/") + "/v1/projects/" + url.PathEscape(o.project) + "/rule-groups/" + url.PathEscape(name)
		if err := call(ctx, http.MethodPut, u, o.key, g, &res); err != nil {
			return fmt.Errorf("group %s: %w", name, err)
		}
		enc := json.NewEncoder(out)
		if err := enc.Encode(res); err != nil {
			return err
		}
	}
	return nil
}

// ruleGroups splits a Prometheus rule file (`groups:`) into its groups.
func ruleGroups(src []byte) ([]map[string]any, error) {
	var doc struct {
		Groups []map[string]any `yaml:"groups"`
	}
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, err
	}
	if len(doc.Groups) == 0 {
		return nil, errors.New("no groups in the rule file")
	}
	return doc.Groups, nil
}

// routingMain is `wtctl routing import-alertmanager <file>`: a preview unless --apply.
func routingMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) < 1 || args[0] != "import-alertmanager" {
		return errors.New(rulesUsage)
	}
	var o rulesOpts
	fs := o.flags("routing import-alertmanager")
	var replace, allowDisabled bool
	fs.BoolVar(&replace, "replace", false, "overwrite receivers and time intervals that already have an imported name")
	fs.BoolVar(&allowDisabled, "allow-disabled-receivers", false, "apply although the routes point at receivers that start disabled")
	fs.BoolVar(&o.apply, "apply", false, "create the draft receivers and save the routing tree (default: preview)")
	file, err := o.parse(fs, args[1:])
	if err != nil {
		return err
	}
	src, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	u := strings.TrimRight(o.api, "/") + "/v1/projects/" + url.PathEscape(o.project) + "/routing:import-alertmanager"
	if o.apply {
		u += "?apply=true"
		if replace {
			u += "&replace=true"
		}
		if allowDisabled {
			u += "&allow_disabled_receivers=true"
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(src))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+o.key)
	req.Header.Set("Content-Type", "application/yaml")
	resp, err := guardedClient(0).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("POST %s: %s: %s", u, resp.Status, strings.TrimSpace(string(b)))
	}
	_, err = out.Write(append(bytes.TrimRight(b, "\n"), '\n'))
	return err
}
