package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Named contexts (PLT-021), like kubeconfig: `wtctl login` stores an API URL, key and project
// under a name, `wtctl context use` picks the current one, and `--context <name>` (or
// $WT_CONTEXT) selects one for a single command. A context fills $WT_API, $WT_API_URL,
// $WT_API_KEY and $WT_PROJECT, which every command already defaults its flags from, so explicit
// flags and variables still win.

const contextUsage = `usage: wtctl login --context <name> --api <url> --project <prj> [--key <key> | $WT_API_KEY]
       wtctl context list|current|use <name>|delete <name>
       wtctl <command> --context <name> ...   (or $WT_CONTEXT)`

type wtContext struct {
	API     string `json:"api"`
	Key     string `json:"key"`
	Project string `json:"project"`
}

type wtConfig struct {
	Current  string               `json:"current"`
	Contexts map[string]wtContext `json:"contexts"`
}

// configPath is $WTCTL_CONFIG or <user config dir>/wtctl/config.json.
func configPath() (string, error) {
	if p := os.Getenv("WTCTL_CONFIG"); p != "" {
		return p, nil
	}
	d, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "wtctl", "config.json"), nil
}

func loadConfig() (wtConfig, string, error) {
	c := wtConfig{Contexts: map[string]wtContext{}}
	p, err := configPath()
	if err != nil {
		return c, "", err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return c, p, nil
	}
	if err != nil {
		return c, p, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, p, fmt.Errorf("%s: %w", p, err)
	}
	if c.Contexts == nil {
		c.Contexts = map[string]wtContext{}
	}
	return c, p, nil
}

// saveConfig writes the file owner-only: it holds API keys.
func saveConfig(c wtConfig, p string) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// applyContext strips `--context <name>` / `--context=<name>` from args and exports the chosen
// context (flag, then $WT_CONTEXT, then the current one) into unset variables.
func applyContext(args []string) ([]string, error) {
	name, rest := os.Getenv("WT_CONTEXT"), make([]string, 0, len(args))
	explicit := name != ""
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--context" || a == "-context":
			if i+1 >= len(args) {
				return nil, errors.New("--context needs a name")
			}
			name, explicit = args[i+1], true
			i++
		case strings.HasPrefix(a, "--context="):
			name, explicit = strings.TrimPrefix(a, "--context="), true
		default:
			rest = append(rest, a)
		}
	}
	if len(rest) > 0 && (rest[0] == "login" || rest[0] == "context") {
		if explicit && rest[0] == "login" {
			rest = append(rest, "--context", name) // login names the context it writes
		}
		return rest, nil
	}
	c, _, err := loadConfig()
	if err != nil {
		return nil, err
	}
	if !explicit {
		name = c.Current
	}
	if name == "" {
		return rest, nil
	}
	sel, ok := c.Contexts[name]
	if !ok {
		if explicit {
			return nil, fmt.Errorf("no context %q (see wtctl context list)", name)
		}
		return rest, nil
	}
	for _, kv := range [][2]string{{"WT_API", sel.API}, {"WT_API_URL", sel.API}, {"WT_API_KEY", sel.Key}, {"WT_PROJECT", sel.Project}} {
		if os.Getenv(kv[0]) == "" && kv[1] != "" {
			_ = os.Setenv(kv[0], kv[1])
		}
	}
	return rest, nil
}

func loginMain(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	name := fs.String("context", "default", "context name")
	api := fs.String("api", os.Getenv("WT_API"), "API base URL")
	key := fs.String("key", os.Getenv("WT_API_KEY"), "API key; prefer $WT_API_KEY over the flag (shell history)")
	project := fs.String("project", os.Getenv("WT_PROJECT"), "default project id")
	verify := fs.Bool("verify", true, "check the key against GET /v1/me first")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *api == "" || *key == "" {
		return errors.New(contextUsage)
	}
	if !strings.HasPrefix(*api, "https://") && !strings.HasPrefix(*api, "http://") {
		return errors.New("--api must be an http(s) URL")
	}
	if *verify {
		if err := call(ctx, "GET", strings.TrimRight(*api, "/")+"/v1/me", *key, nil, nil); err != nil {
			return fmt.Errorf("the key was refused: %w", err)
		}
	}
	c, p, err := loadConfig()
	if err != nil {
		return err
	}
	c.Contexts[*name] = wtContext{API: strings.TrimRight(*api, "/"), Key: *key, Project: *project}
	c.Current = *name
	if err := saveConfig(c, p); err != nil {
		return err
	}
	fmt.Fprintf(out, "context %q saved to %s and selected\n", *name, p)
	return nil
}

func contextMain(_ context.Context, args []string, out io.Writer) error {
	c, p, err := loadConfig()
	if err != nil {
		return err
	}
	if len(args) == 0 {
		return errors.New(contextUsage)
	}
	switch args[0] {
	case "list":
		names := make([]string, 0, len(c.Contexts))
		for n := range c.Contexts {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			mark := " "
			if n == c.Current {
				mark = "*"
			}
			// The key is never printed.
			fmt.Fprintf(out, "%s %s\t%s\t%s\n", mark, n, c.Contexts[n].API, c.Contexts[n].Project)
		}
		return nil
	case "current":
		if c.Current == "" {
			return errors.New("no current context (wtctl login)")
		}
		fmt.Fprintln(out, c.Current)
		return nil
	case "use", "delete":
		if len(args) != 2 {
			return errors.New(contextUsage)
		}
		if _, ok := c.Contexts[args[1]]; !ok {
			return fmt.Errorf("no context %q", args[1])
		}
		if args[0] == "use" {
			c.Current = args[1]
		} else {
			delete(c.Contexts, args[1])
			if c.Current == args[1] {
				c.Current = ""
			}
		}
		return saveConfig(c, p)
	}
	return errors.New(contextUsage)
}
