package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

const promptsUsage = "usage: wtctl prompts pull|push --dir prompts/ --api <url> --key <key> --project <id>"

// promptFile is one prompt as a YAML file under --dir/<folder>/<name>.yaml. Labels name the
// labels that point at this content (the latest version) after a push.
type promptFile struct {
	Name          string   `yaml:"name"`
	Folder        string   `yaml:"folder,omitempty"`
	Type          string   `yaml:"type"`
	Template      any      `yaml:"template"`
	Config        any      `yaml:"config,omitempty"`
	CommitMessage string   `yaml:"commit_message,omitempty"`
	Labels        []string `yaml:"labels,omitempty"`
}

type promptDetail struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Folder string `json:"folder"`
	Type   string `json:"type"`
	Labels []struct {
		Label   string `json:"label"`
		Version int    `json:"version"`
	} `json:"labels"`
	Latest *struct {
		Version       int    `json:"version"`
		Template      any    `json:"template"`
		Config        any    `json:"config"`
		CommitMessage string `json:"commit_message"`
	} `json:"latest"`
}

// promptsMain is `wtctl prompts pull|push`: the registry and a repo directory stay in sync.
func promptsMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) < 1 || (args[0] != "pull" && args[0] != "push") {
		return errors.New(promptsUsage)
	}
	var api, key, project, dir string
	fs := flag.NewFlagSet("prompts "+args[0], flag.ContinueOnError)
	fs.StringVar(&api, "api", "", "API base URL")
	fs.StringVar(&key, "key", os.Getenv("WT_API_KEY"), "API key; default $WT_API_KEY")
	fs.StringVar(&project, "project", "", "project id")
	fs.StringVar(&dir, "dir", "prompts", "directory of prompt YAML files")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if api == "" || key == "" || project == "" {
		return errors.New("--api, --key and --project are required")
	}
	base := strings.TrimRight(api, "/") + "/v1/projects/" + url.PathEscape(project) + "/llm/prompts"
	if args[0] == "push" {
		return promptsPush(ctx, base, key, dir, out)
	}
	return promptsPull(ctx, base, key, dir, out)
}

func promptsPull(ctx context.Context, base, key, dir string, out io.Writer) error {
	cursor, n := "", 0
	for {
		var page struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
			Next string `json:"next_cursor"`
		}
		u := base + "?limit=200"
		if cursor != "" {
			u += "&cursor=" + url.QueryEscape(cursor)
		}
		if err := call(ctx, http.MethodGet, u, key, nil, &page); err != nil {
			return err
		}
		for _, p := range page.Data {
			var d promptDetail
			if err := call(ctx, http.MethodGet, base+"/"+url.PathEscape(p.ID), key, nil, &d); err != nil {
				return err
			}
			if d.Latest == nil {
				continue
			}
			f := promptFile{Name: d.Name, Folder: d.Folder, Type: d.Type, Template: d.Latest.Template, Config: d.Latest.Config, CommitMessage: d.Latest.CommitMessage}
			if m, ok := d.Latest.Config.(map[string]any); ok && len(m) == 0 {
				f.Config = nil
			}
			for _, l := range d.Labels {
				if l.Version == d.Latest.Version {
					f.Labels = append(f.Labels, l.Label)
				}
			}
			if err := writePromptFile(dir, f); err != nil {
				return err
			}
			n++
		}
		if page.Next == "" {
			break
		}
		cursor = page.Next
	}
	fmt.Fprintf(out, "pulled %d prompts into %s\n", n, dir)
	return nil
}

// writePromptFile refuses names that would leave dir (the server validates, a repo path is still ours to protect).
func writePromptFile(dir string, f promptFile) error {
	rel := filepath.Join(filepath.FromSlash(f.Folder), f.Name+".yaml")
	if !filepath.IsLocal(rel) {
		return fmt.Errorf("prompt %q in folder %q is not a safe file path", f.Name, f.Folder)
	}
	b, err := yaml.Marshal(f)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func promptsPush(ctx context.Context, base, key, dir string, out io.Writer) error {
	var files []promptFile
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".yaml") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var f promptFile
		if err := yaml.Unmarshal(b, &f); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		if f.Name == "" || f.Template == nil || (f.Type != "text" && f.Type != "chat") {
			return fmt.Errorf("%s: name, type (text|chat) and template are required", p)
		}
		files = append(files, f)
		return nil
	})
	if err != nil {
		return err
	}
	for _, f := range files {
		state, err := pushPrompt(ctx, base, key, f)
		if err != nil {
			return fmt.Errorf("%s: %w", f.Name, err)
		}
		fmt.Fprintf(out, "%-9s %s\n", state, f.Name)
	}
	return nil
}

// sameJSON compares two decoded YAML/JSON values the way the API would store them.
func sameJSON(a, b any) bool {
	norm := func(v any) any {
		var o any
		if v == nil {
			v = map[string]any{}
		}
		raw, _ := json.Marshal(v)
		_ = json.Unmarshal(raw, &o)
		return o
	}
	return reflect.DeepEqual(norm(a), norm(b))
}

// pushPrompt creates the prompt or saves a new version when the content changed, then moves labels.
func pushPrompt(ctx context.Context, base, key string, f promptFile) (string, error) {
	var page struct {
		Data []struct {
			ID, Name string
		} `json:"data"`
		Next string `json:"next_cursor"`
	}
	id, cursor := "", ""
	for id == "" {
		u := base + "?limit=200&folder=" + url.QueryEscape(f.Folder)
		if cursor != "" {
			u += "&cursor=" + url.QueryEscape(cursor)
		}
		if err := call(ctx, http.MethodGet, u, key, nil, &page); err != nil {
			return "", err
		}
		for _, d := range page.Data {
			if d.Name == f.Name {
				id = d.ID
			}
		}
		if page.Next == "" {
			break
		}
		cursor = page.Next
	}
	body := map[string]any{"template": f.Template, "config": f.Config, "commit_message": f.CommitMessage}
	state, version := "unchanged", 0
	var d promptDetail
	switch {
	case id == "":
		body["name"], body["folder"], body["type"] = f.Name, f.Folder, f.Type
		if err := call(ctx, http.MethodPost, base, key, body, &d); err != nil {
			return "", err
		}
		state, version = "created", 1
	default:
		if err := call(ctx, http.MethodGet, base+"/"+url.PathEscape(id), key, nil, &d); err != nil {
			return "", err
		}
		if d.Latest == nil || !sameJSON(d.Latest.Template, f.Template) || !sameJSON(d.Latest.Config, f.Config) {
			var v struct {
				Version int `json:"version"`
			}
			if err := call(ctx, http.MethodPost, base+"/"+url.PathEscape(id)+"/versions", key, body, &v); err != nil {
				return "", err
			}
			state, version = "new version", v.Version
		} else {
			version = d.Latest.Version
		}
	}
	if id == "" {
		id = d.ID
	}
	for _, l := range f.Labels {
		if err := call(ctx, http.MethodPut, base+"/"+url.PathEscape(id)+"/labels/"+url.PathEscape(l), key, map[string]any{"version": version}, nil); err != nil {
			return "", err
		}
	}
	return state, nil
}
