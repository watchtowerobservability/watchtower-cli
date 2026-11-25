package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/watchtowerobservability/watchtower-cli/internal/ascode"
)

// statusPage is `kind: StatusPage` (or an item of a bundle's `status_pages:`). It desugars into a
// status_page Receiver plus routes in the project's Routing tree; apply never calls the receiver's
// test endpoint (a :test would open a real incident on the page).
type statusPage struct {
	Name       string `yaml:"name"`
	Provider   string `yaml:"provider"`
	Space      string `yaml:"space"` // informational: the hook url/secret already identify the space
	URL        string `yaml:"url"`   // ${ENV} ref; default ${WT_STATUSPAGE_<NAME>_URL}
	Secret     string `yaml:"secret"`
	Components []struct {
		Monitor string `yaml:"monitor"`
		Label   string `yaml:"label"` // Forumulate maps the monitor label to the component itself
	} `yaml:"components"`
}

var nonEnv = regexp.MustCompile(`[^A-Z0-9]+`)

// loadDocs is ascode.LoadDocs that also understands StatusPage.
func loadDocs(path string) ([]ascode.Doc, error) {
	files := []string{path}
	if st, err := os.Stat(path); err != nil {
		return nil, err
	} else if st.IsDir() {
		files = nil
		err := filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && slices.Contains([]string{".yaml", ".yml", ".json"}, filepath.Ext(p)) {
				files = append(files, p)
			}
			return err
		})
		if err != nil {
			return nil, err
		}
		sort.Strings(files)
	}
	var docs []ascode.Doc
	var pages []statusPage
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		b, ps, err := splitStatusPages(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		pages = append(pages, ps...)
		got, err := ascode.ParseDocs(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		docs = append(docs, got...)
	}
	return expandStatusPages(docs, pages)
}

// splitStatusPages takes the StatusPage documents and `status_pages` sections out of a YAML stream.
func splitStatusPages(src []byte) ([]byte, []statusPage, error) {
	if !bytes.Contains(src, []byte("StatusPage")) && !bytes.Contains(src, []byte("status_pages")) {
		return src, nil, nil
	}
	dec := yaml.NewDecoder(bytes.NewReader(src))
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	var pages []statusPage
	for {
		var n yaml.Node
		if err := dec.Decode(&n); err != nil {
			if errors.Is(err, io.EOF) {
				if out.Len() == 0 {
					return nil, pages, nil // Close on an empty stream is an error
				}
				return out.Bytes(), pages, enc.Close()
			}
			return nil, nil, err
		}
		root := &n
		if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
			root = root.Content[0]
		}
		var head struct {
			Kind     string
			Metadata struct{ Name string }
			Spec     statusPage
		}
		if root.Kind == yaml.MappingNode {
			if err := root.Decode(&head); err == nil && head.Kind == "StatusPage" {
				head.Spec.Name = head.Metadata.Name
				pages = append(pages, head.Spec)
				continue
			}
			for i := 0; i+1 < len(root.Content); i += 2 {
				if root.Content[i].Value != "status_pages" {
					continue
				}
				var ps []statusPage
				if err := root.Content[i+1].Decode(&ps); err != nil {
					return nil, nil, fmt.Errorf("status_pages: %w", err)
				}
				pages = append(pages, ps...)
				root.Content = slices.Delete(root.Content, i, i+2)
				break
			}
			if len(root.Content) == 0 {
				continue
			}
		}
		if err := enc.Encode(&n); err != nil {
			return nil, nil, err
		}
	}
}

// expandStatusPages turns each page into a Receiver and routes (continue: true, so the page sees
// alerts without taking them from the rest of the tree), merged ahead of any Routing doc.
func expandStatusPages(docs []ascode.Doc, pages []statusPage) ([]ascode.Doc, error) {
	var routes []any
	var recv []map[string]any
	root := ""
	for _, p := range pages {
		if p.Name == "" || len(p.Components) == 0 {
			return nil, fmt.Errorf("StatusPage %q: name and at least one component are required", p.Name)
		}
		if p.Provider == "" {
			p.Provider = "forumulate"
		}
		env := "WT_STATUSPAGE_" + strings.Trim(nonEnv.ReplaceAllString(strings.ToUpper(p.Name), "_"), "_")
		// The API keeps `provider` among the secrets, and secrets must be ${ENV} references.
		os.Setenv(env+"_PROVIDER", p.Provider)
		ref := func(v, suffix string) string {
			if v != "" {
				return v
			}
			return "${" + env + suffix + "}"
		}
		name := "status-" + p.Name
		recv = append(recv, map[string]any{"apiVersion": ascode.APIVersion, "kind": "Receiver", "metadata": map[string]any{"name": name},
			"spec": map[string]any{"kind": "status_page", "secrets": map[string]any{
				"provider": "${" + env + "_PROVIDER}", "url": ref(p.URL, "_URL"), "secret": ref(p.Secret, "_SECRET")}}})
		for _, c := range p.Components {
			if c.Monitor == "" {
				return nil, fmt.Errorf("StatusPage %s: a component needs a monitor", p.Name)
			}
			routes = append(routes, map[string]any{"matchers": []any{map[string]any{"name": "monitor", "op": "eq", "value": c.Monitor}}, "receiver": name, "continue": true})
		}
		routes = append(routes, map[string]any{"matchers": []any{}, "receiver": name, "continue": true})
		if root == "" {
			root = name
		}
	}
	if len(pages) == 0 {
		return docs, nil
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	for _, r := range recv {
		if err := enc.Encode(r); err != nil {
			return nil, err
		}
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	b := buf.Bytes()
	rdocs, err := ascode.ParseDocs(b)
	if err != nil {
		return nil, err
	}
	docs = append(docs, rdocs...)
	for i := range docs {
		if docs[i].Kind == "Routing" {
			old, _ := docs[i].Spec["routes"].([]any)
			docs[i].Spec["routes"] = append(routes, old...)
			return docs, nil
		}
	}
	return append(docs, ascode.Doc{APIVersion: ascode.APIVersion, Kind: "Routing", Metadata: ascode.Metadata{Name: "routing"},
		Spec: map[string]any{"receiver": root, "routes": routes}}), nil
}
