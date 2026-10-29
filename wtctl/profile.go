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
	"path/filepath"
	"sort"
	"strings"
	"github.com/watchtowerobservability/watchtower-cli/internal/netguard"
)

const profileUsage = `usage: wtctl profile upload <file> --service <s> --version <v> [--format pprof|folded] [--env <e>] --endpoint <url> --key <wti_...>
       wtctl profile top <service> [--type cpu] [--from <rfc3339|unix>] --api <url> --key <key> --project <prj_...>
       wtctl profile convert-cpuprofile <file.cpuprofile>   (V8 .cpuprofile to folded stacks on stdout)`

func profileMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) < 2 || strings.HasPrefix(args[1], "-") {
		return errors.New(profileUsage)
	}
	sub, arg, rest := args[0], args[1], args[2:] // positional first, flags after
	switch sub {
	case "convert-cpuprofile":
		return convertCpuprofile(arg, out)
	case "upload":
		return profileUploadCmd(ctx, arg, rest, out)
	case "top":
		return profileTopCmd(ctx, arg, rest, out)
	}
	return errors.New(profileUsage)
}

func profileUploadCmd(ctx context.Context, file string, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("profile upload", flag.ContinueOnError)
	endpoint := fs.String("endpoint", os.Getenv("WT_ENDPOINT"), "gateway base URL; default $WT_ENDPOINT")
	key := fs.String("key", os.Getenv("WT_INGEST_KEY"), "ingestion key (ingest:profiles); default $WT_INGEST_KEY")
	service := fs.String("service", "", "service name")
	version := fs.String("version", "", "service version")
	env := fs.String("env", "", "environment (informational; the key's environment wins)")
	format := fs.String("format", "", "pprof or folded (default: folded for .folded/.txt/.collapsed, else pprof)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *endpoint == "" || *key == "" || *service == "" {
		return errors.New("--endpoint, --key and --service are required")
	}
	if *format == "" {
		*format = "pprof"
		switch strings.ToLower(filepath.Ext(file)) {
		case ".folded", ".txt", ".collapsed":
			*format = "folded"
		}
	}
	if *format != "pprof" && *format != "folded" {
		return errors.New("--format must be pprof or folded")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	q := url.Values{"service": {*service}, "format": {*format}}
	if *version != "" {
		q.Set("version", *version)
	}
	if *env != "" {
		q.Set("env", *env)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(*endpoint, "/")+"/v1/profiles?"+q.Encode(), bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+*key)
	req.Header.Set("Content-Type", "application/octet-stream")
	if bytes.HasPrefix(data, []byte{0x1f, 0x8b}) {
		req.Header.Set("Content-Encoding", "gzip")
	}
	resp, err := netguard.Guarded("wtctl", 0).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s: %s: %s", file, resp.Status, strings.TrimSpace(string(b)))
	}
	fmt.Fprintf(out, "uploaded %s (%s) %s\n", file, *format, strings.TrimSpace(string(b)))
	return nil
}

func profileTopCmd(ctx context.Context, service string, args []string, out io.Writer) error {
	var o artifactOpts
	fs := flag.NewFlagSet("profile top", flag.ContinueOnError)
	o.flags(fs)
	typ := fs.String("type", "cpu", "sample type")
	from := fs.String("from", "", "window start (RFC 3339 or unix seconds)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := o.check(); err != nil {
		return err
	}
	q := url.Values{"service": {service}, "type": {*typ}, "by": {"function"}}
	if *from != "" {
		q.Set("from", *from)
	}
	u := strings.TrimRight(o.api, "/") + "/v1/projects/" + url.PathEscape(o.project) + "/profiles/top?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+o.key)
	resp, err := netguard.Guarded("wtctl", 0).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var pretty bytes.Buffer
	if json.Indent(&pretty, b, "", "  ") != nil {
		pretty.Reset()
		pretty.Write(b)
	}
	fmt.Fprintln(out, strings.TrimSpace(pretty.String()))
	return nil
}

// cpuprofile is the subset of the V8 .cpuprofile format used for folding.
type cpuprofile struct {
	Nodes []struct {
		ID        int `json:"id"`
		CallFrame struct {
			FunctionName string `json:"functionName"`
			URL          string `json:"url"`
			LineNumber   int    `json:"lineNumber"`
		} `json:"callFrame"`
		Children []int `json:"children"`
	} `json:"nodes"`
	Samples []int `json:"samples"`
}

// foldCpuprofile turns a V8 .cpuprofile into folded stacks (root first, one count per sample).
func foldCpuprofile(raw []byte) (map[string]int, error) {
	var p cpuprofile
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("not a .cpuprofile: %w", err)
	}
	if len(p.Nodes) == 0 {
		return nil, errors.New("not a .cpuprofile: no nodes")
	}
	parent, name := map[int]int{}, map[int]string{}
	for _, n := range p.Nodes {
		f := n.CallFrame.FunctionName
		if f == "" {
			f = "(anonymous)"
		}
		if n.CallFrame.URL != "" {
			f = fmt.Sprintf("%s (%s:%d)", f, n.CallFrame.URL, n.CallFrame.LineNumber+1)
		}
		name[n.ID] = strings.NewReplacer(";", ":", "\n", " ").Replace(f)
		for _, c := range n.Children {
			parent[c] = n.ID
		}
	}
	folded := map[string]int{}
	for _, s := range p.Samples {
		if _, ok := name[s]; !ok {
			continue
		}
		var frames []string
		for id, hops := s, 0; hops < 10000; hops++ {
			frames = append(frames, name[id])
			next, ok := parent[id]
			if !ok {
				break
			}
			id = next
		}
		for i, j := 0, len(frames)-1; i < j; i, j = i+1, j-1 {
			frames[i], frames[j] = frames[j], frames[i]
		}
		folded[strings.Join(frames, ";")]++
	}
	return folded, nil
}

func convertCpuprofile(file string, out io.Writer) error {
	raw, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	folded, err := foldCpuprofile(raw)
	if err != nil {
		return err
	}
	stacks := make([]string, 0, len(folded))
	for s := range folded {
		stacks = append(stacks, s)
	}
	sort.Strings(stacks)
	for _, s := range stacks {
		fmt.Fprintf(out, "%s %d\n", s, folded[s])
	}
	return nil
}
