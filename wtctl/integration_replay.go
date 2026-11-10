package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/watchtowerobservability/watchtower-cli/agent/cloud"
	"github.com/watchtowerobservability/watchtower-cli/agent/gpu"
	"github.com/watchtowerobservability/watchtower-cli/agent/integrations"
	"github.com/watchtowerobservability/watchtower-cli/agent/sink"
)

// replayDir is `wtctl integration test --fixture <dir>` for the kinds that read several endpoints
// or tools. A local server answers each request from the file named METHOD_path, with the slashes
// of the path as underscores and the extension free (`GET_api_2.0_clusters_list.json`;
// `POST_root.json` for a POST to `/`). The collector's endpoint is pointed at it. A request with
// no file is a 404 and fails the test, so a collector that starts calling a new endpoint shows up.
// The gpu kind reads `nvidia-smi.csv` (and `nvidia-smi-ecc.csv`) instead: it runs a tool, not a
// server.
func replayDir(ctx context.Context, m *integrations.Manifest, dir string, timeout time.Duration, rec *sink.Recorder) error {
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if m.Module.Kind == "gpu" {
		return replayGPU(dir, rec)
	}
	var mu sync.Mutex
	var missed []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, ok := fixtureFor(dir, r.Method, r.URL.Path)
		if !ok {
			mu.Lock()
			missed = append(missed, r.Method+" "+r.URL.Path)
			mu.Unlock()
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	}))
	defer srv.Close()
	cfg, err := pointAt(m, srv.URL)
	if err != nil {
		return err
	}
	if m.Module.Kind == "cloud_pull" {
		_ = cloud.RunPullsIn(rctx, cfg, "", rec)
	} else if run := integrations.CollectorFor(m.Module.Kind); run != nil {
		_ = run(rctx, cfg, rec)
	} else {
		return fmt.Errorf("module kind %q has no replayable collector", m.Module.Kind)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(missed) > 0 {
		sort.Strings(missed)
		return fmt.Errorf("the collector asked for endpoints with no fixture file in %s: %s", dir, strings.Join(missed, ", "))
	}
	return nil
}

func fixtureFor(dir, method, path string) ([]byte, bool) {
	key := method + "_" + strings.ReplaceAll(strings.Trim(path, "/"), "/", "_")
	if strings.Trim(path, "/") == "" {
		key = method + "_root"
	}
	for _, ext := range []string{".json", ".txt", ""} {
		if b, err := os.ReadFile(filepath.Join(dir, filepath.Base(key+ext))); err == nil {
			return b, true
		}
	}
	return nil, false
}

// pointAt copies the manifest's config defaults with every endpoint (`url`, and `endpoint` inside
// cloud pulls) set to the replay server and a 5 s interval.
func pointAt(m *integrations.Manifest, base string) (json.RawMessage, error) {
	raw, _ := json.Marshal(m.Module.ConfigDefaults)
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	if m.Module.Kind != "cloud_pull" {
		cfg["url"], cfg["interval"] = base, "5s"
		return json.Marshal(cfg)
	}
	pulls, _ := cfg["pulls"].([]any)
	if len(pulls) == 0 {
		return nil, errors.New("cloud_pull defaults have no pulls")
	}
	for _, p := range pulls {
		pm, _ := p.(map[string]any)
		c, _ := pm["config"].(map[string]any)
		if c == nil {
			return nil, errors.New("a pull has no config")
		}
		c["endpoint"] = base
	}
	return json.Marshal(cfg)
}

func replayGPU(dir string, rec *sink.Recorder) error {
	csv, err := os.Open(filepath.Join(dir, "nvidia-smi.csv"))
	if err != nil {
		return err
	}
	defer csv.Close()
	var ecc *os.File
	if f, err := os.Open(filepath.Join(dir, "nvidia-smi-ecc.csv")); err == nil {
		ecc = f
		defer ecc.Close()
	}
	if ecc == nil {
		return gpu.Replay(rec, csv, nil, time.Now())
	}
	return gpu.Replay(rec, csv, ecc, time.Now())
}
