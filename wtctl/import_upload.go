package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Imports run on the server (DX-21): the CLI uploads the export file to
// POST /v1/projects/{p}/imports and polls GET /v1/projects/{p}/imports/{id}. The vendor
// mappings never ship in this binary.

// importPollEvery is the poll interval; tests shorten it.
var importPollEvery = time.Second

const importWait = 15 * time.Minute

// importJobView is the API's view of a job.
type importJobView struct {
	ID     string `json:"id"`
	State  string `json:"state"`
	Error  string `json:"error"`
	Result struct {
		Output   string          `json:"output"`
		Report   json.RawMessage `json:"report"`
		Markdown string          `json:"markdown"`
	} `json:"result"`
}

// uploadImport sends the named files (role -> path) and text fields, then waits for the job.
func uploadImport(ctx context.Context, api, key, project, source string, apply bool, fields, files map[string]string) (importJobView, error) {
	var view importJobView
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	mode := "dry_run"
	if apply {
		mode = "apply"
	}
	_ = mw.WriteField("source", source)
	_ = mw.WriteField("mode", mode)
	for k, v := range fields {
		if v != "" {
			_ = mw.WriteField(k, v)
		}
	}
	for role, path := range files {
		if path == "" {
			continue
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return view, err
		}
		w, err := mw.CreateFormFile(role, filepath.Base(path))
		if err != nil {
			return view, err
		}
		_, _ = w.Write(b)
	}
	if err := mw.Close(); err != nil {
		return view, err
	}
	base := strings.TrimRight(api, "/") + "/v1/projects/" + url.PathEscape(project) + "/imports"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base, &body)
	if err != nil {
		return view, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := guardedClient(2 * time.Minute).Do(req)
	if err != nil {
		return view, err
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated || json.Unmarshal(b, &view) != nil {
		return view, fmt.Errorf("upload: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	deadline := time.Now().Add(importWait)
	for view.State == "queued" || view.State == "running" {
		if time.Now().After(deadline) {
			return view, errors.New("the import is still running; check GET " + base + "/" + view.ID)
		}
		select {
		case <-ctx.Done():
			return view, ctx.Err()
		case <-time.After(importPollEvery):
		}
		if err := call(ctx, http.MethodGet, base+"/"+view.ID, key, nil, &view); err != nil {
			return view, err
		}
	}
	switch view.State {
	case "succeeded":
		return view, nil
	case "expired":
		return view, errors.New("no import runner picked the upload up in time; it was discarded")
	}
	return view, fmt.Errorf("import failed: %s", view.Error)
}

// writeImportReport writes <prefix>.json and <prefix>.md from the job result.
func writeImportReport(prefix string, v importJobView) error {
	if len(v.Result.Report) > 0 {
		if err := os.WriteFile(prefix+".json", append(v.Result.Report, '\n'), 0o644); err != nil {
			return err
		}
	}
	if v.Result.Markdown != "" {
		return os.WriteFile(prefix+".md", []byte(v.Result.Markdown), 0o644)
	}
	return nil
}
