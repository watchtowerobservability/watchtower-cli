package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
	"github.com/watchtowerobservability/watchtower-cli/internal/netguard"
)

// maxJunitBytes matches the API limit for the whole multipart body.
const maxJunitBytes = 20 << 20

const ciUsage = "usage: wtctl ci upload-junit <file.xml> --api <url> --key <key> --project <id> --run-id <id> [--branch b] [--sha s] [--suite name] [--coverage pct]"

// junitUpload is one JUnit file and the run it belongs to.
type junitUpload struct {
	api, key, project string
	runID, branch     string
	sha, suite        string
	coverage          string
}

func ciMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "upload-junit" {
		return errors.New(ciUsage)
	}
	fs := flag.NewFlagSet("ci upload-junit", flag.ContinueOnError)
	var u junitUpload
	fs.StringVar(&u.api, "api", "", "API base URL")
	fs.StringVar(&u.key, "key", os.Getenv("WT_API_KEY"), "API key; default $WT_API_KEY")
	fs.StringVar(&u.project, "project", "", "project id")
	fs.StringVar(&u.runID, "run-id", "", "CI run id the results belong to")
	fs.StringVar(&u.branch, "branch", "", "branch")
	fs.StringVar(&u.sha, "sha", "", "commit sha")
	fs.StringVar(&u.suite, "suite", "", "suite name (default: the suite names in the XML)")
	fs.StringVar(&u.coverage, "coverage", "", "coverage percent, 0 to 100")
	// flags may follow the file name
	var files []string
	rest := args[1:]
	for len(rest) > 0 {
		if err := fs.Parse(rest); err != nil {
			return err
		}
		rest = fs.Args()
		if len(rest) > 0 {
			files = append(files, rest[0])
			rest = rest[1:]
		}
	}
	if len(files) != 1 {
		return errors.New(ciUsage)
	}
	if u.api == "" || u.key == "" || u.project == "" || u.runID == "" {
		return errors.New("--api, --key, --project and --run-id are required")
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		return err
	}
	body, err := uploadJunit(ctx, netguard.Guarded("wtctl", 0), u, data)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, strings.TrimSpace(body))
	return nil
}

// uploadJunit posts the file as multipart/form-data and returns the response body.
func uploadJunit(ctx context.Context, c *http.Client, u junitUpload, xml []byte) (string, error) {
	if len(xml) > maxJunitBytes-(1<<10) {
		return "", fmt.Errorf("JUnit file is larger than %d MiB", maxJunitBytes>>20)
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, f := range [][2]string{{"run_id", u.runID}, {"branch", u.branch}, {"sha", u.sha}, {"suite", u.suite}, {"coverage_pct", u.coverage}} {
		if f[1] == "" {
			continue
		}
		if err := mw.WriteField(f[0], f[1]); err != nil {
			return "", err
		}
	}
	fw, err := mw.CreateFormFile("file", "junit.xml")
	if err != nil {
		return "", err
	}
	if _, err := fw.Write(xml); err != nil {
		return "", err
	}
	if err := mw.Close(); err != nil {
		return "", err
	}
	endpoint := strings.TrimRight(u.api, "/") + "/v1/projects/" + url.PathEscape(u.project) + "/test-runs"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, &buf)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+u.key)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return string(b), nil
}
