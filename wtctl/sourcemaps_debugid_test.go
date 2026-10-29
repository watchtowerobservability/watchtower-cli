package main

import (
	"bytes"
	"context"
	"net/http"
	"path/filepath"
	"testing"
)

// The browser build plugins add a top-level "debugId" to each map and upload it with the same request
// as `wtctl sourcemaps upload`; the CLI must pass such maps through byte for byte.
func TestSourcemapsUploadKeepsDebugIDField(t *testing.T) {
	dir := t.TempDir()
	body := []byte(`{"version":3,"debugId":"3f1c2a4e-9b7d-4c1e-8a55-0d2e6f7a8b9c","sources":["a.ts"]}`)
	write(t, filepath.Join(dir, "assets", "app-1a2b.js.map"), body)
	srv, got := artifactServer(t, http.StatusCreated)
	o := artifactOpts{api: srv.URL, key: "k", project: "prj_1", release: "abc123"}
	if err := sourcemapsUpload(context.Background(), o, dir, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	u := got()
	if len(u) != 1 || u[0].kind != "sourcemap" || u[0].name != "assets/app-1a2b.js.map" || u[0].release != "abc123" || !bytes.Equal(u[0].body, body) {
		t.Fatalf("unexpected upload: %+v", u)
	}
}
