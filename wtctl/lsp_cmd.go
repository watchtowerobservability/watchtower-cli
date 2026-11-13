package main

import (
	"context"
	"errors"
	"os"

	"github.com/watchtowerobservability/watchtower-cli/wtctl/lsp"
)

// lspMain runs the language server on stdin/stdout until the editor exits. It has no
// deadline: the session lives as long as the editor.
func lspMain(ctx context.Context) error {
	api, key := apiEnv(), os.Getenv("WT_API_KEY")
	if api == "" || key == "" {
		return errors.New("WT_API_URL and WT_API_KEY are required")
	}
	s := lsp.NewServer(&lsp.Client{BaseURL: api, Key: key}, os.Getenv("WT_WEB_URL"), os.Stdout)
	return s.Serve(ctx, os.Stdin)
}
