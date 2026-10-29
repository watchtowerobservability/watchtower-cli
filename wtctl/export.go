package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/watchtowerobservability/watchtower-cli/internal/ascode"
)

// exportMain is `wtctl export`: live resources as manifests with ${ENV} references for secrets,
// to stdout or one file per resource below --out.
func exportMain(ctx context.Context, args []string, out io.Writer) error {
	var o asCodeOpts
	fs := o.flags("export")
	fs.StringVar(&o.kinds, "kinds", "", "comma-separated kinds (default: all)")
	fs.StringVar(&o.outDir, "out", "", "write one YAML file per resource into this directory")
	c, err := o.client(fs, args)
	if err != nil {
		return err
	}
	var kinds []string
	if o.kinds != "" {
		kinds = strings.Split(o.kinds, ",")
	}
	docs, err := c.Export(ctx, kinds)
	if err != nil {
		return err
	}
	if o.outDir == "" {
		b, err := ascode.Marshal(docs)
		if err != nil {
			return err
		}
		_, err = out.Write(b)
		return err
	}
	if err := os.MkdirAll(o.outDir, 0o755); err != nil {
		return err
	}
	for _, d := range docs {
		b, err := ascode.Marshal([]ascode.Doc{d})
		if err != nil {
			return err
		}
		name := strings.ToLower(d.Kind + "-" + d.Metadata.Name)
		name = strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.' {
				return r
			}
			return '_'
		}, name)
		if err := os.WriteFile(o.outDir+"/"+name+".yaml", b, 0o644); err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "exported %d resource(s) to %s\n", len(docs), o.outDir)
	return nil
}
