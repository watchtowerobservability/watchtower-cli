package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// activityTemplates are the compliance starter sets of crates/wt-domain activity/templates.rs.
var activityTemplates = [][2]string{
	{"soc2", "SOC 2: auth, user lifecycle, roles, API keys, exports, settings, access reviews, incidents"},
	{"iso27001", "ISO 27001: the common set plus access reviews, asset classification, policy acknowledgement"},
	{"hipaa", "HIPAA: the common set plus PHI viewed, exported and disclosed, and break-glass access"},
}

// activityTemplatesMain lists the starter sets, or imports one (`--import soc2`) as action
// schemas in warn mode. Re-importing is a no-op: actions that already have a schema are skipped.
func activityTemplatesMain(ctx context.Context, args []string, out io.Writer) error {
	var o activityOpts
	fs := flag.NewFlagSet("activity templates", flag.ContinueOnError)
	o.bind(fs)
	name := fs.String("import", "", "template to import: soc2, iso27001 or hipaa")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		for _, t := range activityTemplates {
			fmt.Fprintf(out, "%-9s %s\n", t[0], t[1])
		}
		return nil
	}
	known := false
	for _, t := range activityTemplates {
		known = known || t[0] == *name
	}
	if !known {
		return errors.New("--import must be soc2, iso27001 or hipaa")
	}
	if err := o.check(); err != nil {
		return err
	}
	var res struct {
		Imported []string `json:"imported"`
		Skipped  []string `json:"skipped"`
	}
	if err := call(ctx, http.MethodPost, o.base()+"/schema-imports", o.key, map[string]string{"template": *name}, &res); err != nil {
		return err
	}
	fmt.Fprintf(out, "imported %d schema(s) in warn mode: %s\n", len(res.Imported), strings.Join(res.Imported, ", "))
	if len(res.Skipped) > 0 {
		fmt.Fprintf(out, "skipped %d with a schema already: %s\n", len(res.Skipped), strings.Join(res.Skipped, ", "))
	}
	return nil
}
