package main

import "strings"

// repeated collects a repeatable string flag (e.g. --var K=V --var K2=V2). Shared by the
// synthetic-checks CLI (checks_run.go) and the load-test CLI; it lives in this non-gated file,
// not the wtserver-gated loadtest_cli.go, so default builds (like the release wtctl binary) resolve it.
type repeated []string

func (r *repeated) String() string     { return strings.Join(*r, ",") }
func (r *repeated) Set(s string) error { *r = append(*r, s); return nil }
