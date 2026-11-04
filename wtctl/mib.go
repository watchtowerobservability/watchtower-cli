package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/watchtowerobservability/watchtower-cli/agent/snmp/mibc"
)

const mibUsage = "usage: wtctl mib compile [-I <dir>]... [-manifest-dir manifests] [-trap-dir trapprofiles] <file.mib>..."

type dirList []string

func (d *dirList) String() string     { return strings.Join(*d, ",") }
func (d *dirList) Set(v string) error { *d = append(*d, v); return nil }

// mibMain compiles vendor MIB files into SNMP manifests (the agent's snmp.manifest_dir) and trap
// profiles (snmp.trap.profile_dir). MIB files under -I directories are loaded only to resolve
// imports; only the modules of the named files are written.
func mibMain(_ context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "compile" {
		return errors.New(mibUsage)
	}
	var inc dirList
	fs := flag.NewFlagSet("mib compile", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Var(&inc, "I", "directory of MIBs to resolve imports from (repeatable)")
	manDir := fs.String("manifest-dir", "manifests", "where manifests are written")
	trapDir := fs.String("trap-dir", "trapprofiles", "where trap profiles are written")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() == 0 {
		return errors.New(mibUsage)
	}
	c := mibc.New()
	for _, d := range inc {
		files, _ := filepath.Glob(filepath.Join(d, "*"))
		for _, f := range files {
			if st, err := os.Stat(f); err == nil && st.Mode().IsRegular() {
				_, _ = c.AddFile(f) // a non-MIB file in an import directory is not an error
			}
		}
	}
	var mods []string
	for _, f := range fs.Args() {
		names, err := c.AddFile(f)
		if err != nil {
			return err
		}
		mods = append(mods, names...)
	}
	for _, d := range []string{*manDir, *trapDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	for _, m := range mods {
		r, err := c.Compile(m)
		if err != nil {
			return err
		}
		for _, w := range r.Warnings {
			fmt.Fprintln(out, "warning:", m+":", w)
		}
		base := strings.ToLower(m) + ".yaml"
		if len(r.Manifest.Tables)+len(r.Manifest.Scalars) > 0 {
			if err := writeYAML(filepath.Join(*manDir, base), "# Compiled by wtctl mib compile from "+m+".\n", r.Manifest); err != nil {
				return err
			}
		}
		if len(r.Traps.Traps) > 0 {
			if err := writeYAML(filepath.Join(*trapDir, base), "# Trap profile compiled by wtctl mib compile from "+m+".\n", r.Traps); err != nil {
				return err
			}
		}
		fmt.Fprintf(out, "%s: %d tables, %d scalars, %d traps\n", m, len(r.Manifest.Tables), len(r.Manifest.Scalars), len(r.Traps.Traps))
	}
	return nil
}

func writeYAML(path, header string, v any) error {
	b, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append([]byte(header), b...), 0o644) //nolint:gosec // config, not a secret
}
