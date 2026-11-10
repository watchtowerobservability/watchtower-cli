package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// debugKind names the artifact kind of a native debug file from its first bytes, "" if unknown.
// A fat Mach-O (several architectures) is recognised as "macho"; debugFilesUpload splits it.
func debugKind(head []byte) string {
	switch {
	case bytes.HasPrefix(head, []byte("\x7fELF")):
		return "elf"
	case bytes.HasPrefix(head, []byte("Microsoft C/C++ MSF 7.00")):
		return "pdb"
	}
	if len(head) >= 4 {
		switch [4]byte(head[:4]) {
		case [4]byte{0xfe, 0xed, 0xfa, 0xce}, [4]byte{0xfe, 0xed, 0xfa, 0xcf},
			[4]byte{0xce, 0xfa, 0xed, 0xfe}, [4]byte{0xcf, 0xfa, 0xed, 0xfe}:
			return "macho"
		}
		if _, _, ok := fatHeader(head); ok {
			return "macho"
		}
	}
	return ""
}

// debugFilesUpload uploads each file (or every file under each directory) by its detected kind.
// Files of an unknown kind are skipped with a note, except ProGuard mappings, which are text and
// are recognised by the name mapping*.txt, and Unity IL2CPP line maps (LineNumberMappings.json).
func debugFilesUpload(ctx context.Context, o artifactOpts, paths []string, out io.Writer) error {
	uploaded := 0
	for _, root := range paths {
		st, err := os.Stat(root)
		if err != nil {
			return err
		}
		base, names := filepath.Dir(root), []string{filepath.Base(root)}
		if st.IsDir() {
			base = root
			if names, err = findFiles(root, func(string) bool { return true }); err != nil {
				return err
			}
		}
		for _, n := range names {
			p := filepath.Join(base, filepath.FromSlash(n))
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if _, _, fat := fatHeader(data); fat {
				slices, ok := splitFatMachO(data)
				if !ok {
					fmt.Fprintf(out, "skipped %s (not a valid universal Mach-O)\n", n)
					continue
				}
				for _, sl := range slices {
					if err := uploadArtifact(ctx, o, "macho", n+"."+sl.arch, sl.data); err != nil {
						return err
					}
					uploaded++
					fmt.Fprintf(out, "uploaded %s.%s (macho)\n", n, sl.arch)
				}
				continue
			}
			kind := debugKind(data[:min(len(data), 32)])
			if kind == "" && strings.HasPrefix(filepath.Base(n), "mapping") && strings.HasSuffix(n, ".txt") {
				kind = "proguard"
			}
			if kind == "" && bytes.HasPrefix(data, []byte("MODULE ")) {
				kind = "breakpad" // Breakpad .sym text
			}
			if kind == "" && filepath.Base(n) == "LineNumberMappings.json" {
				kind = "il2cpp" // Unity IL2CPP C++ to C# line map
			}
			if kind == "" {
				fmt.Fprintf(out, "skipped %s (not an ELF, Mach-O, PDB or ProGuard file)\n", n)
				continue
			}
			if err := uploadArtifact(ctx, o, kind, n, data); err != nil {
				return err
			}
			uploaded++
			fmt.Fprintf(out, "uploaded %s (%s)\n", n, kind)
		}
	}
	if uploaded == 0 {
		return errors.New("no debug files found")
	}
	return nil
}

func debugFilesMain(ctx context.Context, args []string, out io.Writer) error {
	const usage = "usage: wtctl debug-files upload <path>... --api <url> --key <key> --project <prj_...> [--release <version>]"
	if len(args) < 2 || args[0] != "upload" {
		return errors.New(usage)
	}
	// paths come first, flags after (as with `release create <version>`)
	i := 1
	for i < len(args) && !strings.HasPrefix(args[i], "-") {
		i++
	}
	if i == 1 {
		return errors.New(usage)
	}
	var o artifactOpts
	fs := flag.NewFlagSet("debug-files upload", flag.ContinueOnError)
	o.flags(fs)
	if err := fs.Parse(args[i:]); err != nil {
		return err
	}
	if err := o.check(); err != nil {
		return err
	}
	return debugFilesUpload(ctx, o, args[1:i], out)
}
