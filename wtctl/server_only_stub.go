//go:build !wtserver

package main

import (
	"context"
	"fmt"
	"io"
)

// These commands run the server-side check and load engines, which are not in the public build
// (build tag wtserver). The names stay registered so help and dispatch are unchanged.
func serverOnly(cmd string) error {
	return fmt.Errorf("`wtctl %s` runs the server-side check engine and is not in the public build; run it from the Watchtower console or API", cmd)
}

func checksImportPostman(args []string, out, errw io.Writer) error {
	return serverOnly("checks import-postman")
}

func checksImportCurl(args []string, in io.Reader, out, errw io.Writer) error {
	return serverOnly("checks import-curl")
}

func checksRecordMobile(ctx context.Context, args []string, in io.Reader, out io.Writer) error {
	return serverOnly("checks record-mobile")
}

func loadtestCLI(ctx context.Context, args []string, out io.Writer) error {
	return serverOnly("loadtest " + args[0])
}
