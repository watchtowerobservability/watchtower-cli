package main

import (
	"errors"
	"flag"
	"fmt"
	"testing"
)

func TestHelpExit(t *testing.T) {
	usage := errors.New("usage: wtctl x")
	for _, c := range []struct {
		err  error
		args []string
		want bool
	}{
		{nil, []string{"--help"}, false},
		{flag.ErrHelp, nil, true},
		{fmt.Errorf("%w\nusage", flag.ErrHelp), nil, true},
		{usage, []string{"--key", "k", "-h"}, true},
		{usage, []string{"--", "-h"}, false},
		{usage, []string{"--key", "k"}, false},
	} {
		if got := helpExit(c.err, c.args); got != c.want {
			t.Errorf("helpExit(%v, %v) = %v, want %v", c.err, c.args, got, c.want)
		}
	}
}
