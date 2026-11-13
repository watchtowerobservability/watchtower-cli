package main

import (
	"fmt"
	"os"
	"sync"
)

var warnOldAPI sync.Once

// apiEnv is the API base URL from $WT_API_URL; the old $WT_API still works with a one-line warning.
func apiEnv() string {
	if v := os.Getenv("WT_API_URL"); v != "" {
		return v
	}
	v := os.Getenv("WT_API")
	if v != "" {
		warnOldAPI.Do(func() { fmt.Fprintln(os.Stderr, "wtctl: $WT_API is deprecated, use $WT_API_URL") })
	}
	return v
}
