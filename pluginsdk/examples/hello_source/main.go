// Command hello_source is the smallest data-source plugin. Query "series" returns a time series,
// "env" lists the environment variable names the process can see (the runner passes none but
// WT_EGRESS_URL), anything else a one-row table echoing the query.
package main

import (
	"context"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-cli/pluginsdk"
)

type hello struct{}

func (hello) Describe() pluginsdk.Manifest {
	return pluginsdk.Manifest{Name: "hello", Version: "1.0.0", Kinds: []string{pluginsdk.KindSource}}
}

func (hello) Query(_ context.Context, req pluginsdk.QueryRequest) (pluginsdk.Frames, error) {
	switch req.Query {
	case "series":
		ts := make([]any, 0, 3)
		vs := make([]any, 0, 3)
		for i := range 3 {
			ts = append(ts, req.From.Add(time.Duration(i)*time.Minute).Format(time.RFC3339))
			vs = append(vs, float64(i))
		}
		return pluginsdk.Frames{Frames: []pluginsdk.Frame{{Name: "hello", Kind: pluginsdk.FrameTimeSeries,
			Fields: []pluginsdk.Field{{Name: "time", Values: ts}, {Name: "value", Values: vs}}}}}, nil
	case "env":
		var names []any
		for _, kv := range os.Environ() {
			names = append(names, strings.SplitN(kv, "=", 2)[0])
		}
		sort.Slice(names, func(i, j int) bool { return names[i].(string) < names[j].(string) })
		return pluginsdk.Frames{Frames: []pluginsdk.Frame{{Name: "env", Kind: pluginsdk.FrameTable,
			Fields: []pluginsdk.Field{{Name: "name", Values: names}}}}}, nil
	}
	return pluginsdk.Frames{Frames: []pluginsdk.Frame{{Name: "echo", Kind: pluginsdk.FrameTable,
		Fields: []pluginsdk.Field{{Name: "query", Values: []any{req.Query}}}}}}, nil
}

func main() { pluginsdk.Serve(hello{}) }
