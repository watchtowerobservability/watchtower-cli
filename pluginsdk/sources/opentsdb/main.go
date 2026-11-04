// Command opentsdb is the OpenTSDB data source: a panel's query is "<host>|sum:metric{tag=value}".
// Add the host to egress_hosts in the plugin's manifest, and any credential as a secret header.
package main

import (
	"context"

	"github.com/watchtowerobservability/watchtower-cli/pluginsdk"
	"github.com/watchtowerobservability/watchtower-cli/pluginsdk/sources/tsdb"
)

type source struct{}

func (source) Describe() pluginsdk.Manifest {
	return pluginsdk.Manifest{Name: "opentsdb", Version: "1.0.0", Kinds: []string{pluginsdk.KindSource}}
}

func (source) Query(ctx context.Context, req pluginsdk.QueryRequest) (pluginsdk.Frames, error) {
	host, q, err := tsdb.Split(req.Query)
	if err != nil {
		return pluginsdk.Frames{}, err
	}
	path := tsdb.OpenTSDBPath(q, req.From, req.To)
	b, err := tsdb.Get(ctx, host, path)
	if err != nil {
		return pluginsdk.Frames{}, err
	}
	return tsdb.ParseOpenTSDB(b)
}

func main() { pluginsdk.Serve(source{}) }
