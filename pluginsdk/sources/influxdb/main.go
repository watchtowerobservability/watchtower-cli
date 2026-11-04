// Command influxdb is the InfluxDB data source: a panel's query is "<host>|<db>|<InfluxQL>", with $timeFilter in its WHERE,
// or "<host>|flux:<org>|<Flux>" (InfluxDB 2), with v.timeRangeStart and v.timeRangeStop in its range().
// Add the host to egress_hosts in the plugin's manifest, and any credential as a secret header.
package main

import (
	"context"
	"errors"
	"strings"

	"github.com/watchtowerobservability/watchtower-cli/pluginsdk"
	"github.com/watchtowerobservability/watchtower-cli/pluginsdk/sources/tsdb"
)

type source struct{}

func (source) Describe() pluginsdk.Manifest {
	return pluginsdk.Manifest{Name: "influxdb", Version: "1.0.0", Kinds: []string{pluginsdk.KindSource}}
}

func (source) Query(ctx context.Context, req pluginsdk.QueryRequest) (pluginsdk.Frames, error) {
	host, q, err := tsdb.Split(req.Query)
	if err != nil {
		return pluginsdk.Frames{}, err
	}
	db, stmt, ok := strings.Cut(q, "|")
	if !ok {
		return pluginsdk.Frames{}, errors.New(`the query must be "<host>|<db>|<InfluxQL>"`)
	}
	if org, ok := strings.CutPrefix(strings.TrimSpace(db), "flux:"); ok {
		path, body, err := tsdb.FluxRequest(org, strings.TrimSpace(stmt), req.From, req.To)
		if err != nil {
			return pluginsdk.Frames{}, err
		}
		b, err := tsdb.Post(ctx, host, path, "application/json", body)
		if err != nil {
			return pluginsdk.Frames{}, err
		}
		return tsdb.ParseFlux(b)
	}
	path := tsdb.InfluxPath(strings.TrimSpace(db), strings.TrimSpace(stmt), req.From, req.To)
	b, err := tsdb.Get(ctx, host, path)
	if err != nil {
		return pluginsdk.Frames{}, err
	}
	return tsdb.ParseInflux(b)
}

func main() { pluginsdk.Serve(source{}) }
