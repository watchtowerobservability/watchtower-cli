package pluginsdk

import (
	"context"
	"time"
)

// Frame kinds a Source may return.
const (
	FrameTimeSeries = "timeseries"
	FrameTable      = "table"
	FrameLogs       = "logs"
)

// QueryRequest is one data-source query. Vars are the dashboard variable values.
type QueryRequest struct {
	Query string            `json:"query"`
	From  time.Time         `json:"from"`
	To    time.Time         `json:"to"`
	Step  time.Duration     `json:"step"`
	Vars  map[string]string `json:"vars,omitempty"`
}

// Field is one column; Values has one entry per row (numbers, strings, RFC 3339 times).
type Field struct {
	Name   string `json:"name"`
	Values []any  `json:"values"`
}

// Frame is a time series, table or log result.
type Frame struct {
	Name   string  `json:"name"`
	Kind   string  `json:"kind"`
	Fields []Field `json:"fields"`
}

// Frames is a Source's answer.
type Frames struct {
	Frames []Frame `json:"frames"`
}

// Source answers queries for dashboards.
type Source interface {
	Describe() Manifest
	Query(ctx context.Context, req QueryRequest) (Frames, error)
}
