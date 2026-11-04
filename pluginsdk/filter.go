package pluginsdk

import "context"

// Payload kinds a Filter may see. The ingest hot path is deliberately not among them.
const (
	PayloadNotification = "notification"
	PayloadWorkflow     = "workflow"
)

// Payload is a notification or workflow payload; Kind is PayloadNotification or PayloadWorkflow.
type Payload struct {
	Kind string         `json:"kind"`
	Body map[string]any `json:"body"`
}

// Filter rewrites notification and workflow payloads before they are sent or run.
type Filter interface {
	Describe() Manifest
	Process(ctx context.Context, p Payload) (Payload, error)
}

// AllowedPayload reports whether a filter may be applied to this payload kind.
func AllowedPayload(kind string) bool {
	return kind == PayloadNotification || kind == PayloadWorkflow
}
