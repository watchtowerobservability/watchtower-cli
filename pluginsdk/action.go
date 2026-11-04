package pluginsdk

import "context"

// RunRequest is one workflow action call. SecretsRefs name secrets (never values): the runner's
// egress proxy injects them into outbound requests the plugin makes.
type RunRequest struct {
	Inputs      map[string]any `json:"inputs"`
	SecretsRefs []string       `json:"secrets_refs,omitempty"`
}

// Outputs are the action's results, available to later workflow steps.
type Outputs map[string]any

// Action is a workflow step, addressed as `plugin:<name>.<action>`.
type Action interface {
	Describe() Manifest
	Run(ctx context.Context, req RunRequest) (Outputs, error)
}
