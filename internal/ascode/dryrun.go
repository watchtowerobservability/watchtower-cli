package ascode

import (
	"context"
	"errors"
	"fmt"
)

// serverDryRun lists the kinds whose create the server can validate without writing it: it answers
// `POST ...?dryRun=1` with 200, the resource shape and `"dryRun": true`, or with the 409/422 the
// real call would give. The secret-bearing creates are the point: a typo in a scope or a wrong
// env_id used to cost an orphan key.
var serverDryRun = map[string]bool{
	"Organization": true, "Project": true, "IngestKey": true, "PublishableKey": true,
	"ServiceAccount": true, "ServiceAccountKey": true,
}

// dryResult is the outcome of asking the server about one planned create.
type dryResult struct {
	checked bool  // the server validated it
	problem error // the server would refuse it: reported, the dry run goes on
	fatal   error // the dry run itself went wrong (the server wrote something): stop
}

// checkCreate sends the planned create with ?dryRun=1. A create that names a resource this run has not
// created yet cannot be asked about (its id does not exist) and is only planned.
func (c *Client) checkCreate(ctx context.Context, ch Change) dryResult {
	k := ByKind(ch.Kind)
	spec, err := ExpandSecrets(k, ch.doc.Spec)
	if err == nil {
		spec, err = c.resolveRefs(k, localSpec(k, spec), true)
	}
	if err != nil {
		return dryResult{}
	}
	c.dryCreate = true
	out, err := c.Create(ctx, k, ch.Name, spec)
	c.dryCreate = false
	switch {
	case errors.Is(err, errUnresolved):
		return dryResult{}
	case err != nil:
		return dryResult{problem: fmt.Errorf("create %s/%s: the server would refuse it: %w", ch.Kind, ch.Name, err)}
	}
	if d, _ := out["dryRun"].(bool); d {
		return dryResult{checked: true}
	}
	// An older server ignores the parameter and writes the resource: take it back at once.
	msg := fmt.Sprintf("the server does not support ?dryRun=1 and created %s/%s", ch.Kind, ch.Name)
	id, _ := out["id"].(string)
	switch {
	case id == "" || k.NoDelete:
		msg += "; remove it by hand"
	default:
		if derr := c.Delete(ctx, k, Item{Ref: id, Name: ch.Name}); derr != nil {
			msg += "; removing it failed, remove it by hand: " + derr.Error()
		} else {
			msg += " (removed again; any one-time secret it showed is void)"
		}
	}
	return dryResult{fatal: errors.New(msg)}
}
