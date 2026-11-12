// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package policyhook

import (
	"context"

	"github.com/hashicorp/boundary/internal/event"
	"google.golang.org/protobuf/types/known/structpb"
)

// AuditEmitter writes one audit event per decision through the event system.
// The event carries ids, the decision, the reason and the latency only: never
// request or response bodies, URLs or secrets. A write failure is returned so
// the hook denies (fail closed).
type AuditEmitter struct{}

// Emit implements Emitter.
func (AuditEmitter) Emit(ctx context.Context, e Event) error {
	details, err := structpb.NewStruct(map[string]any{
		"request_id":    e.RequestID,
		"principal_id":  e.PrincipalID,
		"target_id":     e.TargetID,
		"authorizer_id": e.AuthorizerID,
		"decision":      e.Decision.String(),
		"reason":        string(e.Reason),
		"latency_ms":    float64(e.Latency.Milliseconds()),
	})
	if err != nil {
		return err
	}
	return event.WriteAudit(ctx, "policyhook.decision", event.WithFlush(), event.WithRequest(&event.Request{
		// Operation is a public audit field, so the decision and reason stay
		// readable; the ids in Details follow the audit redaction config.
		Operation: "authorize-session/" + e.Decision.String() + "/" + string(e.Reason),
		Details:   details,
	}))
}
