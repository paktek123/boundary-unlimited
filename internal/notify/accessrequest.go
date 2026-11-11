// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package notify

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/accessrequest"
)

// Kind is the lifecycle step an access request notification reports.
type Kind string

// Kinds.
const (
	KindRequested Kind = "requested"
	KindApproved  Kind = "approved"
	KindDenied    Kind = "denied"
	KindExpired   Kind = "expired"
	KindCancelled Kind = "cancelled"
)

// summaries are fixed templates. They never include request fields, so no
// justification, grant, principal name or other free text can reach a receiver.
var summaries = map[Kind]string{
	KindRequested: "An access request was created and is waiting for review.",
	KindApproved:  "An access request was approved.",
	KindDenied:    "An access request was denied.",
	KindExpired:   "An access request expired.",
	KindCancelled: "An access request was cancelled.",
}

// FromAccessRequest builds the notification Event for a lifecycle step of an
// access request. The Event holds only the request id, scope id, the kind (as
// the event type "access_request.<kind>"), a timestamp taken from the request
// and a fixed-template summary. It never contains the justification, grants,
// requester or approver ids, or any credential. An unknown kind, or a request
// without the id, scope or timestamp needed for the kind, is an error.
func FromAccessRequest(req accessrequest.Request, kind Kind) (Event, error) {
	if _, ok := summaries[kind]; !ok {
		return Event{}, fmt.Errorf("%w: kind", ErrInvalidEvent)
	}
	var ts time.Time
	switch kind {
	case KindRequested:
		ts = req.CreatedAt
	case KindApproved, KindDenied, KindCancelled:
		ts = req.DecidedAt
	case KindExpired:
		ts = req.ExpiresAt
		if ts.IsZero() {
			ts = req.DecidedAt
		}
	}
	e := Event{
		Type:      "access_request." + string(kind),
		RequestID: req.Id,
		ScopeID:   req.ScopeId,
		Timestamp: ts.UTC(),
		Summary:   summaries[kind],
	}
	if err := e.Validate(); err != nil {
		return Event{}, err
	}
	return e, nil
}

// AccessRequestNotifier adapts a Notifier (typically a *FanOut) to
// accessrequest.Notifier, so the access-request Service and Sweeper can tell
// destinations about lifecycle steps. It builds the minimal Event with
// FromAccessRequest (ids, kind, timestamp and a fixed summary: never the
// justification, grants or principals) and returns only fixed errors.
type AccessRequestNotifier struct{ n Notifier }

var _ accessrequest.Notifier = (*AccessRequestNotifier)(nil)

// NewAccessRequestNotifier returns the adapter. A nil Notifier is an error.
func NewAccessRequestNotifier(n Notifier) (*AccessRequestNotifier, error) {
	if n == nil {
		return nil, fmt.Errorf("%w: notifier is required", ErrInvalidEvent)
	}
	return &AccessRequestNotifier{n: n}, nil
}

var arKinds = map[accessrequest.NotifyKind]Kind{
	accessrequest.NotifyRequested: KindRequested,
	accessrequest.NotifyApproved:  KindApproved,
	accessrequest.NotifyDenied:    KindDenied,
	accessrequest.NotifyCancelled: KindCancelled,
	accessrequest.NotifyExpired:   KindExpired,
}

// Notify implements accessrequest.Notifier.
func (a *AccessRequestNotifier) Notify(ctx context.Context, kind accessrequest.NotifyKind, r accessrequest.Request) error {
	if a == nil || a.n == nil {
		return ErrNotifierFailed
	}
	k, ok := arKinds[kind]
	if !ok {
		return fmt.Errorf("%w: kind", ErrInvalidEvent)
	}
	e, err := FromAccessRequest(r, k)
	if err != nil {
		return err
	}
	return a.n.Notify(ctx, e)
}
