// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package targets

import (
	"context"
	"reflect"

	"github.com/hashicorp/boundary/internal/accessrequest"
	"github.com/hashicorp/boundary/internal/perms"
)

// GrantOverlayProvider returns extra grants for a user in a scope, used by
// AuthorizeSession in addition to the grants resolved from roles. Errors mean
// "no extra grants": the overlay can only add access when it fully succeeds.
type GrantOverlayProvider interface {
	OverlayGrants(ctx context.Context, userID, scopeID string) ([]perms.GrantTuple, error)
}

// WithGrantOverlay returns a copy of the Service whose AuthorizeSession adds
// the provider's grants (UNION) to the built-in grants. A nil or typed-nil
// provider leaves the Service unchanged. With no provider behaviour is
// identical to before. Nothing in the controller configuration selects a
// provider yet and no API can create access requests yet.
func (s Service) WithGrantOverlay(p GrantOverlayProvider) Service {
	if p == nil {
		return s
	}
	if rv := reflect.ValueOf(p); rv.Kind() == reflect.Ptr && rv.IsNil() {
		return s
	}
	s.grantOverlay = p
	return s
}

// AccessRequestOverlay is the GrantOverlayProvider backed by approved access
// requests. It fails closed: a missing source, clock or audit sink, a source or
// clock failure, or any audit emit failure yields no overlay grants (an
// unauditable grant is never given). Grants are exactly the approved grant
// strings of requests that are approved and unexpired; they are limited to the
// request scope and wildcard grants are dropped (see accessrequest.MergeOverlay).
type AccessRequestOverlay struct {
	Source accessrequest.GrantOverlaySource
	Clock  accessrequest.Clock
	// Audit receives one access-request.overlay-authorized event per overlay
	// grant (request, requester and grant ids only) before the grant is used.
	Audit accessrequest.Emitter
}

var _ GrantOverlayProvider = AccessRequestOverlay{}

// OverlayGrants implements GrantOverlayProvider.
func (o AccessRequestOverlay) OverlayGrants(ctx context.Context, userID, scopeID string) (out []perms.GrantTuple, err error) {
	defer func() {
		if recover() != nil {
			out, err = nil, accessrequest.ErrOverlayUnavailable
		}
	}()
	if o.Source == nil || o.Clock == nil || o.Audit == nil {
		return nil, accessrequest.ErrOverlayUnavailable
	}
	res, err := accessrequest.MergeOverlay(ctx, nil, userID, scopeID, o.Source, o.Clock)
	if err != nil {
		return nil, accessrequest.ErrOverlayUnavailable
	}
	for _, ev := range res.Events {
		if o.Audit.Emit(ctx, ev) != nil {
			return nil, accessrequest.ErrOverlayUnavailable
		}
	}
	return res.Grants, nil
}
