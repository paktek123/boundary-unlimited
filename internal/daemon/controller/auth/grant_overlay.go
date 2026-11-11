// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package auth

import (
	"context"

	"github.com/hashicorp/boundary/internal/perms"
)

// GrantOverlayFunc returns extra grants (for example from approved, unexpired
// access requests) for a user in a scope. It is consulted only when a caller
// opted in with WithGrantOverlay and the action is session authorization. The
// returned grants are ADDED to the grants resolved from roles; they never
// remove or alter them. Any error, panic or nil function means no extra
// grants (fail closed: the overlay can only widen access when it succeeds).
type GrantOverlayFunc func(ctx context.Context, userId, scopeId string) ([]perms.GrantTuple, error)

// WithGrantOverlay makes Verify add the grants f returns to the user's grants.
// A nil f is ignored.
func WithGrantOverlay(f GrantOverlayFunc) Option {
	return func(o *options) {
		o.withGrantOverlay = f
	}
}

// safeOverlay calls f, containing panics. It returns no grants on any failure.
func safeOverlay(ctx context.Context, f GrantOverlayFunc, userId, scopeId string) (out []perms.GrantTuple) {
	if f == nil || userId == "" || scopeId == "" {
		return nil
	}
	defer func() {
		if recover() != nil {
			out = nil
		}
	}()
	got, err := f(ctx, userId, scopeId)
	if err != nil {
		return nil
	}
	return got
}
