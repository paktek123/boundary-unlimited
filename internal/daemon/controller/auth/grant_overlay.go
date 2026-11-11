// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package auth

import (
	"context"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/types/action"
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

// applyOverlay adds the overlay grants to the role grants. The overlay is used
// only for session authorization and only for an identified (non-anonymous)
// user. Overlay tuples are parsed one by one and any that fail to parse are
// skipped, so the overlay can never make the check fail. Grants are appended,
// never replacing the role grants. With a nil overlay the inputs are returned
// unchanged.
func applyOverlay(ctx context.Context, overlay GrantOverlayFunc, act action.Type, userId, scopeId string, tuples []perms.GrantTuple, parsed []perms.Grant) ([]perms.GrantTuple, []perms.Grant) {
	if overlay == nil || act != action.AuthorizeSession || userId == "" || userId == globals.AnonymousUserId {
		return tuples, parsed
	}
	for _, tuple := range safeOverlay(ctx, overlay, userId, scopeId) {
		g, err := perms.Parse(ctx, tuple,
			perms.WithUserId(userId),
			perms.WithSkipFinalValidation(true))
		if err != nil {
			continue
		}
		tuples = append(tuples, tuple)
		parsed = append(parsed, g)
	}
	return tuples, parsed
}
