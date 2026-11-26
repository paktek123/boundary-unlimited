// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package accessrequests

import (
	"context"
	"errors"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/accessrequest"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
)

// errUnauthenticated is the fixed reason returned for every resolver failure.
// It never carries the underlying error, a grant string or a token.
var errUnauthenticated = errors.New("accessrequests: unauthenticated")

// anonymousUserId is the id of the anonymous user; it is never an access
// request caller.
const anonymousUserId = "u_anon"

// verifyFunc matches auth.Verify. It is a field so tests can substitute a fake
// verifier without a database.
type verifyFunc func(ctx context.Context, typ resource.Type, opt ...auth.Option) auth.VerifyResults

// VerifiedActorResolver is the ActorResolver backed by auth.Verify. The actor
// id comes from the verified result.
//
// auth.Verify authorizes one action on one resource, so it is always called
// with a real action: action.Approve on an access request in the request's
// stored scope when a scope is given, and action.Read in the global scope for
// an authenticate-only call. An authenticated caller who lacks the grant gets
// a forbidden result with the user id and AuthenticationFinished set;
// that is "authenticated, cannot approve", not "unauthenticated". CanApprove is
// true only when Verify itself authorized approve, and perms.ACL never lets
// type=* or actions=* satisfy it for access requests.
//
// Actor.Grants is left empty: the approval domain check requires the approver
// to hold every requested grant, so approval fails closed (ErrGrantsNotHeld)
// until a follow-up supplies the resolved grant strings.
//
// The resolver is not registered in the controller (see #322).
type VerifiedActorResolver struct {
	verify verifyFunc
}

var _ ActorResolver = (*VerifiedActorResolver)(nil)

// NewVerifiedActorResolver returns a resolver backed by auth.Verify.
func NewVerifiedActorResolver() *VerifiedActorResolver {
	return &VerifiedActorResolver{verify: auth.Verify}
}

// Actor authenticates the request. An empty scopeId authenticates only.
// Anonymous and recovery-token callers are refused (by the auth options and,
// as defence in depth, by user id here) and every failure returns
// errUnauthenticated.
func (r *VerifiedActorResolver) Actor(ctx context.Context, scopeId string) (accessrequest.Actor, error) {
	if r == nil || r.verify == nil {
		return accessrequest.Actor{}, errUnauthenticated
	}
	verifyScope, act := scope.Global.String(), action.Read
	if scopeId != "" {
		if !validScopeId(scopeId) {
			return accessrequest.Actor{}, errUnauthenticated
		}
		verifyScope, act = scopeId, action.Approve
	}
	res := r.verify(ctx, resource.AccessRequest,
		auth.WithScopeId(verifyScope),
		auth.WithAction(act),
		auth.WithAnonymousUserNotAllowed(true),
		auth.WithRecoveryTokenNotAllowed(true),
	)
	if !authenticated(res) {
		return accessrequest.Actor{}, errUnauthenticated
	}
	actor := accessrequest.Actor{Id: res.UserId}
	if scopeId != "" {
		// Only Verify's own authorization of approve counts.
		actor.CanApprove = res.Error == nil
	}
	return actor, nil
}

// authenticated reports whether res identifies a real user. A nil error means
// the user is also authorized for the verified action. A forbidden error
// with AuthenticationFinished set means the user is authenticated but not
// granted the action. Every other error, and the anonymous and recovery users,
// are not authenticated.
func authenticated(res auth.VerifyResults) bool {
	if res.UserId == "" || res.UserId == anonymousUserId || res.UserId == globals.RecoveryUserId {
		return false
	}
	switch {
	case res.Error == nil:
		return true
	case errors.Is(res.Error, handlers.ForbiddenError()) && res.AuthenticationFinished:
		return true
	}
	return false
}

// validScopeId reports whether scopeId has the shape of a stored scope id
// (global, an org or a project), so a malformed value fails closed instead of
// silently yielding CanApprove=false.
func validScopeId(scopeId string) bool {
	return scopeId == scope.Global.String() ||
		strings.HasPrefix(scopeId, scope.Org.Prefix()+"_") ||
		strings.HasPrefix(scopeId, scope.Project.Prefix()+"_")
}
