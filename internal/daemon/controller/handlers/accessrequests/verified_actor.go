// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package accessrequests

import (
	"context"
	"errors"

	"github.com/hashicorp/boundary/internal/accessrequest"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/perms"
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
// id comes from the verified result. CanApprove is true only when the verified
// ACL authorizes the explicit approve action on the access-request type in the
// given (stored) scope; wildcard type or action grants never satisfy it
// because perms.ACL excludes access requests from both wildcards.
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
// Anonymous and recovery-token callers are refused and every failure returns
// errUnauthenticated.
func (r *VerifiedActorResolver) Actor(ctx context.Context, scopeId string) (accessrequest.Actor, error) {
	if r == nil || r.verify == nil {
		return accessrequest.Actor{}, errUnauthenticated
	}
	res := r.verify(ctx, resource.AccessRequest,
		auth.WithScopeId(scope.Global.String()),
		auth.WithAnonymousUserNotAllowed(true),
		auth.WithRecoveryTokenNotAllowed(true),
	)
	if res.Error != nil || res.UserId == "" || res.UserId == anonymousUserId {
		return accessrequest.Actor{}, errUnauthenticated
	}
	actor := accessrequest.Actor{Id: res.UserId}
	if scopeId == "" {
		return actor, nil
	}
	actor.CanApprove = canApprove(res.ACL(), res.UserId, scopeId)
	return actor, nil
}

// canApprove reports whether acl explicitly authorizes the approve action on
// access requests stored in scopeId. perms.ACL never lets type=* or actions=*
// satisfy it.
func canApprove(acl perms.ACL, userId, scopeId string) bool {
	return acl.Allowed(
		perms.Resource{ScopeId: scopeId, Type: resource.AccessRequest},
		action.Approve,
		userId,
	).Authorized
}
