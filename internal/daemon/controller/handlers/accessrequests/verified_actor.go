// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package accessrequests

import (
	"context"
	"errors"

	"github.com/hashicorp/boundary/internal/accessrequest"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
)

// errUnauthenticated is the fixed reason for every resolver failure. It never
// carries the underlying error, a grant string or a token.
var errUnauthenticated = errors.New("accessrequests: unauthenticated")

// anonymousUserId is the anonymous user; it is never an access request actor.
const anonymousUserId = "u_anon"

// anyRequestId is a placeholder id used to evaluate the approve action against
// grants of the form ids=*;type=access-request;actions=approve (the grant
// parser does not accept ids of a specific access request, so ids=* is the only
// form). The domain still re-checks the decision.
const anyRequestId = "ar_0000000000"

// verifyFunc matches auth.Verify; a field so tests can use a fake verifier.
type verifyFunc func(ctx context.Context, typ resource.Type, opt ...auth.Option) auth.VerifyResults

// VerifiedActorResolver is the ActorResolver backed by auth.Verify. Actor.Id
// comes from the verified result and Actor.CanApprove is true only when the
// verified ACL authorizes the explicit approve action on the given (stored)
// scope. Wildcard type or action grants never authorize it because perms.ACL
// excludes access requests from wildcard grants. Self-approval stays refused
// by the domain. It is not registered in the controller in this slice.
type VerifiedActorResolver struct {
	verify verifyFunc
	// aclOf extracts the verified ACL; a field so tests can supply grants.
	aclOf func(res *auth.VerifyResults) perms.ACL
}

var _ ActorResolver = (*VerifiedActorResolver)(nil)

// NewVerifiedActorResolver returns a resolver backed by auth.Verify.
func NewVerifiedActorResolver() *VerifiedActorResolver {
	return &VerifiedActorResolver{verify: auth.Verify, aclOf: (*auth.VerifyResults).ACL}
}

// Actor authenticates the request. An empty scopeId authenticates only.
// Anonymous and recovery-token callers are refused; every failure returns
// errUnauthenticated.
func (r *VerifiedActorResolver) Actor(ctx context.Context, scopeId string) (accessrequest.Actor, error) {
	if r == nil || r.verify == nil {
		return accessrequest.Actor{}, errUnauthenticated
	}
	// Ask for list recursively from global to load the user's grants; a
	// Forbidden result for an identified user just means no access request
	// grant, so the ACL allows nothing.
	res := r.verify(ctx, resource.AccessRequest,
		auth.WithScopeId(scope.Global.String()),
		auth.WithAction(action.List),
		auth.WithRecursive(true),
		auth.WithAnonymousUserNotAllowed(true),
		auth.WithRecoveryTokenNotAllowed(true),
	)
	if res.Error != nil && !errors.Is(res.Error, handlers.ForbiddenError()) {
		return accessrequest.Actor{}, errUnauthenticated
	}
	if res.UserId == "" || res.UserId == anonymousUserId {
		return accessrequest.Actor{}, errUnauthenticated
	}
	actor := accessrequest.Actor{Id: res.UserId}
	if scopeId == "" {
		return actor, nil
	}
	aclOf := r.aclOf
	if aclOf == nil {
		aclOf = (*auth.VerifyResults).ACL
	}
	acl := aclOf(&res)
	actor.CanApprove = acl.Allowed(perms.Resource{
		ScopeId: scopeId,
		Id:      anyRequestId,
		Type:    resource.AccessRequest,
	}, action.Approve, res.UserId).Authorized
	return actor, nil
}
