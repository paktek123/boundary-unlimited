// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package runbooks

import (
	"context"
	"errors"

	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
)

// errUnauthenticated is the fixed reason returned for every resolver failure.
// It never carries the underlying error, a grant string or a token so that
// nothing sensitive reaches logs or responses.
var errUnauthenticated = errors.New("runbooks: unauthenticated")

// anonymousUserId is the id of the anonymous user; it is never a runbook caller.
const anonymousUserId = "u_anon"

// verifyFunc matches auth.Verify. It is a field so tests can substitute a fake
// verifier without a database.
type verifyFunc func(ctx context.Context, typ resource.Type, opt ...auth.Option) auth.VerifyResults

// VerifiedCallerResolver is the controller's CallerResolver. It authenticates
// the request through auth.Verify and returns the verified ACL. Grants are
// never hand-built from GrantsForUser. Per-RPC decisions (Get/Delete on the
// stored scope, List on one explicit scope) are made by Service with
// Caller.ACL, and wildcard type or action grants never satisfy them because
// perms.ACL excludes runbooks from wildcard type grants.
//
// The resolver is not registered in the controller in this slice (see #320).
type VerifiedCallerResolver struct {
	verify verifyFunc
}

var _ CallerResolver = (*VerifiedCallerResolver)(nil)

// NewVerifiedCallerResolver returns a resolver backed by auth.Verify.
func NewVerifiedCallerResolver() *VerifiedCallerResolver {
	return &VerifiedCallerResolver{verify: auth.Verify}
}

// Caller authenticates the request context. Anonymous and recovery-token
// callers are refused, and every failure returns errUnauthenticated.
func (r *VerifiedCallerResolver) Caller(ctx context.Context) (Caller, error) {
	if r == nil || r.verify == nil {
		return Caller{}, errUnauthenticated
	}
	res := r.verify(ctx, resource.Runbook,
		auth.WithScopeId(scope.Global.String()),
		auth.WithAnonymousUserNotAllowed(true),
		auth.WithRecoveryTokenNotAllowed(true),
	)
	if res.Error != nil || res.UserId == "" || res.UserId == anonymousUserId {
		return Caller{}, errUnauthenticated
	}
	return Caller{UserId: res.UserId, ACL: res.ACL()}, nil
}
