// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package perms

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccessRequestGrantParsing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, a := range []string{"create", "list", "read", "cancel", "approve", "deny", "revoke", "read,approve"} {
		g, err := Parse(ctx, GrantTuple{RoleScopeId: "o_1234567890", GrantScopeId: "o_1234567890", Grant: "ids=*;type=access-request;actions=" + a})
		require.NoError(t, err, a)
		assert.Equal(t, resource.AccessRequest, g.Type())
	}
	// only the hyphenated form is accepted
	_, err := Parse(ctx, GrantTuple{RoleScopeId: "o_1234567890", GrantScopeId: "o_1234567890", Grant: "ids=*;type=access_request;actions=read"})
	require.Error(t, err)
	_, err = Parse(ctx, GrantTuple{RoleScopeId: "o_1234567890", GrantScopeId: "o_1234567890", Grant: "ids=*;type=access-request;actions=frobnicate"})
	require.Error(t, err)
	assert.Equal(t, "access-request", resource.AccessRequest.String())
	assert.Equal(t, "access-requests", resource.AccessRequest.PluralString())
}

func TestAccessRequestWildcardDoesNotGrantAccessRequests(t *testing.T) {
	t.Parallel()
	const scopeId = "o_1234567890"
	acl := runbookACL(t, scopeId,
		"ids=*;type=*;actions=*",
		"ids=*;type=*;actions=read,create,list,cancel",
	)
	all := []action.Type{action.Create, action.List, action.Read, action.Cancel, action.Approve, action.Deny, action.Revoke}
	for _, a := range all {
		res := acl.Allowed(Resource{ScopeId: scopeId, Type: resource.AccessRequest}, a, "u_1234567890")
		assert.False(t, res.Authorized, "wildcard grant must not authorize %s on access requests", a)
		res = acl.Allowed(Resource{ScopeId: scopeId, Id: "ar_1234567890", Type: resource.AccessRequest}, a, "u_1234567890")
		assert.False(t, res.Authorized, "wildcard grant must not authorize %s on an access request id", a)
	}
	// Wildcard grants keep working for other types.
	res := acl.Allowed(Resource{ScopeId: scopeId, Id: "tssh_1234567890", Type: resource.Target}, action.Read, "u_1234567890")
	assert.True(t, res.Authorized)
}

func TestAccessRequestExplicitGrants(t *testing.T) {
	t.Parallel()
	const scopeId = "o_1234567890"
	acl := runbookACL(t, scopeId,
		"type=access-request;actions=create,list",
		"ids=*;type=access-request;actions=read,cancel",
	)
	for _, a := range []action.Type{action.Create, action.List} {
		assert.True(t, acl.Allowed(Resource{ScopeId: scopeId, Type: resource.AccessRequest}, a, "u_1234567890").Authorized, a.String())
	}
	for _, a := range []action.Type{action.Read, action.Cancel} {
		assert.True(t, acl.Allowed(Resource{ScopeId: scopeId, Id: "ar_1234567890", Type: resource.AccessRequest}, a, "u_1234567890").Authorized, a.String())
	}
	// approve is not implied by the other actions.
	for _, a := range []action.Type{action.Approve, action.Deny, action.Revoke} {
		assert.False(t, acl.Allowed(Resource{ScopeId: scopeId, Id: "ar_1234567890", Type: resource.AccessRequest}, a, "u_1234567890").Authorized, a.String())
	}
	// an explicit grant of approve authorizes it.
	acl = runbookACL(t, scopeId, "ids=*;type=access-request;actions=approve")
	assert.True(t, acl.Allowed(Resource{ScopeId: scopeId, Id: "ar_1234567890", Type: resource.AccessRequest}, action.Approve, "u_1234567890").Authorized)
}

func TestAccessRequestActionsWildcardAuthorizesNothing(t *testing.T) {
	t.Parallel()
	const scopeId = "o_1234567890"
	all := []action.Type{action.Create, action.List, action.Read, action.Cancel, action.Approve, action.Deny, action.Revoke}
	for _, grants := range [][]string{
		{"ids=*;type=access-request;actions=*"},
		{"ids=*;type=*;actions=*", "ids=*;type=access-request;actions=*"},
	} {
		acl := runbookACL(t, scopeId, grants...)
		for _, a := range all {
			assert.False(t, acl.Allowed(Resource{ScopeId: scopeId, Type: resource.AccessRequest}, a, "u_1234567890").Authorized, "%v %s collection", grants, a)
			assert.False(t, acl.Allowed(Resource{ScopeId: scopeId, Id: "ar_1234567890", Type: resource.AccessRequest}, a, "u_1234567890").Authorized, "%v %s id", grants, a)
		}
		perms := acl.ListPermissions(map[string]*scopes.ScopeInfo{scopeId: nil}, resource.AccessRequest, action.AccessRequestIdActions, "u_1234567890")
		assert.Empty(t, perms, "%v", grants)
	}

}
