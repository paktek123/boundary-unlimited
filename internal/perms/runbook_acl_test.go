// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package perms

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runbookACL(t *testing.T, scopeId string, grants ...string) ACL {
	t.Helper()
	var parsed []Grant
	for _, g := range grants {
		grant, err := Parse(context.Background(), GrantTuple{RoleScopeId: scopeId, GrantScopeId: scopeId, Grant: g})
		require.NoError(t, err, g)
		parsed = append(parsed, grant)
	}
	return NewACL(parsed...)
}

func TestRunbookGrantParsing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, a := range []string{"create", "read", "update", "delete", "list", "*", "read,execute"} {
		g, err := Parse(ctx, GrantTuple{RoleScopeId: "o_1234567890", GrantScopeId: "o_1234567890", Grant: "ids=*;type=runbook;actions=" + a})
		require.NoError(t, err, a)
		assert.Equal(t, resource.Runbook, g.Type())
	}
	_, err := Parse(ctx, GrantTuple{RoleScopeId: "o_1234567890", GrantScopeId: "o_1234567890", Grant: "ids=*;type=runbook;actions=frobnicate"})
	require.Error(t, err)

	// A grant that only names execute would authorize nothing, so it is
	// rejected at parse time (fail closed until the executor exists).
	_, err = Parse(ctx, GrantTuple{RoleScopeId: "o_1234567890", GrantScopeId: "o_1234567890", Grant: "ids=*;type=runbook;actions=execute"})
	require.Error(t, err)
	assert.Equal(t, "runbook", resource.Runbook.String())
	assert.Equal(t, "runbooks", resource.Runbook.PluralString())
}

func TestRunbookWildcardDoesNotGrantRunbooks(t *testing.T) {
	t.Parallel()
	const scopeId = "o_1234567890"
	acl := runbookACL(t, scopeId,
		"ids=*;type=*;actions=*",
		"ids=*;type=*;actions=read,update,delete,create,list",
	)
	for _, a := range []action.Type{action.Create, action.List, action.Read, action.Update, action.Delete, action.Execute} {
		res := acl.Allowed(Resource{ScopeId: scopeId, Type: resource.Runbook}, a, "u_1234567890")
		assert.False(t, res.Authorized, "wildcard grant must not authorize %s on runbooks", a)
		res = acl.Allowed(Resource{ScopeId: scopeId, Id: "rb_1234567890", Type: resource.Runbook}, a, "u_1234567890")
		assert.False(t, res.Authorized, "wildcard grant must not authorize %s on a runbook id", a)
	}
	// Wildcard grants keep working for other types.
	res := acl.Allowed(Resource{ScopeId: scopeId, Id: "tssh_1234567890", Type: resource.Target}, action.Read, "u_1234567890")
	assert.True(t, res.Authorized)
}

func TestRunbookExplicitGrantAndExecuteDenied(t *testing.T) {
	t.Parallel()
	const scopeId = "o_1234567890"
	acl := runbookACL(t, scopeId,
		"type=runbook;actions=create,list",
		"ids=*;type=runbook;actions=read,update,delete",
	)
	for _, a := range []action.Type{action.Create, action.List} {
		res := acl.Allowed(Resource{ScopeId: scopeId, Type: resource.Runbook}, a, "u_1234567890")
		assert.True(t, res.Authorized, a.String())
	}
	for _, a := range []action.Type{action.Read, action.Update, action.Delete} {
		res := acl.Allowed(Resource{ScopeId: scopeId, Id: "rb_1234567890", Type: resource.Runbook}, a, "u_1234567890")
		assert.True(t, res.Authorized, a.String())
	}

	// execute is defined but never authorized until the executor exists, even
	// when named explicitly or covered by an explicit type=runbook;actions=*.
	acl = runbookACL(t, scopeId,
		"ids=*;type=runbook;actions=read,execute",
		"ids=*;type=runbook;actions=*",
	)
	res := acl.Allowed(Resource{ScopeId: scopeId, Id: "rb_1234567890", Type: resource.Runbook}, action.Execute, "u_1234567890")
	assert.False(t, res.Authorized)
	res = acl.Allowed(Resource{ScopeId: scopeId, Id: "rb_1234567890", Type: resource.Runbook}, action.Read, "u_1234567890")
	assert.True(t, res.Authorized)
}
