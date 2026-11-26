// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package accessrequests

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fake(res auth.VerifyResults) verifyFunc {
	return func(context.Context, resource.Type, ...auth.Option) auth.VerifyResults { return res }
}

func TestVerifiedActorResolver_Denials(t *testing.T) {
	canary := "canary-secret-grant-string"
	cases := map[string]auth.VerifyResults{
		"verify error":    {Error: errors.New(canary)},
		"anonymous":       {UserId: "u_anon"},
		"empty user":      {},
		"forbidden/no id": {Error: handlers.ForbiddenError()},
		"unauthenticated": {UserId: "u_1", Error: handlers.UnauthenticatedError()},
	}
	for name, res := range cases {
		for _, scopeId := range []string{"", "o_1234567890"} {
			t.Run(name+"/"+scopeId, func(t *testing.T) {
				r := &VerifiedActorResolver{verify: fake(res)}
				a, err := r.Actor(context.Background(), scopeId)
				require.Error(t, err)
				assert.Equal(t, errUnauthenticated, err)
				assert.NotContains(t, err.Error(), canary)
				assert.Empty(t, a.Id)
				assert.False(t, a.CanApprove)
			})
		}
	}
	var nilR *VerifiedActorResolver
	_, err := nilR.Actor(context.Background(), "")
	assert.Equal(t, errUnauthenticated, err)
	_, err = (&VerifiedActorResolver{}).Actor(context.Background(), "")
	assert.Equal(t, errUnauthenticated, err)
}

func TestVerifiedActorResolver_Identity(t *testing.T) {
	r := &VerifiedActorResolver{verify: fake(auth.VerifyResults{UserId: "u_1"})}
	a, err := r.Actor(context.Background(), "")
	require.NoError(t, err)
	assert.Equal(t, "u_1", a.Id)
	assert.False(t, a.CanApprove)

	// An identified user without a grant (ACL empty) cannot approve in a scope.
	a, err = r.Actor(context.Background(), "o_1234567890")
	require.NoError(t, err)
	assert.Equal(t, "u_1", a.Id)
	assert.False(t, a.CanApprove)

	r = &VerifiedActorResolver{verify: fake(auth.VerifyResults{UserId: "u_1", Error: handlers.ForbiddenError()})}
	a, err = r.Actor(context.Background(), "o_1234567890")
	require.NoError(t, err)
	assert.Equal(t, "u_1", a.Id)
	assert.False(t, a.CanApprove)
}

func aclWith(t *testing.T, grants map[string][]string) func(*auth.VerifyResults) perms.ACL {
	t.Helper()
	var parsed []perms.Grant
	for scopeId, gs := range grants {
		for _, g := range gs {
			pg, err := perms.Parse(context.Background(), perms.GrantTuple{RoleScopeId: scopeId, GrantScopeId: scopeId, Grant: g})
			require.NoError(t, err, g)
			parsed = append(parsed, pg)
		}
	}
	acl := perms.NewACL(parsed...)
	return func(*auth.VerifyResults) perms.ACL { return acl }
}

func TestVerifiedActorResolver_CanApprove(t *testing.T) {
	const a, b = "o_1234567890", "o_0987654321"
	cases := []struct {
		name   string
		grants map[string][]string
		scope  string
		want   bool
	}{
		{"explicit approve in the scope", map[string][]string{a: {"ids=*;type=access-request;actions=approve"}}, a, true},
		{"approve in scope A does not allow scope B", map[string][]string{a: {"ids=*;type=access-request;actions=approve"}}, b, false},
		{"read-only does not approve", map[string][]string{a: {"ids=*;type=access-request;actions=read,list"}}, a, false},
		{"wildcard type and action do not approve", map[string][]string{a: {"ids=*;type=*;actions=*"}}, a, false},
		{"access-request actions=* does not approve", map[string][]string{a: {"ids=*;type=access-request;actions=*"}}, a, false},
		{"no grants", nil, a, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &VerifiedActorResolver{
				verify: fake(auth.VerifyResults{UserId: "u_1234567890"}),
				aclOf:  aclWith(t, tc.grants),
			}
			actor, err := r.Actor(context.Background(), tc.scope)
			require.NoError(t, err)
			assert.Equal(t, "u_1234567890", actor.Id)
			assert.Equal(t, tc.want, actor.CanApprove)
			// Authenticate-only never grants approval.
			actor, err = r.Actor(context.Background(), "")
			require.NoError(t, err)
			assert.False(t, actor.CanApprove)
		})
	}
}
