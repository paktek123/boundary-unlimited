// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package accessrequests

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
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
