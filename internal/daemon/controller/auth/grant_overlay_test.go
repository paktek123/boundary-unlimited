// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/stretchr/testify/assert"
)

func TestSafeOverlay(t *testing.T) {
	ctx := context.Background()
	tuple := perms.GrantTuple{RoleScopeId: "p_1", GrantScopeId: "p_1", Grant: "ids=a;type=target;actions=read"}
	ok := func(context.Context, string, string) ([]perms.GrantTuple, error) {
		return []perms.GrantTuple{tuple}, nil
	}
	bad := func(context.Context, string, string) ([]perms.GrantTuple, error) {
		return []perms.GrantTuple{tuple}, errors.New("db down") // grants returned with an error must be ignored
	}
	boom := func(context.Context, string, string) ([]perms.GrantTuple, error) { panic("x") }

	assert.Equal(t, []perms.GrantTuple{tuple}, safeOverlay(ctx, ok, "u_1", "p_1"))
	assert.Empty(t, safeOverlay(ctx, bad, "u_1", "p_1"))
	assert.Empty(t, safeOverlay(ctx, boom, "u_1", "p_1"))
	assert.Empty(t, safeOverlay(ctx, nil, "u_1", "p_1"))
	assert.Empty(t, safeOverlay(ctx, ok, "", "p_1"))
	assert.Empty(t, safeOverlay(ctx, ok, "u_1", ""))

	var o options
	WithGrantOverlay(ok)(&o)
	assert.NotNil(t, o.withGrantOverlay)
	assert.Nil(t, getOpts().withGrantOverlay)
}

func TestApplyOverlay(t *testing.T) {
	ctx := context.Background()
	overlayTuple := perms.GrantTuple{RoleScopeId: "p_1", GrantScopeId: "p_1", Grant: "ids=ttcp_1;actions=authorize-session"}
	badTuple := perms.GrantTuple{RoleScopeId: "p_1", GrantScopeId: "p_1", Grant: "not a grant"}
	role := perms.GrantTuple{RoleScopeId: "p_1", GrantScopeId: "p_1", Grant: "ids=ttcp_2;actions=read"}
	roleParsed, err := perms.Parse(ctx, role, perms.WithSkipFinalValidation(true))
	assert.NoError(t, err)

	calls := 0
	mk := func(ts ...perms.GrantTuple) GrantOverlayFunc {
		return func(context.Context, string, string) ([]perms.GrantTuple, error) {
			calls++
			return ts, nil
		}
	}
	tests := []struct {
		name      string
		overlay   GrantOverlayFunc
		act       action.Type
		userId    string
		wantAdded int
		wantCalls int
	}{
		{"authorize session adds grant", mk(overlayTuple), action.AuthorizeSession, "u_1", 1, 1},
		{"other action ignored", mk(overlayTuple), action.Read, "u_1", 0, 0},
		{"anonymous user ignored", mk(overlayTuple), action.AuthorizeSession, globals.AnonymousUserId, 0, 0},
		{"empty user ignored", mk(overlayTuple), action.AuthorizeSession, "", 0, 0},
		{"unparsable tuple skipped, valid kept", mk(badTuple, overlayTuple), action.AuthorizeSession, "u_1", 1, 1},
		{"only unparsable tuple adds nothing", mk(badTuple), action.AuthorizeSession, "u_1", 0, 1},
		{"nil overlay unchanged", nil, action.AuthorizeSession, "u_1", 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls = 0
			gt, pg := applyOverlay(ctx, tt.overlay, tt.act, tt.userId, "p_1", []perms.GrantTuple{role}, []perms.Grant{roleParsed})
			assert.Len(t, gt, 1+tt.wantAdded)
			assert.Len(t, pg, 1+tt.wantAdded)
			assert.Equal(t, role, gt[0], "role grants are never replaced")
			assert.Equal(t, tt.wantCalls, calls)
		})
	}
}
