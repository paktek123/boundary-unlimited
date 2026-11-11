// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/boundary/internal/perms"
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
