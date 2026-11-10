// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package targets

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/policyhook"
	"github.com/hashicorp/boundary/internal/target/targettest"
	"github.com/hashicorp/boundary/internal/target/targettest/store"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeAuthorizer struct {
	d      policyhook.Decision
	called int
	gotReq string
	gotG   bool
	gotIn  policyhook.Input
}

func (f *fakeAuthorizer) Authorize(_ context.Context, requestID string, grantsAllowed bool, in policyhook.Input) (policyhook.Decision, policyhook.Reason) {
	f.called++
	f.gotReq, f.gotG, f.gotIn = requestID, grantsAllowed, in
	return f.d, policyhook.ReasonDeny
}

func TestExternalAuthorize(t *testing.T) {
	ctx := context.Background()
	tgt := &targettest.Target{Target: &store.Target{PublicId: "ttcp_1234567890", ProjectId: "p_1234567890"}}
	scope := &scopes.ScopeInfo{Id: "p_1234567890"}

	t.Run("no authorizer configured is a no-op", func(t *testing.T) {
		require.NoError(t, Service{}.externalAuthorize(ctx, "req", "u_1", scope, tgt, "hst_1"))
		require.NoError(t, Service{}.WithSessionAuthorizer(nil).externalAuthorize(ctx, "req", "u_1", scope, tgt, "hst_1"))
	})
	t.Run("allow continues and input is minimal", func(t *testing.T) {
		f := &fakeAuthorizer{d: policyhook.Allow}
		require.NoError(t, Service{}.WithSessionAuthorizer(f).externalAuthorize(ctx, "req", "u_1", scope, tgt, "hst_1"))
		assert.Equal(t, 1, f.called)
		assert.Equal(t, "req", f.gotReq)
		assert.True(t, f.gotG, "authorizer is only consulted after grants allowed")
		assert.Equal(t, "u_1", f.gotIn.PrincipalID)
		assert.Equal(t, "ttcp_1234567890", f.gotIn.TargetID)
		assert.Equal(t, "hst_1", f.gotIn.HostID)
		assert.Equal(t, "authorize-session", f.gotIn.Action)
		assert.Equal(t, []string{"p_1234567890"}, f.gotIn.ScopeIDs)
	})
	t.Run("deny is a generic forbidden error", func(t *testing.T) {
		f := &fakeAuthorizer{d: policyhook.Deny}
		err := Service{}.WithSessionAuthorizer(f).externalAuthorize(ctx, "req", "u_1", scope, tgt, "")
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "deny")
	})
	t.Run("zero decision is deny", func(t *testing.T) {
		f := &fakeAuthorizer{}
		require.Error(t, Service{}.WithSessionAuthorizer(f).externalAuthorize(ctx, "req", "u_1", scope, tgt, ""))
	})
	t.Run("typed nil hook fails closed", func(t *testing.T) {
		var h *policyhook.Hook
		require.Error(t, Service{}.WithSessionAuthorizer(h).externalAuthorize(ctx, "req", "u_1", scope, tgt, ""))
	})
}
