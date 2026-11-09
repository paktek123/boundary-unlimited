// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package kubernetes

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTarget_Hooks(t *testing.T) {
	ctx := context.Background()
	h := targetHooks{}

	tt, err := h.NewTarget(ctx, "p_1234567890", target.WithName("k"), target.WithDefaultPort(443),
		target.WithEnableSessionRecording(true), target.WithStorageBucketId("sb_1"))
	require.NoError(t, err)
	assert.Equal(t, Subtype, tt.GetType())
	// Nothing enforces recording for kubernetes targets, so it must never be enabled.
	assert.False(t, tt.GetEnableSessionRecording())
	assert.Empty(t, tt.GetStorageBucketId())
	tt.SetEnableSessionRecording(true)
	tt.SetStorageBucketId("sb_1")
	assert.False(t, tt.GetEnableSessionRecording())
	assert.Empty(t, tt.GetStorageBucketId())

	assert.NoError(t, h.Vet(ctx, tt))
	assert.NoError(t, tt.SetPublicId(ctx, TargetPrefix+"_abc"))
	assert.Error(t, tt.SetPublicId(ctx, "trdp_abc"))

	_, err = h.NewTarget(ctx, "")
	assert.Error(t, err)

	noPort, _ := h.NewTarget(ctx, "p_1234567890", target.WithName("k"))
	assert.Error(t, h.Vet(ctx, noPort))
	assert.Error(t, h.VetForUpdate(ctx, noPort, []string{"DefaultPort"}))
	assert.NoError(t, h.VetForUpdate(ctx, noPort, []string{"Name"}))

	cl := tt.Clone()
	cl.SetName("other")
	assert.NotEqual(t, tt.GetName(), cl.GetName())
}

func TestVetCredentialSources_BrokeredOnly(t *testing.T) {
	ctx := context.Background()
	h := targetHooks{}
	lib := func(p credential.Purpose) *target.CredentialLibrary {
		return &target.CredentialLibrary{CredentialLibrary: &store.CredentialLibrary{CredentialPurpose: string(p)}}
	}
	assert.NoError(t, h.VetCredentialSources(ctx, []*target.CredentialLibrary{lib(credential.BrokeredPurpose)}, nil))
	assert.Error(t, h.VetCredentialSources(ctx, []*target.CredentialLibrary{lib(credential.InjectedApplicationPurpose)}, nil))
}
