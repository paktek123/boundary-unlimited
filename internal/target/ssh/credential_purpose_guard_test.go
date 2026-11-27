// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package ssh

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/store"
	"github.com/stretchr/testify/assert"
)

// TestVetCredentialSourcesBrokeredOnly guards the enforcement-first rule of
// #5: no injected purpose is accepted on an ssh target until the worker
// injects credentials end to end.
func TestVetCredentialSourcesBrokeredOnly(t *testing.T) {
	ctx := context.Background()
	h := targetHooks{}
	lib := func(p credential.Purpose) []*target.CredentialLibrary {
		return []*target.CredentialLibrary{{CredentialLibrary: &store.CredentialLibrary{CredentialPurpose: string(p)}}}
	}
	cred := func(p credential.Purpose) []*target.StaticCredential {
		return []*target.StaticCredential{{StaticCredential: &store.StaticCredential{CredentialPurpose: string(p)}}}
	}
	assert.NoError(t, h.VetCredentialSources(ctx, lib(credential.BrokeredPurpose), cred(credential.BrokeredPurpose)))
	for _, p := range []credential.Purpose{credential.InjectedApplicationPurpose, credential.Purpose("injected"), credential.Purpose("")} {
		assert.Error(t, h.VetCredentialSources(ctx, lib(p), nil), "library purpose %q", p)
		assert.Error(t, h.VetCredentialSources(ctx, nil, cred(p)), "static purpose %q", p)
	}
}
