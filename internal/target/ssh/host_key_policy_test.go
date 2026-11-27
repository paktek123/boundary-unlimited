// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/target/ssh/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
)

func testKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	spk, err := gossh.NewPublicKey(pub)
	require.NoError(t, err)
	return strings.TrimSpace(string(gossh.MarshalAuthorizedKey(spk)))
}

func TestHostKeyPolicyRoundTrip(t *testing.T) {
	ctx := context.Background()
	tgt := &Target{Target: &store.Target{}}
	keys, cas := []string{testKey(t), testKey(t)}, []string{testKey(t)}
	require.NoError(t, tgt.SetHostKeyPolicy(ctx, keys, cas))
	gotK, gotC, err := tgt.HostKeyPolicy(ctx)
	require.NoError(t, err)
	assert.Equal(t, keys, gotK)
	assert.Equal(t, cas, gotC)

	// replaced as a whole, and clearing works
	require.NoError(t, tgt.SetHostKeyPolicy(ctx, nil, nil))
	gotK, gotC, err = tgt.HostKeyPolicy(ctx)
	require.NoError(t, err)
	assert.Empty(t, gotK)
	assert.Empty(t, gotC)
}

func TestSetHostKeyPolicyRefusals(t *testing.T) {
	ctx := context.Background()
	const canary = "CANARYKEYMATERIAL"
	tooMany := func(t *testing.T) []string {
		var l []string
		for i := 0; i < 17; i++ {
			l = append(l, testKey(t))
		}
		return l
	}
	tests := map[string]struct{ keys, cas []string }{
		"malformed key":  {keys: []string{"ssh-ed25519 " + canary}},
		"wildcard key":   {keys: []string{"* " + testKey(t)}},
		"too many keys":  {keys: tooMany(t)},
		"malformed ca":   {cas: []string{"ssh-ed25519 " + canary}},
		"too many cas":   {cas: tooMany(t)},
		"duplicate keys": {keys: func() []string { k := testKey(t); return []string{k, k} }()},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			tgt := &Target{Target: &store.Target{}}
			before := testKey(t)
			require.NoError(t, tgt.SetHostKeyPolicy(ctx, []string{before}, nil))
			err := tgt.SetHostKeyPolicy(ctx, tc.keys, tc.cas)
			require.Error(t, err)
			assert.NotContains(t, err.Error(), canary)
			// the target is unchanged by a refused update
			k, _, err := tgt.HostKeyPolicy(ctx)
			require.NoError(t, err)
			assert.Equal(t, []string{before}, k)
		})
	}
}

func TestVetForWriteRefusesUnvalidatedPolicy(t *testing.T) {
	ctx := context.Background()
	tgt := &Target{Target: &store.Target{}}
	tgt.PublicId, tgt.ProjectId, tgt.Name = "tssh_1234567890", "p_1234567890", "n"
	require.NoError(t, tgt.VetForWrite(ctx, nil, db.CreateOp))
	tgt.Target.HostKeyPolicyKeys = "{\"ssh-ed25519 CANARYKEYMATERIAL\"}"
	err := tgt.VetForWrite(ctx, nil, db.CreateOp)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "CANARYKEYMATERIAL")
	tgt.Target.HostKeyPolicyKeys = "not an array"
	require.Error(t, tgt.VetForWrite(ctx, nil, db.CreateOp))
}
