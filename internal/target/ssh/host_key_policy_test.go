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
		"duplicate cas":  {cas: func() []string { k := testKey(t); return []string{k, k} }()},
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
	tgt.HostKeyPolicyKeys = "ssh-ed25519 CANARYKEYMATERIAL"
	err := tgt.VetForWrite(ctx, nil, db.CreateOp)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "CANARYKEYMATERIAL")
}

// A stored value that is inconsistent in any way is an error, never an empty or
// partial policy.
func TestHostKeyPolicyInvalidStoredValue(t *testing.T) {
	ctx := context.Background()
	k, other := testKey(t), testKey(t)
	var tooMany []string
	for i := 0; i < 17; i++ {
		tooMany = append(tooMany, testKey(t))
	}
	for name, stored := range map[string]string{
		"malformed":        "ssh-ed25519 CANARYKEYMATERIAL",
		"one bad of two":   k + "\nnot a key",
		"empty entry":      k + "\n\n" + other,
		"trailing newline": k + "\n",
		"only newline":     "\n",
		"carriage return":  k + "\r\n" + other,
		"duplicate":        k + "\n" + k,
		"seventeen":        strings.Join(tooMany, "\n"),
		"old array form":   "{}",
	} {
		t.Run(name, func(t *testing.T) {
			for _, asCa := range []bool{false, true} {
				tgt := &Target{Target: &store.Target{}}
				if asCa {
					tgt.SetStoredHostKeyPolicy("", stored)
				} else {
					tgt.SetStoredHostKeyPolicy(stored, "")
				}
				keys, cas, err := tgt.HostKeyPolicy(ctx)
				require.Error(t, err)
				assert.Nil(t, keys)
				assert.Nil(t, cas)
				assert.NotContains(t, err.Error(), "CANARYKEYMATERIAL")
			}
		})
	}
}

func TestSetHostKeyPolicyNewlinesAndTrim(t *testing.T) {
	ctx := context.Background()
	k, other := testKey(t), testKey(t)
	tgt := &Target{Target: &store.Target{}}
	// an embedded newline cannot be written
	require.Error(t, tgt.SetHostKeyPolicy(ctx, []string{k + "\n" + other}, nil))
	require.Error(t, tgt.SetHostKeyPolicy(ctx, nil, []string{k + "\n" + other}))
	assert.Empty(t, tgt.GetHostKeyPolicyKeys())
	assert.Empty(t, tgt.GetHostKeyPolicyCas())
	// surrounding whitespace is normalised away
	require.NoError(t, tgt.SetHostKeyPolicy(ctx, []string{"  " + k + "\n"}, []string{other + "\r\n"}))
	keys, cas, err := tgt.HostKeyPolicy(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{k}, keys)
	assert.Equal(t, []string{other}, cas)
}
