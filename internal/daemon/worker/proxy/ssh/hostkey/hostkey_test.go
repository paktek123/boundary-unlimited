// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package hostkey

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestGenerate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a, err := Generate(ctx)
	require.NoError(t, err)
	b, err := Generate(ctx)
	require.NoError(t, err)

	assert.NotEqual(t, a.AuthorizedKey, b.AuthorizedKey)
	assert.NotEqual(t, a.Fingerprint, b.Fingerprint)
	assert.Equal(t, ssh.KeyAlgoED25519, a.Signer.PublicKey().Type())

	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(a.AuthorizedKey))
	require.NoError(t, err)
	assert.Equal(t, a.Fingerprint, ssh.FingerprintSHA256(pub))
	assert.Equal(t, pub.Marshal(), a.Signer.PublicKey().Marshal())
}

func TestPrivateKeyRedaction(t *testing.T) {
	t.Parallel()
	k, err := Generate(context.Background())
	require.NoError(t, err)

	raw := []byte(k.Private.key)
	seed := k.Private.key.Seed()
	needles := []string{
		string(raw), string(seed),
		base64.StdEncoding.EncodeToString(raw),
		base64.StdEncoding.EncodeToString(seed),
		fmt.Sprintf("%x", raw), fmt.Sprintf("%x", seed),
	}

	js, err := json.Marshal(struct {
		K PrivateKey
		P *PrivateKey
	}{k.Private, &k.Private})
	require.NoError(t, err)

	outputs := []string{
		fmt.Sprintf("%v", k.Private), fmt.Sprintf("%+v", k.Private),
		fmt.Sprintf("%#v", k.Private), fmt.Sprintf("%s", k.Private),
		fmt.Sprintf("%x", k.Private), fmt.Sprintf("%d", k.Private),
		fmt.Sprintf("%v", &k.Private), fmt.Sprintf("%+v", k), fmt.Sprintf("%#v", *k),
		string(js),
		fmt.Errorf("failed: %w", fmt.Errorf("%v", k.Private)).Error(),
	}
	for _, out := range outputs {
		for _, n := range needles {
			assert.NotContains(t, out, n)
		}
	}
	assert.Equal(t, redacted, k.Private.String())
	assert.Equal(t, redacted, k.Private.GoString())
}
