// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package hostkeypolicy

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func authKey(t *testing.T, pub any) string {
	t.Helper()
	k, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

func rsaKey(t *testing.T, bits int) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	return authKey(t, &k.PublicKey)
}

func ecKey(t *testing.T, c elliptic.Curve) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	require.NoError(t, err)
	return authKey(t, &k.PublicKey)
}

func edKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return authKey(t, pub)
}

func TestValidateHostKeys(t *testing.T) {
	t.Parallel()
	ed := edKey(t)
	rsa3072 := rsaKey(t, 3072)
	rsa2048 := rsaKey(t, 2048)

	many := make([]string, MaxHostKeys+1)
	for i := range many {
		many[i] = edKey(t)
	}

	tests := []struct {
		name    string
		keys    []string
		wantErr string
	}{
		{"nil", nil, ""},
		{"ed25519", []string{ed}, ""},
		{"ed25519 with comment", []string{ed + " host.example.com"}, ""},
		{"ecdsa p256", []string{ecKey(t, elliptic.P256())}, ""},
		{"ecdsa p384", []string{ecKey(t, elliptic.P384())}, ""},
		{"ecdsa p521", []string{ecKey(t, elliptic.P521())}, ""},
		{"rsa 3072", []string{rsa3072}, ""},
		{"max keys", many[:MaxHostKeys], ""},
		{"too many keys", many, "too many host keys"},
		{"rsa 2048", []string{rsa2048}, "smaller than"},
		{"empty entry", []string{""}, "empty"},
		{"blank entry", []string{"   "}, "empty"},
		{"duplicate", []string{ed, ed}, "duplicate"},
		{"duplicate differing comment", []string{ed, ed + " other"}, "duplicate"},
		{"options", []string{`command="id" ` + ed}, "options"},
		{"control char in comment", []string{ed + " bad\x01comment"}, "control characters"},
		{"newline in entry", []string{ed + " a\nb"}, "control characters"},
		{"wildcard", []string{"*.example.com " + ed}, "wildcards"},
		{"garbage", []string{"not a key"}, "not a valid public key"},
		{"oversize", []string{ed + " " + strings.Repeat("a", MaxEntryLength)}, "exceeds"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateHostKeys(tt.keys)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestValidateHostKeys_DSARejected(t *testing.T) {
	t.Parallel()
	var p dsa.PrivateKey
	require.NoError(t, dsa.GenerateParameters(&p.Parameters, rand.Reader, dsa.L1024N160))
	require.NoError(t, dsa.GenerateKey(&p, rand.Reader))
	blob := ssh.Marshal(struct {
		Name       string
		P, Q, G, Y *big.Int
	}{"ssh-dss", p.P, p.Q, p.G, p.Y})
	line := "ssh-dss " + base64.StdEncoding.EncodeToString(blob)
	err := ValidateHostKeys([]string{line})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key type")
	assert.NotContains(t, err.Error(), line[8:40])
}

func TestValidateHostCA(t *testing.T) {
	t.Parallel()
	assert.NoError(t, ValidateHostCA(edKey(t)))
	assert.NoError(t, ValidateHostCA(rsaKey(t, 3072)))
	assert.Error(t, ValidateHostCA(""))
	assert.Error(t, ValidateHostCA(rsaKey(t, 2048)))
	assert.Error(t, ValidateHostCA(`cert-authority `+edKey(t)))
	assert.Error(t, ValidateHostCA(edKey(t)+"\n"+edKey(t)))
}

func TestErrorsNeverEchoKeyMaterial(t *testing.T) {
	t.Parallel()
	k := rsaKey(t, 2048)
	blob := strings.Fields(k)[1]
	err := ValidateHostKeys([]string{k})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), blob[:40])
	assert.Contains(t, err.Error(), "SHA256:")
	err = ValidateHostCA(`x="y" ` + k)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), blob[:40])
}

func TestHostKeyAlgorithms(t *testing.T) {
	t.Parallel()
	assert.NotContains(t, HostKeyAlgorithms, ssh.KeyAlgoRSA)
	assert.NotEmpty(t, HostKeyAlgorithms)
}
