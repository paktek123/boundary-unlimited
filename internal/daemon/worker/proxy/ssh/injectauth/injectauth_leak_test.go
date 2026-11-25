// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package injectauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuthMethods_ErrorsNeverLeakSecrets asserts that every failure path of
// AuthMethods returns an error that carries none of the secret inputs
// (password, passphrase, key bytes). Refs #7.
func TestAuthMethods_ErrorsNeverLeakSecrets(t *testing.T) {
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	enc := pemKey(t, ed, secretPassphrase)
	plain := pemKey(t, ed, "")

	const secretPassword = "SENTINEL-password-77aa"
	garbage := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nSENTINEL-garbage-5521\n-----END OPENSSH PRIVATE KEY-----\n")

	tests := []struct {
		name string
		in   Input
	}{
		{"encrypted key, no passphrase", Input{Username: "u", PrivateKey: enc}},
		{"encrypted key, wrong passphrase", Input{Username: "u", PrivateKey: enc, Passphrase: []byte(secretPassword)}},
		{"garbage key", Input{Username: "u", PrivateKey: garbage, Passphrase: []byte(secretPassphrase)}},
		{"certificate without key", Input{Username: "u", Password: secretPassword, Certificate: []byte("SENTINEL-cert-1")}},
		{"garbage certificate", Input{Username: "u", PrivateKey: plain, Certificate: []byte("SENTINEL-cert-2")}},
		{"no credential", Input{Username: "u"}},
	}
	secrets := []string{secretPassphrase, secretPassword, "SENTINEL-garbage-5521", "SENTINEL-cert-1", "SENTINEL-cert-2", string(plain[:40])}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, methods, err := AuthMethods(tc.in)
			require.Error(t, err)
			assert.Empty(t, methods)
			for _, s := range secrets {
				assert.False(t, strings.Contains(err.Error(), s), "error leaks %q", s[:8])
			}
		})
	}
}
