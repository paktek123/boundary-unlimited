// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package injectauth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const (
	secretPassword   = "SENTINEL-password-7f3a"
	secretPassphrase = "SENTINEL-passphrase-91bc"
)

func pemKey(t *testing.T, priv any, passphrase string) []byte {
	t.Helper()
	var blk *pem.Block
	var err error
	if passphrase != "" {
		blk, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	} else {
		blk, err = ssh.MarshalPrivateKey(priv, "")
	}
	require.NoError(t, err)
	return pem.EncodeToMemory(blk)
}

func TestAuthMethods(t *testing.T) {
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	edPEM := pemKey(t, ed, "")
	edEnc := pemKey(t, ed, secretPassphrase)

	// legacy PKCS#1 PEM
	legacy := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsa2048)})

	tests := []struct {
		name        string
		in          Input
		wantErr     error
		wantMethods int
	}{
		{"no username", Input{Password: "p"}, ErrUsernameRequired, 0},
		{"no credential", Input{Username: "u"}, ErrNoCredential, 0},
		{"password only", Input{Username: "u", Password: secretPassword}, nil, 1},
		{"ed25519", Input{Username: "u", PrivateKey: edPEM}, nil, 1},
		{"rsa 2048", Input{Username: "u", PrivateKey: pemKey(t, rsa2048, "")}, nil, 1},
		{"rsa 2048 legacy pem", Input{Username: "u", PrivateKey: legacy}, nil, 1},
		{"ecdsa", Input{Username: "u", PrivateKey: pemKey(t, ec, "")}, nil, 1},
		{"rsa 1024 rejected", Input{Username: "u", PrivateKey: pemKey(t, rsa1024, "")}, ErrBadPrivateKey, 0},
		{"encrypted with passphrase", Input{Username: "u", PrivateKey: edEnc, Passphrase: []byte(secretPassphrase)}, nil, 1},
		{"encrypted without passphrase", Input{Username: "u", PrivateKey: edEnc}, ErrBadPrivateKey, 0},
		{"encrypted wrong passphrase", Input{Username: "u", PrivateKey: edEnc, Passphrase: []byte("wrong")}, ErrBadPrivateKey, 0},
		{"garbage key", Input{Username: "u", PrivateKey: []byte("not a key")}, ErrBadPrivateKey, 0},
		{"key and password", Input{Username: "u", PrivateKey: edPEM, Password: secretPassword}, nil, 2},
		{"bad key and good password is still an error", Input{Username: "u", PrivateKey: []byte("x"), Password: secretPassword}, ErrBadPrivateKey, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			user, methods, err := AuthMethods(tc.in)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				assert.Empty(t, user)
				assert.Nil(t, methods)
				for _, s := range []string{secretPassword, secretPassphrase, "PRIVATE KEY", string(tc.in.PrivateKey)} {
					if s != "" {
						assert.False(t, strings.Contains(err.Error(), s), "error leaks secret material: %v", err)
					}
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.in.Username, user)
			assert.Len(t, methods, tc.wantMethods)
		})
	}
}

func TestKeyBeforePassword(t *testing.T) {
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, methods, err := AuthMethods(Input{Username: "u", Password: "p", PrivateKey: pemKey(t, ed, "")})
	require.NoError(t, err)
	require.Len(t, methods, 2)
	// ssh.Password and ssh.PublicKeys return different concrete types.
	assert.NotEqual(t, typeName(ssh.Password("p")), typeName(methods[0]))
	assert.Equal(t, typeName(ssh.Password("p")), typeName(methods[1]))
}

func typeName(m ssh.AuthMethod) string {
	return fmt.Sprintf("%T", m)
}
