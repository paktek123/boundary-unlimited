// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package hostkey

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/target/ssh/hostkeypolicy"
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

func edKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return authKey(t, pub)
}

func ecKey(t *testing.T, c elliptic.Curve) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	require.NoError(t, err)
	return authKey(t, &k.PublicKey)
}

func rsaKey(t *testing.T, bits int) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	return authKey(t, &k.PublicKey)
}

func TestValidate(t *testing.T) {
	ed := edKey(t)
	many := make([]string, hostkeypolicy.MaxHostKeys+1)
	for i := range many {
		many[i] = edKey(t)
	}
	// The parser only needs well-formed integers; the values are arbitrary.
	n := big.NewInt
	dsaBlob := ssh.Marshal(struct {
		Name       string
		P, Q, G, Y *big.Int
	}{"ssh-dss", n(0x7fffffff), n(0x7ffffff1), n(2), n(12345678)})
	dsa := "ssh-dss " + base64.StdEncoding.EncodeToString(dsaBlob)
	rsa2048 := rsaKey(t, 2048)
	cert := string(ssh.MarshalAuthorizedKey(hostCert(t, newSigner(t), newSigner(t), []string{"h"}, time.Now().Add(time.Hour))))

	tests := []struct {
		name    string
		policy  Policy
		wantErr error
	}{
		{"ed25519 pin", Policy{PinnedKeys: []string{ed}}, nil},
		{"ed25519 pin with comment", Policy{PinnedKeys: []string{ed + " host.example.com"}}, nil},
		{"ecdsa p256", Policy{PinnedKeys: []string{ecKey(t, elliptic.P256())}}, nil},
		{"ecdsa p384", Policy{PinnedKeys: []string{ecKey(t, elliptic.P384())}}, nil},
		{"ecdsa p521", Policy{PinnedKeys: []string{ecKey(t, elliptic.P521())}}, nil},
		{"rsa 3072 pin", Policy{PinnedKeys: []string{rsaKey(t, hostkeypolicy.MinRSABits)}}, nil},
		{"ca only", Policy{HostCAs: []string{edKey(t)}}, nil},
		{"pin and ca", Policy{PinnedKeys: []string{ed}, HostCAs: []string{edKey(t)}}, nil},
		{"max entries", Policy{PinnedKeys: many[:hostkeypolicy.MaxHostKeys]}, nil},

		{"empty policy", Policy{}, ErrEmptyPolicy},
		{"too many pins", Policy{PinnedKeys: many}, ErrTooManyEntries},
		{"too many in total", Policy{PinnedKeys: many[:hostkeypolicy.MaxHostKeys], HostCAs: []string{edKey(t)}}, ErrTooManyEntries},
		{"oversize entry", Policy{PinnedKeys: []string{ed + " " + strings.Repeat("a", hostkeypolicy.MaxEntryLength)}}, ErrEntryTooLarge},
		{"empty entry", Policy{PinnedKeys: []string{""}}, ErrMalformedEntry},
		{"garbage", Policy{PinnedKeys: []string{"not a key"}}, ErrMalformedEntry},
		{"two keys in one entry", Policy{PinnedKeys: []string{ed + "\n" + edKey(t)}}, ErrMalformedEntry},
		{"options on pin", Policy{PinnedKeys: []string{`command="id" ` + ed}}, ErrKeyOptions},
		{"options on ca", Policy{HostCAs: []string{`cert-authority ` + ed}}, ErrKeyOptions},
		{"control char in comment", Policy{PinnedKeys: []string{ed + " bad\x01comment"}}, ErrInvalidComment},
		{"leading comment line", Policy{PinnedKeys: []string{"# note\n" + ed}}, ErrInvalidComment},
		{"second line in entry", Policy{PinnedKeys: []string{ed + " a\nb"}}, ErrMalformedEntry},
		{"duplicate pin", Policy{PinnedKeys: []string{ed, ed}}, ErrDuplicateKey},
		{"duplicate pin with other comment", Policy{PinnedKeys: []string{ed, ed + " other"}}, ErrDuplicateKey},
		{"duplicate ca", Policy{HostCAs: []string{ed, ed}}, ErrDuplicateKey},
		{"same key as pin and ca", Policy{PinnedKeys: []string{ed}, HostCAs: []string{ed}}, ErrDuplicateKey},
		{"wildcard host pattern", Policy{PinnedKeys: []string{"*.example.com " + ed}}, ErrWildcardPattern},
		{"question mark host pattern", Policy{PinnedKeys: []string{"host?.example.com " + ed}}, ErrWildcardPattern},
		{"wildcard in comment", Policy{PinnedKeys: []string{ed + " *.example.com"}}, ErrWildcardPattern},
		// The pinned x/crypto no longer parses ssh-dss at all, so DSA is
		// rejected as unparsable; checkAlgorithm still names it if it ever does.
		{"dsa", Policy{PinnedKeys: []string{dsa}}, ErrMalformedEntry},
		{"rsa 2048", Policy{PinnedKeys: []string{rsa2048}}, ErrWeakKey},
		{"rsa 2048 ca", Policy{HostCAs: []string{rsa2048}}, ErrWeakKey},
		{"security key algorithm", Policy{PinnedKeys: []string{skKey(t)}}, ErrUnsupportedAlgorithm},
		{"certificate as pin", Policy{PinnedKeys: []string{cert}}, ErrCertificateEntry},
		{"certificate as ca", Policy{HostCAs: []string{cert}}, ErrCertificateEntry},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.policy)
			cb, newErr := New(tt.policy)
			if tt.wantErr == nil {
				require.NoError(t, err)
				require.NoError(t, newErr)
				assert.NotNil(t, cb)
				return
			}
			require.ErrorIs(t, err, tt.wantErr)
			require.ErrorIs(t, newErr, tt.wantErr, "New must enforce Validate")
			assert.Nil(t, cb)
		})
	}
}

// skKey returns a well-formed sk-ssh-ed25519@openssh.com key.
func skKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	blob := ssh.Marshal(struct {
		Name        string
		Key         []byte
		Application string
	}{"sk-ssh-ed25519@openssh.com", pub, "ssh:"})
	return "sk-ssh-ed25519@openssh.com " + base64.StdEncoding.EncodeToString(blob)
}

func TestValidateErrorsNeverEchoKeyMaterial(t *testing.T) {
	k := rsaKey(t, 2048)
	blob := strings.Fields(k)[1]
	err := Validate(Policy{PinnedKeys: []string{k}})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), blob[:40])
	assert.Contains(t, err.Error(), "SHA256:")

	ed := edKey(t)
	err = Validate(Policy{PinnedKeys: []string{ed, ed}})
	require.ErrorIs(t, err, ErrDuplicateKey)
	assert.NotContains(t, err.Error(), strings.Fields(ed)[1][:40])
	assert.Contains(t, err.Error(), "SHA256:")

	err = Validate(Policy{PinnedKeys: []string{`command="id" ` + k}})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), blob[:40])
}
