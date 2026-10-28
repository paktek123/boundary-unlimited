// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package hostkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	s, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return s
}

func authorized(s ssh.Signer) string { return string(ssh.MarshalAuthorizedKey(s.PublicKey())) }

func hostCert(t *testing.T, ca, host ssh.Signer, principals []string, validBefore time.Time) *ssh.Certificate {
	t.Helper()
	c := &ssh.Certificate{
		Key:             host.PublicKey(),
		CertType:        ssh.HostCert,
		ValidPrincipals: principals,
		ValidAfter:      uint64(time.Now().Add(-time.Hour).Unix()),
		ValidBefore:     uint64(validBefore.Unix()),
	}
	require.NoError(t, c.SignCert(rand.Reader, ca))
	return c
}

var addr = &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 22}

func TestPinned(t *testing.T) {
	good, other := newSigner(t), newSigner(t)
	cb, err := New(Policy{PinnedKeys: []string{authorized(good)}})
	require.NoError(t, err)
	assert.NoError(t, cb("h:22", addr, good.PublicKey()))
	err = cb("h:22", addr, other.PublicKey())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrHostKeyMismatch)
}

func TestEmptyPolicyFailsConstruction(t *testing.T) {
	cb, err := New(Policy{})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEmptyPolicy)
	assert.Nil(t, cb)
}

func TestMalformedFailsConstruction(t *testing.T) {
	good := newSigner(t)
	for name, p := range map[string]Policy{
		"bad pinned":     {PinnedKeys: []string{"not a key"}},
		"bad ca":         {HostCAs: []string{"ssh-ed25519 !!!"}},
		"good and bad":   {PinnedKeys: []string{authorized(good), "junk"}},
		"trailing data":  {PinnedKeys: []string{authorized(good) + authorized(good)}},
		"cert as pinned": {PinnedKeys: []string{string(ssh.MarshalAuthorizedKey(hostCert(t, newSigner(t), good, []string{"h"}, time.Now().Add(time.Hour))))}},
		"empty string":   {PinnedKeys: []string{""}},
	} {
		t.Run(name, func(t *testing.T) {
			cb, err := New(p)
			require.Error(t, err)
			assert.Nil(t, cb)
		})
	}
}

func TestHostCA(t *testing.T) {
	ca, unknownCA, host := newSigner(t), newSigner(t), newSigner(t)
	cb, err := New(Policy{HostCAs: []string{authorized(ca)}})
	require.NoError(t, err)
	future := time.Now().Add(time.Hour)

	assert.NoError(t, cb("h:22", addr, hostCert(t, ca, host, []string{"h"}, future)))
	assert.ErrorIs(t, cb("h:22", addr, hostCert(t, unknownCA, host, []string{"h"}, future)), ErrHostKeyMismatch, "unknown CA")
	assert.ErrorIs(t, cb("h:22", addr, hostCert(t, ca, host, []string{"h"}, time.Now().Add(-time.Minute))), ErrHostKeyMismatch, "expired")
	assert.ErrorIs(t, cb("h:22", addr, hostCert(t, ca, host, []string{"other"}, future)), ErrHostKeyMismatch, "wrong principal")
	// A plain key is not accepted just because a CA is configured.
	assert.ErrorIs(t, cb("h:22", addr, host.PublicKey()), ErrHostKeyMismatch)
	// A user certificate is not a host certificate.
	uc := hostCert(t, ca, host, []string{"h"}, future)
	uc.CertType = ssh.UserCert
	require.NoError(t, uc.SignCert(rand.Reader, ca))
	assert.ErrorIs(t, cb("h:22", addr, uc), ErrHostKeyMismatch)
}
