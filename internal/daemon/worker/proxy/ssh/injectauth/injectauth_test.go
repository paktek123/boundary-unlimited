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
	"net"
	"strings"
	"testing"
	"time"

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

func newCA(t *testing.T) ssh.Signer {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	s, err := ssh.NewSignerFromKey(k)
	require.NoError(t, err)
	return s
}

// certFor signs a certificate for pub using ca, applying mod first.
func certFor(t *testing.T, ca ssh.Signer, pub ssh.PublicKey, mod func(*ssh.Certificate)) []byte {
	t.Helper()
	c := &ssh.Certificate{
		Key:             pub,
		CertType:        ssh.UserCert,
		KeyId:           "test",
		ValidPrincipals: []string{"u"},
		ValidAfter:      uint64(time.Now().Add(-time.Hour).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
	}
	if mod != nil {
		mod(c)
	}
	require.NoError(t, c.SignCert(rand.Reader, ca))
	return ssh.MarshalAuthorizedKey(c)
}

func TestAuthMethodsCertificate(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	edSigner, err := ssh.NewSignerFromKey(edKey)
	require.NoError(t, err)
	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	otherSigner, err := ssh.NewSignerFromKey(otherKey)
	require.NoError(t, err)
	ca := newCA(t)
	keyPEM := pemKey(t, edKey, "")

	tests := []struct {
		name    string
		in      Input
		wantErr error
	}{
		{"valid", Input{Username: "u", PrivateKey: keyPEM, Certificate: certFor(t, ca, edSigner.PublicKey(), nil)}, nil},
		{"valid with password", Input{Username: "u", Password: secretPassword, PrivateKey: keyPEM, Certificate: certFor(t, ca, edSigner.PublicKey(), nil)}, nil},
		{"host cert", Input{Username: "u", PrivateKey: keyPEM, Certificate: certFor(t, ca, edSigner.PublicKey(), func(c *ssh.Certificate) { c.CertType = ssh.HostCert })}, ErrBadCertificate},
		{"expired", Input{Username: "u", PrivateKey: keyPEM, Certificate: certFor(t, ca, edSigner.PublicKey(), func(c *ssh.Certificate) {
			c.ValidAfter = uint64(time.Now().Add(-2 * time.Hour).Unix())
			c.ValidBefore = uint64(time.Now().Add(-time.Hour).Unix())
		})}, ErrBadCertificate},
		{"not yet valid", Input{Username: "u", PrivateKey: keyPEM, Certificate: certFor(t, ca, edSigner.PublicKey(), func(c *ssh.Certificate) {
			c.ValidAfter = uint64(time.Now().Add(time.Hour).Unix())
			c.ValidBefore = uint64(time.Now().Add(2 * time.Hour).Unix())
		})}, ErrBadCertificate},
		{"key mismatch", Input{Username: "u", PrivateKey: keyPEM, Certificate: certFor(t, ca, otherSigner.PublicKey(), nil)}, ErrBadCertificate},
		{"unparsable", Input{Username: "u", PrivateKey: keyPEM, Certificate: []byte("garbage")}, ErrBadCertificate},
		{"plain public key, not a cert", Input{Username: "u", PrivateKey: keyPEM, Certificate: ssh.MarshalAuthorizedKey(edSigner.PublicKey())}, ErrBadCertificate},
		{"certificate without key", Input{Username: "u", Password: secretPassword, Certificate: certFor(t, ca, edSigner.PublicKey(), nil)}, ErrBadCertificate},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			user, methods, err := AuthMethods(tc.in)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				assert.Empty(t, user)
				assert.Nil(t, methods)
				for _, s := range []string{secretPassword, "PRIVATE KEY", string(tc.in.PrivateKey), string(tc.in.Certificate)} {
					if s != "" {
						assert.False(t, strings.Contains(err.Error(), s), "error leaks material: %v", err)
					}
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "u", user)
			assert.NotEmpty(t, methods)
		})
	}
}

func TestCertificateAuthAgainstServer(t *testing.T) {
	ca := newCA(t)
	otherCA := newCA(t)
	_, userKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	userSigner, err := ssh.NewSignerFromKey(userKey)
	require.NoError(t, err)

	_, hostKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	hostSigner, err := ssh.NewSignerFromKey(hostKey)
	require.NoError(t, err)

	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return bytesEqual(auth.Marshal(), ca.PublicKey().Marshal())
		},
	}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if _, ok := key.(*ssh.Certificate); !ok {
				return nil, fmt.Errorf("certificate required")
			}
			return checker.Authenticate(conn, key)
		},
	}
	cfg.AddHostKey(hostSigner)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					c.Close()
					return
				}
				go ssh.DiscardRequests(reqs)
				go func() {
					for ch := range chans {
						ch.Reject(ssh.Prohibited, "no")
					}
				}()
				sc.Wait()
			}()
		}
	}()

	dial := func(t *testing.T, cert []byte) error {
		user, methods, err := AuthMethods(Input{Username: "u", PrivateKey: pemKey(t, userKey, ""), Certificate: cert})
		require.NoError(t, err)
		cc, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{
			User:            user,
			Auth:            methods,
			HostKeyCallback: ssh.FixedHostKey(hostSigner.PublicKey()),
			Timeout:         5 * time.Second,
		})
		if err == nil {
			cc.Close()
		}
		return err
	}

	t.Run("trusted CA accepted", func(t *testing.T) {
		require.NoError(t, dial(t, certFor(t, ca, userSigner.PublicKey(), nil)))
	})
	t.Run("untrusted CA rejected", func(t *testing.T) {
		require.Error(t, dial(t, certFor(t, otherCA, userSigner.PublicKey(), nil)))
	})
	t.Run("principal not allowed rejected", func(t *testing.T) {
		require.Error(t, dial(t, certFor(t, ca, userSigner.PublicKey(), func(c *ssh.Certificate) { c.ValidPrincipals = []string{"someone-else"} })))
	})
}

func bytesEqual(a, b []byte) bool { return string(a) == string(b) }
