// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh/injectauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const (
	testUpstreamUser = "alice"
	testUpstreamPass = "sentinel-password-7c1e"
)

// passwordTarget is an in-process SSH server that requires a password, counts
// authentication attempts, echoes session data and acknowledges "exec".
type passwordTarget struct {
	addr     string
	hostKey  ssh.Signer
	authTrys atomic.Int32
	// agentRejected receives the result of the server trying to open a
	// channel towards the client.
	agentRejected chan bool
	closed        chan struct{}
}

func newPasswordTarget(t *testing.T) *passwordTarget {
	t.Helper()
	pt := &passwordTarget{
		hostKey:       newSigner(t),
		agentRejected: make(chan bool, 1),
		closed:        make(chan struct{}, 1),
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			pt.authTrys.Add(1)
			if c.User() == testUpstreamUser && string(pw) == testUpstreamPass {
				return nil, nil
			}
			return nil, assert.AnError
		},
	}
	cfg.AddHostKey(pt.hostKey)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	pt.addr = l.Addr().String()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go pt.serve(c, cfg)
		}
	}()
	return pt
}

func (pt *passwordTarget) serve(c net.Conn, cfg *ssh.ServerConfig) {
	defer func() {
		select {
		case pt.closed <- struct{}{}:
		default:
		}
	}()
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		c.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	// Try to open a channel towards the client, as agent forwarding would.
	go func() {
		_, _, err := sc.OpenChannel("auth-agent@openssh.com", nil)
		select {
		case pt.agentRejected <- err != nil:
		default:
		}
	}()
	for nc := range chans {
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			for r := range creqs {
				if r.WantReply {
					_ = r.Reply(r.Type == "exec", nil)
				}
			}
		}()
		go func() {
			_, _ = io.Copy(ch, ch)
			_ = ch.Close()
		}()
	}
}

func TestNewClientUpstream(t *testing.T) {
	cb := ssh.FixedHostKey(newSigner(t).PublicKey())
	good := injectauth.Input{Username: testUpstreamUser, Password: testUpstreamPass}

	tests := []struct {
		name string
		addr string
		cred injectauth.Input
		cb   ssh.HostKeyCallback
	}{
		{"nil callback", "127.0.0.1:22", good, nil},
		{"empty address", "", good, cb},
		{"no username", "127.0.0.1:22", injectauth.Input{Password: testUpstreamPass}, cb},
		{"no credential", "127.0.0.1:22", injectauth.Input{Username: "u"}, cb},
		{"bad private key", "127.0.0.1:22", injectauth.Input{Username: "u", PrivateKey: []byte("not a key")}, cb},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			up, err := NewClientUpstream(context.Background(), tt.addr, tt.cred, tt.cb)
			require.Error(t, err)
			assert.Nil(t, up)
			assert.NotContains(t, err.Error(), testUpstreamPass)
		})
	}

	t.Run("pins host key algorithms and requires callback", func(t *testing.T) {
		up, err := NewClientUpstream(context.Background(), "127.0.0.1:22", good, cb)
		require.NoError(t, err)
		assert.NotNil(t, up.config.HostKeyCallback)
		assert.NotEmpty(t, up.config.HostKeyAlgorithms)
		assert.NotContains(t, up.config.HostKeyAlgorithms, ssh.KeyAlgoRSA)
	})

	t.Run("zeroes key and passphrase buffers", func(t *testing.T) {
		_, priv := newPEMKey(t)
		in := injectauth.Input{Username: "u", PrivateKey: priv}
		_, err := NewClientUpstream(context.Background(), "127.0.0.1:22", in, cb)
		require.NoError(t, err)
		assert.Equal(t, make([]byte, len(priv)), priv)
	})
}

func TestClientUpstream_Dial(t *testing.T) {
	t.Run("correct password and matching host key", func(t *testing.T) {
		pt := newPasswordTarget(t)
		up, err := NewClientUpstream(context.Background(), pt.addr,
			injectauth.Input{Username: testUpstreamUser, Password: testUpstreamPass},
			ssh.FixedHostKey(pt.hostKey.PublicKey()))
		require.NoError(t, err)
		conn, err := up.Dial(context.Background())
		require.NoError(t, err)
		defer conn.Close()

		ch, reqs, err := conn.OpenChannel("session", nil)
		require.NoError(t, err)
		go ssh.DiscardRequests(reqs)
		ok, _, err := conn.SendRequest("keepalive@openssh.com", false, nil)
		require.NoError(t, err)
		assert.False(t, ok)
		_, err = ch.Write([]byte("hello"))
		require.NoError(t, err)
		buf := make([]byte, 5)
		_, err = io.ReadFull(ch, buf)
		require.NoError(t, err)
		assert.Equal(t, "hello", string(buf))
		assert.Equal(t, int32(1), pt.authTrys.Load())

		// A channel opened by the target is rejected.
		select {
		case rejected := <-pt.agentRejected:
			assert.True(t, rejected)
		case <-time.After(5 * time.Second):
			t.Fatal("target-initiated channel was neither accepted nor rejected")
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		pt := newPasswordTarget(t)
		up, err := NewClientUpstream(context.Background(), pt.addr,
			injectauth.Input{Username: testUpstreamUser, Password: "wrong-password"},
			ssh.FixedHostKey(pt.hostKey.PublicKey()))
		require.NoError(t, err)
		conn, err := up.Dial(context.Background())
		require.Error(t, err)
		assert.Nil(t, conn)
		assert.NotContains(t, err.Error(), "wrong-password")
		assert.Equal(t, int32(1), pt.authTrys.Load())
	})

	t.Run("host key mismatch refuses before authentication", func(t *testing.T) {
		pt := newPasswordTarget(t)
		up, err := NewClientUpstream(context.Background(), pt.addr,
			injectauth.Input{Username: testUpstreamUser, Password: testUpstreamPass},
			ssh.FixedHostKey(newSigner(t).PublicKey()))
		require.NoError(t, err)
		conn, err := up.Dial(context.Background())
		require.Error(t, err)
		assert.Nil(t, conn)
		assert.NotContains(t, err.Error(), testUpstreamPass)
		assert.Equal(t, int32(0), pt.authTrys.Load(), "no authentication may be attempted")
	})

	t.Run("dial failure", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		addr := l.Addr().String()
		require.NoError(t, l.Close())
		up, err := NewClientUpstream(context.Background(), addr,
			injectauth.Input{Username: "u", Password: "p"}, ssh.FixedHostKey(newSigner(t).PublicKey()))
		require.NoError(t, err)
		_, err = up.Dial(context.Background())
		require.Error(t, err)
	})
}

func TestClientUpstream_ServeContextCancelClosesBothLegs(t *testing.T) {
	pt := newPasswordTarget(t)
	up, err := NewClientUpstream(context.Background(), pt.addr,
		injectauth.Input{Username: testUpstreamUser, Password: testUpstreamPass},
		ssh.FixedHostKey(pt.hostKey.PublicKey()))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, done := startServe(t, ctx, okAuth(), up)

	sess, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, sess.Start("true"))

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after context cancel")
	}
	select {
	case <-pt.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream connection was not closed")
	}
	_, _, err = client.SendRequest("keepalive@openssh.com", true, nil)
	assert.Error(t, err, "client leg must be closed")
}

// newPEMKey returns a fresh OpenSSH-format Ed25519 private key.
func newPEMKey(t *testing.T) (ssh.Signer, []byte) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	blk, err := ssh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)
	return signer, pem.EncodeToMemory(blk)
}

func TestClientUpstream_DialStalledHandshakeIsBounded(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err == nil {
			defer c.Close()
			_, _ = io.Copy(io.Discard, c) // accept and never answer
		}
	}()
	up, err := NewClientUpstream(context.Background(), l.Addr().String(),
		injectauth.Input{Username: "u", Password: "p"}, ssh.FixedHostKey(newSigner(t).PublicKey()))
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = up.Dial(ctx)
	require.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second)
}
