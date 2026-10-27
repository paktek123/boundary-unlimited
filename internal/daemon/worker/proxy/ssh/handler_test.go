// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"bytes"
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh/hostkey"
	"github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh/injectauth"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// countingListener counts connections and closes them immediately.
func countingListener(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	var n atomic.Int32
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			c.Close()
		}
	}()
	return l.Addr().String(), &n
}

func pinned(s ssh.Signer) hostkey.Policy {
	return hostkey.Policy{PinnedKeys: []string{string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(s.PublicKey())))}}
}

// startHandle runs HandleSession on one end of a TCP pair and returns a
// client connected to the other end.
func startHandle(t *testing.T, cfg SessionConfig) (*ssh.Client, <-chan error) {
	t.Helper()
	c1, c2 := tcpPair(t)
	done := make(chan error, 1)
	go func() { done <- HandleSession(context.Background(), c2, cfg) }()
	sc, chans, reqs, err := ssh.NewClientConn(c1, "worker", &ssh.ClientConfig{
		User:            "anyone",
		HostKeyCallback: ssh.FixedHostKey(cfg.ClientHostKey.PublicKey()),
		Timeout:         5 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { sc.Close() })
	return ssh.NewClient(sc, chans, reqs), done
}

func TestHandleSession_FailsClosedBeforeDial(t *testing.T) {
	addr, dials := countingListener(t)
	target := newSigner(t)
	good := func() SessionConfig {
		return SessionConfig{
			Authorization: okAuth(),
			ClientHostKey: newSigner(t),
			UpstreamAddr:  addr,
			Credential:    injectauth.Input{Username: testUpstreamUser, Password: testUpstreamPass},
			HostKeys:      pinned(target),
		}
	}
	tests := []struct {
		name string
		mod  func(*SessionConfig)
	}{
		{"empty host key policy", func(c *SessionConfig) { c.HostKeys = hostkey.Policy{} }},
		{"unparsable host key policy", func(c *SessionConfig) { c.HostKeys = hostkey.Policy{PinnedKeys: []string{"junk"}} }},
		{"expired authorization", func(c *SessionConfig) { c.Authorization.Expiry = time.Now().Add(-time.Second) }},
		{"missing session id", func(c *SessionConfig) { c.Authorization.SessionId = "" }},
		{"nil client host key", func(c *SessionConfig) { c.ClientHostKey = nil }},
		{"missing address", func(c *SessionConfig) { c.UpstreamAddr = "" }},
		{"no username", func(c *SessionConfig) { c.Credential.Username = "" }},
		{"no credential", func(c *SessionConfig) { c.Credential.Password = "" }},
		{"bad private key", func(c *SessionConfig) {
			c.Credential.Password = ""
			c.Credential.PrivateKey = []byte("not a key")
		}},
		{"invalid policy", func(c *SessionConfig) { c.Policy = Policy{AllowedChannelTypes: []string{"session"}} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := good()
			tt.mod(&cfg)
			c1, c2 := tcpPair(t)
			defer c1.Close()
			err := HandleSession(context.Background(), c2, cfg)
			require.Error(t, err)
			assert.True(t, errors.Match(errors.T(errors.InvalidParameter), err), "got %v", err)
			assert.NotContains(t, err.Error(), testUpstreamPass)
			// conn was closed by HandleSession.
			_ = c1.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, rerr := c1.Read(make([]byte, 1))
			assert.Error(t, rerr)
		})
	}
	assert.Zero(t, dials.Load(), "upstream must never be dialed")
}

func TestHandleSession_PasswordExec(t *testing.T) {
	pt := newPasswordTarget(t)
	client, done := startHandle(t, SessionConfig{
		Authorization: okAuth(),
		ClientHostKey: newSigner(t),
		UpstreamAddr:  pt.addr,
		Credential:    injectauth.Input{Username: testUpstreamUser, Password: testUpstreamPass},
		HostKeys:      pinned(pt.hostKey),
	})
	sess, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, sess.Start("hello"))
	assert.EqualValues(t, 1, pt.authTrys.Load())
	client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("HandleSession did not return")
	}
}

func TestHandleSession_PrivateKeyExec(t *testing.T) {
	userSigner, pemKey := newPEMKey(t)
	var keyAuths atomic.Int32
	hostSigner := newSigner(t)
	scfg := &ssh.ServerConfig{PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		keyAuths.Add(1)
		if c.User() == testUpstreamUser && bytes.Equal(k.Marshal(), userSigner.PublicKey().Marshal()) {
			return nil, nil
		}
		return nil, assert.AnError
	}}
	scfg.AddHostKey(hostSigner)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				sc, chans, reqs, err := ssh.NewServerConn(c, scfg)
				if err != nil {
					c.Close()
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(reqs)
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
					go func() { _ = ch.Close() }()
				}
			}()
		}
	}()

	client, _ := startHandle(t, SessionConfig{
		Authorization: okAuth(),
		ClientHostKey: newSigner(t),
		UpstreamAddr:  l.Addr().String(),
		Credential:    injectauth.Input{Username: testUpstreamUser, PrivateKey: pemKey},
		HostKeys:      pinned(hostSigner),
	})
	sess, err := client.NewSession()
	require.NoError(t, err)
	// The exec request is acknowledged by the target; the channel then closes.
	_ = sess.Run("hello")
	assert.EqualValues(t, 1, keyAuths.Load())
}

func TestHandleSession_HostKeyMismatchRefuses(t *testing.T) {
	pt := newPasswordTarget(t)
	client, done := startHandle(t, SessionConfig{
		Authorization: okAuth(),
		ClientHostKey: newSigner(t),
		UpstreamAddr:  pt.addr,
		Credential:    injectauth.Input{Username: testUpstreamUser, Password: testUpstreamPass},
		HostKeys:      pinned(newSigner(t)), // not the target's key
	})
	defer client.Close()
	select {
	case err := <-done:
		require.Error(t, err)
		assert.NotContains(t, err.Error(), testUpstreamPass)
	case <-time.After(5 * time.Second):
		t.Fatal("HandleSession did not return")
	}
	assert.Zero(t, pt.authTrys.Load(), "no authentication may be attempted after a host key mismatch")
	_, err := client.NewSession()
	assert.Error(t, err)
}

func TestHandleSession_ClientCannotChooseTarget(t *testing.T) {
	pt := newPasswordTarget(t)
	other, otherDials := countingListener(t)
	client, _ := startHandle(t, SessionConfig{
		Authorization: okAuth(),
		ClientHostKey: newSigner(t),
		UpstreamAddr:  pt.addr,
		Credential:    injectauth.Input{Username: testUpstreamUser, Password: testUpstreamPass},
		HostKeys:      pinned(pt.hostKey),
	})
	host, port, err := net.SplitHostPort(other)
	require.NoError(t, err)
	payload := ssh.Marshal(struct {
		Host     string
		Port     uint32
		OrigHost string
		OrigPort uint32
	}{host, 1, "127.0.0.1", 1})
	_ = port
	_, _, err = client.OpenChannel("direct-tcpip", payload)
	require.Error(t, err)
	var oe *ssh.OpenChannelError
	require.ErrorAs(t, err, &oe)
	assert.Equal(t, ssh.Prohibited, oe.Reason)
	assert.Zero(t, otherDials.Load())
}

func TestHandleSession_PolicySnapshot(t *testing.T) {
	pt := newPasswordTarget(t)
	cfg := SessionConfig{
		Authorization: okAuth(),
		ClientHostKey: newSigner(t),
		UpstreamAddr:  pt.addr,
		Credential:    injectauth.Input{Username: testUpstreamUser, Password: testUpstreamPass},
		HostKeys:      pinned(pt.hostKey),
		Policy:        DefaultPolicy(),
	}
	client, _ := startHandle(t, cfg)
	// Mutate the caller's copy after the session has started.
	cfg.Policy.AllowedChannelTypes[0] = "direct-tcpip"
	cfg.Policy.AllowedChannelTypes = append(cfg.Policy.AllowedChannelTypes, "direct-tcpip")
	cfg.HostKeys.PinnedKeys[0] = "junk"

	_, _, err := client.OpenChannel("direct-tcpip", nil)
	require.Error(t, err, "mutated policy must not apply to the running session")
	sess, err := client.NewSession()
	require.NoError(t, err, "snapshotted policy still allows session channels")
	require.NoError(t, sess.Start("hello"))
}

func TestSnapshotPolicy_ZeroIsDefault(t *testing.T) {
	assert.Equal(t, DefaultPolicy(), snapshotPolicy(Policy{}))
}

func TestHandleSession_NoSecretInErrors(t *testing.T) {
	const sentinel = "sentinel-password-7c1e"
	addr, _ := countingListener(t)
	c1, c2 := tcpPair(t)
	defer c1.Close()
	err := HandleSession(context.Background(), c2, SessionConfig{
		Authorization: okAuth(),
		ClientHostKey: newSigner(t),
		UpstreamAddr:  addr,
		Credential:    injectauth.Input{Username: "u", Password: sentinel, PrivateKey: []byte("bad")},
		HostKeys:      pinned(newSigner(t)),
	})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), sentinel)
}
