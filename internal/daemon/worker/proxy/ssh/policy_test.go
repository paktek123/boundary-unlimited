// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// startServeOpts is startServe with Serve options.
func startServeOpts(t *testing.T, up Upstream, opt ...Option) (*ssh.Client, <-chan error) {
	t.Helper()
	hostKey := newSigner(t)
	c1, c2 := tcpPair(t)
	done := make(chan error, 1)
	go func() { done <- Serve(context.Background(), c2, hostKey, okAuth(), up, opt...) }()
	sc, chans, reqs, err := ssh.NewClientConn(c1, "worker", &ssh.ClientConfig{
		User:            "anyone",
		HostKeyCallback: ssh.FixedHostKey(hostKey.PublicKey()),
		Timeout:         5 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { sc.Close() })
	return ssh.NewClient(sc, chans, reqs), done
}

func TestServe_ChannelTypes(t *testing.T) {
	tests := []struct {
		name       string
		chanType   string
		policy     *Policy
		wantReject ssh.RejectionReason
		wantOpen   bool
	}{
		{name: "session allowed", chanType: "session", wantOpen: true},
		{name: "direct-tcpip denied", chanType: "direct-tcpip", wantReject: ssh.Prohibited},
		{name: "forwarded-tcpip denied", chanType: "forwarded-tcpip", wantReject: ssh.Prohibited},
		{name: "agent channel denied", chanType: "auth-agent@openssh.com", wantReject: ssh.Prohibited},
		{name: "x11 denied", chanType: "x11", wantReject: ssh.Prohibited},
		{name: "unknown denied", chanType: "made-up", wantReject: ssh.Prohibited},
		{
			name: "explicitly allowed by policy", chanType: "direct-tcpip", wantOpen: true,
			policy: func() *Policy {
				p := DefaultPolicy()
				p.AllowedChannelTypes = append(p.AllowedChannelTypes, "direct-tcpip")
				return &p
			}(),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ft := newFakeTarget(t)
			var opts []Option
			if tc.policy != nil {
				opts = append(opts, WithPolicy(*tc.policy))
			}
			client, _ := startServeOpts(t, ft, opts...)
			ch, _, err := client.OpenChannel(tc.chanType, nil)
			if tc.wantOpen {
				require.NoError(t, err)
				require.NoError(t, ch.Close())
				return
			}
			var oe *ssh.OpenChannelError
			require.True(t, errors.As(err, &oe), "got %v", err)
			assert.Equal(t, tc.wantReject, oe.Reason)
			assert.NotContains(t, ft.seen(&ft.chanTypes), tc.chanType, "denied channel must not reach the target")
		})
	}
}

func TestServe_ChannelRequests(t *testing.T) {
	ft := newFakeTarget(t)
	client, _ := startServeOpts(t, ft)
	sess, err := client.NewSession()
	require.NoError(t, err)

	for _, denied := range []string{"x11-req", "auth-agent-req@openssh.com", "made-up"} {
		ok, err := sess.SendRequest(denied, true, nil)
		require.NoError(t, err)
		assert.False(t, ok, denied)
	}
	ok, err := sess.SendRequest("exec", true, nil)
	require.NoError(t, err)
	assert.True(t, ok)

	assert.Equal(t, []string{"exec"}, ft.seen(&ft.reqTypes), "only allowed requests reach the target")
}

func TestServe_GlobalRequests(t *testing.T) {
	t.Run("denied by default", func(t *testing.T) {
		ft := newFakeTarget(t)
		client, _ := startServeOpts(t, ft)
		for _, typ := range []string{"tcpip-forward", "cancel-tcpip-forward", "keepalive@openssh.com", "made-up"} {
			ok, _, err := client.SendRequest(typ, true, nil)
			require.NoError(t, err)
			assert.False(t, ok, typ)
		}
		assert.Empty(t, ft.seen(&ft.globalReqs))
	})
	t.Run("allowed by policy", func(t *testing.T) {
		ft := newFakeTarget(t)
		p := DefaultPolicy()
		p.AllowedGlobalRequests = []string{"keepalive@openssh.com"}
		client, _ := startServeOpts(t, ft, WithPolicy(p))
		ok, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
		require.NoError(t, err)
		assert.True(t, ok)
		ok, _, err = client.SendRequest("tcpip-forward", true, nil)
		require.NoError(t, err)
		assert.False(t, ok)
		assert.Equal(t, []string{"keepalive@openssh.com"}, ft.seen(&ft.globalReqs))
	})
}

func TestServe_ChannelCap(t *testing.T) {
	ft := newFakeTarget(t)
	p := DefaultPolicy()
	p.MaxChannels = 2
	client, _ := startServeOpts(t, ft, WithPolicy(p))

	s1, err := client.NewSession()
	require.NoError(t, err)
	_, err = client.NewSession()
	require.NoError(t, err)

	_, err = client.NewSession()
	var oe *ssh.OpenChannelError
	require.True(t, errors.As(err, &oe), "got %v", err)
	assert.Equal(t, ssh.ResourceShortage, oe.Reason)

	// closing a channel frees a slot
	require.NoError(t, s1.Close())
	require.Eventually(t, func() bool {
		s, err := client.NewSession()
		if err != nil {
			return false
		}
		_ = s.Close()
		return true
	}, 5*time.Second, 25*time.Millisecond)
}

func TestServe_InvalidPolicyFailsClosed(t *testing.T) {
	for _, max := range []int{0, -1} {
		ft := newFakeTarget(t)
		p := DefaultPolicy()
		p.MaxChannels = max
		_, c := tcpPair(t)
		require.Error(t, Serve(context.Background(), c, newSigner(t), okAuth(), ft, WithPolicy(p)))
		assert.Zero(t, ft.dials.Load(), "must not dial upstream")
	}
}

func TestDefaultPolicy(t *testing.T) {
	p := DefaultPolicy()
	assert.Equal(t, []string{"session"}, p.AllowedChannelTypes)
	assert.Empty(t, p.AllowedGlobalRequests)
	assert.Equal(t, DefaultMaxChannels, p.MaxChannels)
	for _, denied := range []string{"x11-req", "auth-agent-req@openssh.com", "tcpip-forward"} {
		assert.False(t, p.allowChannelRequest(denied), denied)
		assert.False(t, p.allowUpstreamRequest(denied), denied)
	}
	assert.False(t, p.allowUpstreamRequest("shell"))
}

// The target must not be able to open channels (for example agent
// forwarding) towards the client; the upstream fake rejects them and Serve has
// no code path that relays them.
func TestServe_UpstreamInitiatedChannelsRejected(t *testing.T) {
	ft := newFakeTarget(t)
	client, _ := startServeOpts(t, ft)
	_, err := client.NewSession()
	require.NoError(t, err)

	var srv ssh.Conn
	select {
	case srv = <-ft.srvConns:
	case <-time.After(5 * time.Second):
		t.Fatal("target connection not established")
	}
	// The fake's server side is the target; opening a channel towards the
	// worker must fail.
	_, _, err = srv.OpenChannel("auth-agent@openssh.com", nil)
	var oe *ssh.OpenChannelError
	require.True(t, errors.As(err, &oe), "got %v", err)
	assert.Equal(t, ssh.Prohibited, oe.Reason)
}
