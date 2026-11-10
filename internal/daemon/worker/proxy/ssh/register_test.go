// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package ssh

import (
	"context"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/worker/proxy"
	"github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh/hostkey"
	"github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh/injectauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"
)

func withDecoder(t *testing.T, d InputDecoder) {
	t.Helper()
	old := decodeInput
	decodeInput = d
	t.Cleanup(func() { decodeInput = old })
}

func registered(t *testing.T) proxy.Handler {
	t.Helper()
	h, err := proxy.LookupHandler(proxy.SshHandlerName)
	require.NoError(t, err)
	return h
}

func TestRegistered_ExactlyOnceAndLookedUpByName(t *testing.T) {
	require.NotNil(t, registered(t))
	assert.ErrorIs(t, proxy.RegisterHandler(proxy.SshHandlerName, handleProxy), proxy.ErrProtocolAlreadyRegistered)
	_, err := proxy.LookupHandler("nope")
	assert.ErrorIs(t, err, proxy.ErrUnknownProtocol)
}

func TestHandler_RefusesBeforeRelay(t *testing.T) {
	ctx := context.Background()
	pb, err := anypb.New(&emptypb.Empty{})
	require.NoError(t, err)
	good := func(t *testing.T) SessionConfig {
		return SessionConfig{
			Authorization: Authorization{SessionId: "s_1", ConnectionId: "sc_1", Expiry: time.Now().Add(time.Minute)},
			ClientHostKey: newSigner(t),
			UpstreamAddr:  "127.0.0.1:1",
			HostKeys:      pinned(newSigner(t)),
		}
	}
	tests := []struct {
		name    string
		pb      *anypb.Any
		connId  string
		decoder func(t *testing.T) InputDecoder
	}{
		{"default decoder refuses", pb, "sc_1", nil},
		{"nil input", nil, "sc_1", func(t *testing.T) InputDecoder {
			return func(context.Context, proxy.DecryptFn, *anypb.Any) (SessionConfig, []HandleOption, error) {
				return good(t), nil, nil
			}
		}},
		{"undecodable", pb, "sc_1", func(t *testing.T) InputDecoder {
			return func(context.Context, proxy.DecryptFn, *anypb.Any) (SessionConfig, []HandleOption, error) {
				return SessionConfig{}, nil, assert.AnError
			}
		}},
		{"empty host key policy", pb, "sc_1", func(t *testing.T) InputDecoder {
			return func(context.Context, proxy.DecryptFn, *anypb.Any) (SessionConfig, []HandleOption, error) {
				c := good(t)
				c.HostKeys = hostkey.Policy{}
				return c, nil, nil
			}
		}},
		{"connection id mismatch", pb, "sc_other", func(t *testing.T) InputDecoder {
			return func(context.Context, proxy.DecryptFn, *anypb.Any) (SessionConfig, []HandleOption, error) {
				return good(t), nil, nil
			}
		}},
		{"empty connection id", pb, "", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.decoder != nil {
				withDecoder(t, tc.decoder(t))
			}
			c1, c2 := net.Pipe()
			defer c1.Close()
			fn, err := registered(t)(ctx, ctx, nil, c2, nil, tc.connId, tc.pb, nil)
			require.Error(t, err)
			assert.Nil(t, fn)
			// The conn was closed and nothing was written to the client.
			_ = c1.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, rerr := c1.Read(make([]byte, 1))
			assert.Zero(t, n)
			assert.Error(t, rerr)
		})
	}
}

func TestHandler_ValidPolicyReachesUpstream(t *testing.T) {
	ctx := context.Background()
	pt := newPasswordTarget(t)
	clientKey := newSigner(t)
	withDecoder(t, func(context.Context, proxy.DecryptFn, *anypb.Any) (SessionConfig, []HandleOption, error) {
		return SessionConfig{
			Authorization: okAuth(),
			ClientHostKey: clientKey,
			UpstreamAddr:  pt.addr,
			Credential:    injectauth.Input{Username: testUpstreamUser, Password: testUpstreamPass},
			HostKeys:      pinned(pt.hostKey),
		}, nil, nil
	})
	pb, err := anypb.New(&emptypb.Empty{})
	require.NoError(t, err)

	c1, c2 := tcpPair(t)
	fn, err := registered(t)(ctx, ctx, nil, c2, nil, okAuth().ConnectionId, pb, nil)
	require.NoError(t, err)
	require.NotNil(t, fn)
	done := make(chan struct{})
	go func() { fn(); close(done) }()

	sc, chans, reqs, err := ssh.NewClientConn(c1, "worker", &ssh.ClientConfig{
		User:            "anyone",
		HostKeyCallback: ssh.FixedHostKey(clientKey.PublicKey()),
		Timeout:         5 * time.Second,
	})
	require.NoError(t, err)
	client := ssh.NewClient(sc, chans, reqs)
	sess, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, sess.Start("hello"))
	assert.EqualValues(t, 1, pt.authTrys.Load())
	client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not return")
	}
}

// TestNoInsecureHostKeyCallback enforces the security decision on #6: no
// non-test code in the ssh proxy tree may skip host key verification.
func TestNoInsecureHostKeyCallback(t *testing.T) {
	err := filepath.WalkDir(".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		assert.NotContains(t, string(b), "InsecureIgnoreHostKey", p)
		return nil
	})
	require.NoError(t, err)
}
