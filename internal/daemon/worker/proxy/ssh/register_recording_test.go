// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package ssh

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/worker/proxy"
	"github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh/injectauth"
	"github.com/hashicorp/boundary/internal/daemon/worker/recording/scratch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"
)

type countingFactory struct{ wraps atomic.Int32 }

func (f *countingFactory) Wrap(_ context.Context, _ Authorization, inner Upstream) (Upstream, error) {
	f.wraps.Add(1)
	return inner, nil
}

func recDecoder(t *testing.T, addr string, key ssh.Signer, hk ssh.Signer, rec bool) InputDecoder {
	return func(context.Context, proxy.DecryptFn, *anypb.Any) (SessionConfig, []HandleOption, error) {
		return SessionConfig{
			Authorization:    okAuth(),
			ClientHostKey:    key,
			UpstreamAddr:     addr,
			Credential:       injectauth.Input{Username: testUpstreamUser, Password: testUpstreamPass},
			HostKeys:         pinned(hk),
			RecordingEnabled: rec,
		}, nil, nil
	}
}

func TestHandler_RecordingEnabledWithoutFactoryIsRefused(t *testing.T) {
	ctx := context.Background()
	InstallRecordingFactory(nil)
	pt := newPasswordTarget(t)
	withDecoder(t, recDecoder(t, pt.addr, newSigner(t), pt.hostKey, true))
	pb, err := anypb.New(&emptypb.Empty{})
	require.NoError(t, err)
	c1, c2 := net.Pipe()
	defer c1.Close()
	fn, err := registered(t)(ctx, ctx, nil, c2, nil, okAuth().ConnectionId, pb, nil)
	require.Error(t, err)
	assert.Nil(t, fn)
	_ = c1.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, rerr := c1.Read(make([]byte, 1))
	assert.Zero(t, n)
	assert.Error(t, rerr)
	assert.Zero(t, pt.authTrys.Load(), "upstream must never be dialled")
}

func TestHandler_RecordingEnabledUsesFactory(t *testing.T) {
	ctx := context.Background()
	f := &countingFactory{}
	InstallRecordingFactory(f)
	t.Cleanup(func() { InstallRecordingFactory(nil) })
	pt := newPasswordTarget(t)
	clientKey := newSigner(t)
	withDecoder(t, recDecoder(t, pt.addr, clientKey, pt.hostKey, true))
	pb, err := anypb.New(&emptypb.Empty{})
	require.NoError(t, err)

	c1, c2 := tcpPair(t)
	fn, err := registered(t)(ctx, ctx, nil, c2, nil, okAuth().ConnectionId, pb, nil)
	require.NoError(t, err)
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	sc, chans, reqs, err := ssh.NewClientConn(c1, "worker", &ssh.ClientConfig{
		User: "anyone", HostKeyCallback: ssh.FixedHostKey(clientKey.PublicKey()), Timeout: 5 * time.Second,
	})
	require.NoError(t, err)
	ssh.NewClient(sc, chans, reqs).Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not return")
	}
	assert.EqualValues(t, 1, f.wraps.Load())
}

func TestHandler_RecordingDisabledIgnoresFactory(t *testing.T) {
	ctx := context.Background()
	f := &countingFactory{}
	InstallRecordingFactory(f)
	t.Cleanup(func() { InstallRecordingFactory(nil) })
	pt := newPasswordTarget(t)
	clientKey := newSigner(t)
	withDecoder(t, recDecoder(t, pt.addr, clientKey, pt.hostKey, false))
	pb, err := anypb.New(&emptypb.Empty{})
	require.NoError(t, err)
	c1, c2 := tcpPair(t)
	fn, err := registered(t)(ctx, ctx, nil, c2, nil, okAuth().ConnectionId, pb, nil)
	require.NoError(t, err)
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	sc, chans, reqs, err := ssh.NewClientConn(c1, "worker", &ssh.ClientConfig{
		User: "anyone", HostKeyCallback: ssh.FixedHostKey(clientKey.PublicKey()), Timeout: 5 * time.Second,
	})
	require.NoError(t, err)
	ssh.NewClient(sc, chans, reqs).Close()
	<-done
	assert.Zero(t, f.wraps.Load())
}

func TestRecoverScratch(t *testing.T) {
	_, err := RecoverScratch(context.Background(), nil)
	require.Error(t, err)
	s, err := scratch.New(t.TempDir(), 1<<20)
	require.NoError(t, err)
	orphans, err := RecoverScratch(context.Background(), s)
	require.NoError(t, err)
	assert.Empty(t, orphans)
}
