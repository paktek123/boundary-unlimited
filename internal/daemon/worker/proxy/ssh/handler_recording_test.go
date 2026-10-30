// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh/injectauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// fnFactory adapts a function to a RecordingFactory.
type fnFactory func(ctx context.Context, auth Authorization, inner Upstream) (Upstream, error)

func (f fnFactory) Wrap(ctx context.Context, auth Authorization, inner Upstream) (Upstream, error) {
	return f(ctx, auth, inner)
}

// teeUpstream counts the connections dialled through it.
type teeUpstream struct {
	Upstream
	dials int
}

func (u *teeUpstream) Dial(ctx context.Context) (UpstreamConn, error) {
	u.dials++
	return u.Upstream.Dial(ctx)
}

func recCfg(t *testing.T, addr string, hostKey ssh.Signer, rep Reporter) SessionConfig {
	t.Helper()
	return SessionConfig{
		Authorization: okAuth(),
		ClientHostKey: newSigner(t),
		UpstreamAddr:  addr,
		Credential:    injectauth.Input{Username: testUpstreamUser, Password: testUpstreamPass},
		HostKeys:      pinned(hostKey),
		TargetId:      reportTargetId,
		Reporter:      rep,
	}
}

// dialClient connects an SSH client to the worker end of a pair.
func dialClient(t *testing.T, c net.Conn, cfg SessionConfig) *ssh.Client {
	t.Helper()
	sc, chans, reqs, err := ssh.NewClientConn(c, "worker", &ssh.ClientConfig{
		User:            "anyone",
		HostKeyCallback: ssh.FixedHostKey(cfg.ClientHostKey.PublicKey()),
		Timeout:         5 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { sc.Close() })
	return ssh.NewClient(sc, chans, reqs)
}

func TestHandleSession_Recording_NoFactoryUnchanged(t *testing.T) {
	pt := newPasswordTarget(t)
	client, done := startHandle(t, recCfg(t, pt.addr, pt.hostKey, nil))
	sess, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, sess.Start("hello"))
	client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("HandleSession did not return")
	}
}

func TestHandleSession_Recording_FactoryWrapsUpstream(t *testing.T) {
	pt := newPasswordTarget(t)
	var tee *teeUpstream
	var gotAuth Authorization
	f := fnFactory(func(_ context.Context, auth Authorization, inner Upstream) (Upstream, error) {
		gotAuth = auth
		tee = &teeUpstream{Upstream: inner}
		return tee, nil
	})
	cfg := recCfg(t, pt.addr, pt.hostKey, nil)
	c1, c2 := tcpPair(t)
	done := make(chan error, 1)
	go func() { done <- HandleSession(context.Background(), c2, cfg, WithRecordingFactory(f)) }()
	client := dialClient(t, c1, cfg)
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
	require.NotNil(t, tee)
	assert.Equal(t, 1, tee.dials, "session must be relayed through the wrapped upstream")
	assert.Equal(t, cfg.Authorization.SessionId, gotAuth.SessionId)
}

func TestHandleSession_Recording_FactoryFailureRefusesBeforeDial(t *testing.T) {
	tests := []struct {
		name string
		f    RecordingFactory
	}{
		{"error", fnFactory(func(context.Context, Authorization, Upstream) (Upstream, error) {
			return nil, errors.New("no recording capacity")
		})},
		{"nil upstream", fnFactory(func(context.Context, Authorization, Upstream) (Upstream, error) {
			return nil, nil
		})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, dials := countingListener(t)
			pt := newPasswordTarget(t)
			rep := &fakeReporter{}
			cfg := recCfg(t, pt.addr, pt.hostKey, rep)
			cfg.UpstreamAddr = addr
			c1, c2 := tcpPair(t)
			defer c1.Close()
			err := HandleSession(context.Background(), c2, cfg, WithRecordingFactory(tt.f))
			require.Error(t, err)
			assert.NotContains(t, err.Error(), testUpstreamPass)
			assert.Zero(t, dials.Load(), "upstream must never be dialled")
			assert.Zero(t, pt.authTrys.Load())
			assert.Equal(t, [][2]string{{reportTargetId, ReasonRecordingUnavailable}}, rep.rejected)
			// conn was closed before any SSH data was relayed.
			_ = c1.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, rerr := c1.Read(make([]byte, 1))
			assert.Error(t, rerr)
		})
	}
}

// TestHandleSession_Recording_WriteFailureTerminatesSession wires the real
// recording wrapper through the factory and checks that a recording failure
// mid-session ends the session.
func TestHandleSession_Recording_WriteFailureTerminatesSession(t *testing.T) {
	pt := newPtyTarget(t)
	h, _ := newRecHarness(t, 64<<10, 8<<10, nil)
	f := fnFactory(func(ctx context.Context, _ Authorization, inner Upstream) (Upstream, error) {
		return NewRecordingUpstream(ctx, inner, h.deps)
	})
	cfg := recCfg(t, pt.addr, pt.hostKey, nil)
	c1, c2 := tcpPair(t)
	done := make(chan error, 1)
	go func() { done <- HandleSession(context.Background(), c2, cfg, WithRecordingFactory(f)) }()
	client := dialClient(t, c1, cfg)
	closeClient := func() { _ = client.Close() }
	h.term.onTerminate.Store(&closeClient)
	sess, err := client.NewSession()
	require.NoError(t, err)
	stdin, err := sess.StdinPipe()
	require.NoError(t, err)
	require.NoError(t, sess.Start("cat"))
	chunk := make([]byte, 16<<10)
	_, err = rand.Read(chunk)
	require.NoError(t, err)
	go func() {
		for i := 0; i < 64; i++ {
			if _, err := stdin.Write(chunk); err != nil {
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("HandleSession did not return after the recording failed")
	}
	assert.EqualValues(t, 1, h.term.calls.Load(), "terminator called exactly once")
	assert.EqualValues(t, 1, h.mark.calls.Load(), "recording marked incomplete exactly once")
}
