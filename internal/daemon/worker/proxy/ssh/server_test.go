// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync/atomic"
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

// fakeTarget is an in-process SSH server that echoes session channel data
// and acknowledges "exec" requests.
type fakeTarget struct {
	hostKey  ssh.Signer
	dials    atomic.Int32
	closed   chan struct{}
	failDial bool
}

func newFakeTarget(t *testing.T) *fakeTarget {
	return &fakeTarget{hostKey: newSigner(t), closed: make(chan struct{}, 8)}
}

func (f *fakeTarget) Dial(ctx context.Context) (UpstreamConn, error) {
	f.dials.Add(1)
	if f.failDial {
		return nil, errors.New("dial failed")
	}
	c1, c2 := tcpPair(nil)
	go f.serve(c2)
	sc, chans, reqs, err := ssh.NewClientConn(c1, "target", &ssh.ClientConfig{
		User:            "u",
		HostKeyCallback: ssh.FixedHostKey(f.hostKey.PublicKey()),
	})
	if err != nil {
		return nil, err
	}
	go ssh.DiscardRequests(reqs)
	go func() {
		for nc := range chans {
			_ = nc.Reject(ssh.Prohibited, "no")
		}
	}()
	return &closeNotify{Conn: sc, f: f}, nil
}

type closeNotify struct {
	ssh.Conn
	f *fakeTarget
}

func (c *closeNotify) Close() error {
	err := c.Conn.Close()
	select {
	case c.f.closed <- struct{}{}:
	default:
	}
	return err
}

func (f *fakeTarget) serve(c net.Conn) {
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(f.hostKey)
	_, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
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
		go func() {
			_, _ = io.Copy(ch, ch)
			_ = ch.Close()
		}()
	}
}

func okAuth() Authorization {
	return Authorization{SessionId: "s_1", ConnectionId: "sc_1", Expiry: time.Now().Add(time.Minute)}
}

// startServe runs Serve on one end of a pipe and returns a connected client.
func startServe(t *testing.T, ctx context.Context, auth Authorization, up Upstream) (*ssh.Client, <-chan error) {
	t.Helper()
	hostKey := newSigner(t)
	c1, c2 := tcpPair(t)
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, c2, hostKey, auth, up) }()
	sc, chans, reqs, err := ssh.NewClientConn(c1, "worker", &ssh.ClientConfig{
		User:            "anyone",
		HostKeyCallback: ssh.FixedHostKey(hostKey.PublicKey()),
		Timeout:         5 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { sc.Close() })
	return ssh.NewClient(sc, chans, reqs), done
}

func TestServe_Bridges(t *testing.T) {
	ft := newFakeTarget(t)
	client, done := startServe(t, context.Background(), okAuth(), ft)

	sess, err := client.NewSession()
	require.NoError(t, err)
	stdin, err := sess.StdinPipe()
	require.NoError(t, err)
	stdout, err := sess.StdoutPipe()
	require.NoError(t, err)

	// requests are forwarded and replies come from the target
	ok, err := sess.SendRequest("exec", true, nil)
	require.NoError(t, err)
	assert.True(t, ok)
	ok, err = sess.SendRequest("bogus", true, nil)
	require.NoError(t, err)
	assert.False(t, ok)

	_, err = stdin.Write([]byte("hello"))
	require.NoError(t, err)
	buf := make([]byte, 5)
	_, err = io.ReadFull(stdout, buf)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), buf)
	assert.Equal(t, int32(1), ft.dials.Load())

	// closing the client ends Serve and closes the upstream
	require.NoError(t, client.Close())
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
	select {
	case <-ft.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream not closed")
	}
}

func TestServe_RejectsBadAuthorization(t *testing.T) {
	past := okAuth()
	past.Expiry = time.Now().Add(-time.Second)
	noSession := okAuth()
	noSession.SessionId = ""
	noConn := okAuth()
	noConn.ConnectionId = ""
	for name, a := range map[string]Authorization{
		"empty": {}, "expired": past, "no session": noSession, "no connection": noConn,
	} {
		t.Run(name, func(t *testing.T) {
			ft := newFakeTarget(t)
			c1, c2 := tcpPair(t)
			defer c1.Close()
			err := Serve(context.Background(), c2, newSigner(t), a, ft)
			require.Error(t, err)
			assert.Zero(t, ft.dials.Load(), "must not dial upstream")
			// server side is closed: no SSH handshake possible
			_ = c1.SetReadDeadline(time.Now().Add(time.Second))
			_, rerr := c1.Read(make([]byte, 1))
			assert.Error(t, rerr)
		})
	}
}

func TestServe_CancelledContextAtStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ft := newFakeTarget(t)
	_, c2 := tcpPair(t)
	require.Error(t, Serve(ctx, c2, newSigner(t), okAuth(), ft))
	assert.Zero(t, ft.dials.Load())
}

func TestServe_NilArgs(t *testing.T) {
	_, c := tcpPair(t)
	assert.Error(t, Serve(context.Background(), c, nil, okAuth(), newFakeTarget(t)))
	_, c = tcpPair(t)
	assert.Error(t, Serve(context.Background(), c, newSigner(t), okAuth(), nil))
}

func TestServe_ContextCancelClosesBothLegs(t *testing.T) {
	ft := newFakeTarget(t)
	ctx, cancel := context.WithCancel(context.Background())
	client, done := startServe(t, ctx, okAuth(), ft)
	sess, err := client.NewSession()
	require.NoError(t, err)
	_, err = sess.SendRequest("exec", true, nil)
	require.NoError(t, err)

	cancel()
	select {
	case err := <-done:
		assert.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after cancel")
	}
	select {
	case <-ft.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream not closed")
	}
	assert.Error(t, client.Wait(), "client leg must be closed")
}

func TestServe_ExpiryClosesConnection(t *testing.T) {
	ft := newFakeTarget(t)
	a := okAuth()
	a.Expiry = time.Now().Add(300 * time.Millisecond)
	client, done := startServe(t, context.Background(), a, ft)
	_, err := client.NewSession()
	require.NoError(t, err)
	select {
	case err := <-done:
		assert.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return at expiry")
	}
}

func TestServe_UpstreamDialFailureClosesClient(t *testing.T) {
	ft := newFakeTarget(t)
	ft.failDial = true
	client, done := startServe(t, context.Background(), okAuth(), ft)
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
	assert.Error(t, client.Wait())
}

func TestServe_NoSecretInErrors(t *testing.T) {
	a := okAuth()
	a.Expiry = time.Time{}
	err := Serve(context.Background(), mustPipe(), newSigner(t), a, newFakeTarget(t))
	require.Error(t, err)
	assert.False(t, bytes.Contains([]byte(err.Error()), []byte("PRIVATE KEY")))
}

func mustPipe() net.Conn { _, c := tcpPair(nil); return c }

// tcpPair returns both ends of a loopback TCP connection. net.Pipe is
// unsuitable for SSH because both sides write their version first.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	if t != nil {
		t.Helper()
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer l.Close()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() { c, err := l.Accept(); ch <- res{c, err} }()
	c1, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		panic(err)
	}
	r := <-ch
	if r.err != nil {
		panic(r.err)
	}
	return c1, r.c
}
