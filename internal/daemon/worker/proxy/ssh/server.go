// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package ssh contains the client-facing SSH server of the worker SSH proxy.
//
// The server terminates the user's SSH connection on the worker. It performs no
// client authentication of its own: the caller must already have authenticated
// the Boundary session and passes the resulting Authorization. The server is
// fail-closed: a missing, expired or cancelled authorization never results in
// a bridged connection.
//
// This package is not registered with the worker proxy handler, so nothing is
// enabled by its existence.
package ssh

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"golang.org/x/crypto/ssh"
)

const handshakeTimeout = 30 * time.Second

// Authorization is the result of the caller having authorized a Boundary
// session connection.
type Authorization struct {
	SessionId    string
	ConnectionId string
	Expiry       time.Time
}

func (a Authorization) validate(ctx context.Context, now time.Time) error {
	const op = "ssh.Authorization.validate"
	switch {
	case a.SessionId == "":
		return errors.New(ctx, errors.InvalidParameter, op, "missing session id")
	case a.ConnectionId == "":
		return errors.New(ctx, errors.InvalidParameter, op, "missing connection id")
	case a.Expiry.IsZero() || !now.Before(a.Expiry):
		return errors.New(ctx, errors.InvalidParameter, op, "authorization expired or missing expiry")
	}
	return nil
}

// UpstreamConn is the worker-to-target SSH connection, a subset of ssh.Conn.
// Implementations must reject every channel the target tries to open towards
// the worker (for example agent forwarding); Serve never relays them.
type UpstreamConn interface {
	OpenChannel(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error)
	SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error)
	Close() error
}

// Upstream dials the target.
type Upstream interface {
	Dial(ctx context.Context) (UpstreamConn, error)
}

// Serve runs the client-facing SSH server on conn and bridges the client's
// channels and requests to the upstream until the client disconnects, ctx is
// cancelled, or auth expires. Serve always closes conn and any upstream
// connection before returning. Server-initiated channels from the upstream
// are not forwarded. Channel types, channel requests and global requests not
// allowed by the Policy (default: DefaultPolicy) are rejected, and the number
// of concurrently open channels is capped.
func Serve(ctx context.Context, conn net.Conn, hostKey ssh.Signer, auth Authorization, up Upstream, opt ...Option) error {
	const op = "ssh.Serve"
	defer conn.Close()
	opts := getOpts(opt...)
	if err := opts.policy.validate(ctx); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if hostKey == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing host key")
	}
	if up == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing upstream")
	}
	if err := auth.validate(ctx, time.Now()); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if err := ctx.Err(); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	ctx, cancel := context.WithDeadline(ctx, auth.Expiry)
	defer cancel()
	// Closing conn unblocks the handshake and all later reads.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(hostKey)
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("handshake"))
	}
	_ = conn.SetDeadline(time.Time{})
	defer sconn.Close()

	upConn, err := up.Dial(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("dialing upstream"))
	}
	defer upConn.Close()
	// Closing upstream when the context ends unblocks any pending copies.
	stopUp := context.AfterFunc(ctx, func() { upConn.Close() })
	defer stopUp()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		forwardGlobal(reqs, upConn, opts.policy)
	}()
	slots := make(chan struct{}, opts.policy.MaxChannels)
	for nc := range chans {
		if ctx.Err() != nil {
			_ = nc.Reject(ssh.ConnectionFailed, "session no longer authorized")
			continue
		}
		if !opts.policy.allowChannelType(nc.ChannelType()) {
			_ = nc.Reject(ssh.Prohibited, "channel type not allowed")
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = nc.Reject(ssh.ResourceShortage, "too many open channels")
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			bridgeChannel(nc, upConn, opts.policy)
		}()
	}
	// chans is closed once the client connection is gone.
	sconn.Close()
	upConn.Close()
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

func forwardGlobal(reqs <-chan *ssh.Request, up UpstreamConn, p Policy) {
	for r := range reqs {
		if !p.allowGlobalRequest(r.Type) {
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
			continue
		}
		ok, payload, err := up.SendRequest(r.Type, r.WantReply, r.Payload)
		if r.WantReply {
			_ = r.Reply(ok && err == nil, payload)
		}
	}
}

func bridgeChannel(nc ssh.NewChannel, up UpstreamConn, p Policy) {
	upCh, upReqs, err := up.OpenChannel(nc.ChannelType(), nc.ExtraData())
	if err != nil {
		if oe, ok := err.(*ssh.OpenChannelError); ok {
			_ = nc.Reject(oe.Reason, oe.Message)
		} else {
			_ = nc.Reject(ssh.ConnectionFailed, "upstream channel open failed")
		}
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		_ = upCh.Close()
		return
	}

	var wg sync.WaitGroup
	wg.Add(4)
	go func() { defer wg.Done(); proxyRequests(reqs, upCh, p.allowChannelRequest) }()
	go func() { defer wg.Done(); proxyRequests(upReqs, ch, p.allowUpstreamRequest) }()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upCh, ch)
		_ = upCh.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(ch, upCh)
		_ = ch.CloseWrite()
	}()
	wg.Wait()
	_ = ch.Close()
	_ = upCh.Close()
}

type requester interface {
	SendRequest(name string, wantReply bool, payload []byte) (bool, error)
}

func proxyRequests(in <-chan *ssh.Request, out requester, allow func(string) bool) {
	for r := range in {
		if !allow(r.Type) {
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
			continue
		}
		ok, err := out.SendRequest(r.Type, r.WantReply, r.Payload)
		if r.WantReply {
			_ = r.Reply(ok && err == nil, nil)
		}
	}
}
