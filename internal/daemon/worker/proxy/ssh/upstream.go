// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"context"
	"net"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh/injectauth"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/target/ssh/hostkeypolicy"
	"golang.org/x/crypto/ssh"
)

const upstreamDialTimeout = 30 * time.Second

// ClientUpstream is an Upstream that dials a target SSH server with injected
// credentials. The host key of the target is always verified with the
// mandatory HostKeyCallback before any authentication is attempted.
type ClientUpstream struct {
	addr   string
	config *ssh.ClientConfig
}

// NewClientUpstream returns an Upstream that dials addr, which must come from
// the session's resolved address and never from client input. hostKeyCallback
// is required: a nil callback is an error and there is no way to disable host
// key verification. cred supplies the username and the password and/or
// private key; its PrivateKey and Passphrase buffers are zeroed once parsed,
// so the caller must not reuse them. The Password is held as a string and
// cannot be zeroed. Errors never contain credential material.
func NewClientUpstream(ctx context.Context, addr string, cred injectauth.Input, hostKeyCallback ssh.HostKeyCallback) (*ClientUpstream, error) {
	const op = "ssh.NewClientUpstream"
	if addr == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing upstream address")
	}
	if hostKeyCallback == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing host key callback")
	}
	user, methods, err := injectauth.AuthMethods(cred)
	clear(cred.PrivateKey)
	clear(cred.Passphrase)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.InvalidParameter))
	}
	return &ClientUpstream{
		addr: addr,
		config: &ssh.ClientConfig{
			User:              user,
			Auth:              methods,
			HostKeyCallback:   hostKeyCallback,
			HostKeyAlgorithms: hostkeypolicy.HostKeyAlgorithms(),
			Timeout:           upstreamDialTimeout,
		},
	}, nil
}

// Dial connects to the target. The returned UpstreamConn rejects every
// channel the target tries to open (for example agent forwarding) and denies
// target-initiated global requests.
func (u *ClientUpstream) Dial(ctx context.Context) (UpstreamConn, error) {
	const op = "ssh.ClientUpstream.Dial"
	d := net.Dialer{Timeout: upstreamDialTimeout}
	nc, err := d.DialContext(ctx, "tcp", u.addr)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("dialing target"))
	}
	// Closing nc unblocks the handshake if ctx ends while it is running.
	stop := context.AfterFunc(ctx, func() { nc.Close() })
	defer stop()

	sc, chans, reqs, err := ssh.NewClientConn(nc, u.addr, u.config)
	if err != nil {
		nc.Close()
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("ssh handshake"))
	}
	go func() {
		for c := range chans {
			_ = c.Reject(ssh.Prohibited, "channel not permitted")
		}
	}()
	go func() {
		for r := range reqs {
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
		}
	}()
	return sc, nil
}
