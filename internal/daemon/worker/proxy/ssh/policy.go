// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"context"
	"slices"

	"github.com/hashicorp/boundary/internal/errors"
)

// DefaultMaxChannels is the default cap on concurrently open channels per
// client connection.
const DefaultMaxChannels = 10

// Policy controls what the client may open or request through the proxy. The
// zero value is not used directly; use DefaultPolicy and adjust it. Anything
// not explicitly allowed is denied.
type Policy struct {
	// AllowedChannelTypes are the channel types the client may open.
	AllowedChannelTypes []string
	// AllowedChannelRequests are the per-channel request types the client may
	// send (for example "exec" or "x11-req").
	AllowedChannelRequests []string
	// AllowedUpstreamRequests are the per-channel request types accepted from
	// the target and relayed to the client.
	AllowedUpstreamRequests []string
	// AllowedGlobalRequests are the connection-level request types (for
	// example "tcpip-forward") that are forwarded to the target.
	AllowedGlobalRequests []string
	// MaxChannels caps concurrently open channels per connection. Must be
	// greater than zero.
	MaxChannels int
}

// DefaultPolicy returns the conservative default: interactive session
// channels only, no forwarding of any kind, no agent or X11 forwarding, no
// global requests, and at most DefaultMaxChannels concurrent channels.
func DefaultPolicy() Policy {
	return Policy{
		AllowedChannelTypes: []string{"session"},
		AllowedChannelRequests: []string{
			"pty-req", "shell", "exec", "subsystem", "env", "window-change",
			"signal", "eow@openssh.com", "keepalive@openssh.com",
		},
		AllowedUpstreamRequests: []string{
			"exit-status", "exit-signal", "eow@openssh.com", "keepalive@openssh.com",
		},
		MaxChannels: DefaultMaxChannels,
	}
}

func (p Policy) validate(ctx context.Context) error {
	const op = "ssh.Policy.validate"
	if p.MaxChannels <= 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "max channels must be greater than zero")
	}
	return nil
}

func (p Policy) allowChannelType(t string) bool { return slices.Contains(p.AllowedChannelTypes, t) }
func (p Policy) allowChannelRequest(t string) bool {
	return slices.Contains(p.AllowedChannelRequests, t)
}
func (p Policy) allowUpstreamRequest(t string) bool {
	return slices.Contains(p.AllowedUpstreamRequests, t)
}
func (p Policy) allowGlobalRequest(t string) bool { return slices.Contains(p.AllowedGlobalRequests, t) }

// Option configures Serve.
type Option func(*options)

type options struct {
	policy Policy
}

func getOpts(opt ...Option) options {
	o := options{policy: DefaultPolicy()}
	for _, f := range opt {
		f(&o)
	}
	return o
}

// WithPolicy replaces the default Policy. Serve fails closed if the policy is
// invalid.
func WithPolicy(p Policy) Option {
	return func(o *options) { o.policy = p }
}
