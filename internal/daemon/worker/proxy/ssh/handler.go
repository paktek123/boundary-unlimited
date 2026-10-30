// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"context"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh/hostkey"
	"github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh/injectauth"
	"github.com/hashicorp/boundary/internal/errors"
	"golang.org/x/crypto/ssh"
)

// SessionConfig carries everything HandleSession needs as plain values. It is
// copied on entry, so the caller may reuse or mutate it afterwards without
// affecting a running session.
type SessionConfig struct {
	// Authorization is the caller's authorization of the session connection.
	Authorization Authorization
	// ClientHostKey is the ephemeral host key presented to the connecting
	// client. Required.
	ClientHostKey ssh.Signer
	// UpstreamAddr is the resolved host:port of the target. It must come from
	// the authorized session, never from client input. Required.
	UpstreamAddr string
	// Credential is the injected credential used to authenticate to the
	// target. Its PrivateKey and Passphrase are copied and the copies zeroed
	// once parsed; the caller's buffers are left untouched.
	Credential injectauth.Input
	// HostKeys is the snapshot of the target's host key policy (pinned host
	// keys and/or host CAs). An empty policy is rejected: there is no
	// trust-on-first-use and no way to skip host key verification.
	HostKeys hostkey.Policy
	// Policy restricts what the client may open or request. The zero value
	// selects DefaultPolicy.
	Policy Policy
	// TargetId identifies the target in reported events.
	TargetId string
	// Reporter receives host key verification failures and rejected
	// sessions. Nil means no reporting. A slow or panicking Reporter never
	// stops a session from being refused.
	Reporter Reporter
}

// RecordingFactory wraps the session's upstream so the session is recorded.
// It is called once per session, after the configuration has been validated
// and before the upstream is dialled. Returning an error (or a nil Upstream)
// makes HandleSession refuse the session before any data is relayed.
// Implementations must not return a typed nil pointer wrapped in a non-nil
// Upstream interface together with a nil error; only an untyped nil is
// detected and refused.
type RecordingFactory interface {
	Wrap(ctx context.Context, auth Authorization, inner Upstream) (Upstream, error)
}

// HandleOption configures HandleSession.
type HandleOption func(*handleOptions)

type handleOptions struct {
	recording RecordingFactory
}

// WithRecordingFactory makes HandleSession wrap its upstream with f. Without
// it, sessions are relayed unrecorded exactly as before. A nil f is ignored.
func WithRecordingFactory(f RecordingFactory) HandleOption {
	return func(o *handleOptions) { o.recording = f }
}

// HandleSession is the single entry point for one proxied SSH connection. It
// validates cfg, builds the mandatory host key callback from the host key
// policy snapshot and the upstream from the injected credential, and then runs
// Serve on conn. Every validation failure is returned before any connection to
// the target is attempted, and conn is always closed.
//
// HandleSession is not called by the worker yet, so nothing is enabled by its
// existence.
func HandleSession(ctx context.Context, conn net.Conn, cfg SessionConfig, opt ...HandleOption) error {
	const op = "ssh.HandleSession"
	defer conn.Close()
	var opts handleOptions
	for _, o := range opt {
		o(&opts)
	}

	// Snapshot everything the session depends on before doing anything else.
	pol := snapshotPolicy(cfg.Policy)
	hk := hostkey.Policy{
		PinnedKeys: slices.Clone(cfg.HostKeys.PinnedKeys),
		HostCAs:    slices.Clone(cfg.HostKeys.HostCAs),
	}
	rep := newSafeReporter(cfg.Reporter)
	rejected := func(reason string) { rep.SessionRejected(ctx, cfg.TargetId, reason) }
	cred := cfg.Credential
	cred.PrivateKey = slices.Clone(cred.PrivateKey)
	cred.Passphrase = slices.Clone(cred.Passphrase)
	defer func() {
		clear(cred.PrivateKey)
		clear(cred.Passphrase)
	}()

	if err := cfg.Authorization.validate(ctx, time.Now()); err != nil {
		rejected(ReasonInvalidAuthorization)
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.InvalidParameter))
	}
	if cfg.ClientHostKey == nil {
		rejected(ReasonMissingClientHostKey)
		return errors.New(ctx, errors.InvalidParameter, op, "missing client-facing host key")
	}
	if cfg.UpstreamAddr == "" {
		rejected(ReasonMissingUpstreamAddr)
		return errors.New(ctx, errors.InvalidParameter, op, "missing upstream address")
	}
	if len(hk.PinnedKeys) == 0 && len(hk.HostCAs) == 0 {
		rejected(ReasonEmptyHostKeyPolicy)
		return errors.New(ctx, errors.InvalidParameter, op, "empty upstream host key policy")
	}
	if err := pol.validate(ctx); err != nil {
		rejected(ReasonInvalidSessionPolicy)
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.InvalidParameter))
	}
	cb, err := hostkey.New(hk)
	if err != nil {
		rejected(ReasonInvalidHostKeyPolicy)
		return errors.Wrap(ctx, err, op, errors.WithMsg("invalid upstream host key policy"), errors.WithCode(errors.InvalidParameter))
	}
	var failOnce sync.Once
	reportingCb := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := cb(hostname, remote, key)
		if err != nil {
			failOnce.Do(func() { rep.HostKeyFailure(ctx, cfg.TargetId, ssh.FingerprintSHA256(key)) })
		}
		return err
	}
	up, err := NewClientUpstream(ctx, cfg.UpstreamAddr, cred, reportingCb)
	if err != nil {
		rejected(ReasonInvalidCredential)
		return errors.Wrap(ctx, err, op)
	}
	var upstream Upstream = up
	if opts.recording != nil {
		wrapped, err := opts.recording.Wrap(ctx, cfg.Authorization, up)
		if err != nil {
			rejected(ReasonRecordingUnavailable)
			return errors.Wrap(ctx, err, op, errors.WithMsg("recording unavailable"))
		}
		if wrapped == nil {
			rejected(ReasonRecordingUnavailable)
			return errors.New(ctx, errors.Internal, op, "recording factory returned no upstream")
		}
		upstream = wrapped
	}
	return Serve(ctx, conn, cfg.ClientHostKey, cfg.Authorization, upstream, WithPolicy(pol))
}

// snapshotPolicy returns a deep copy of p, or DefaultPolicy for the zero
// value.
func snapshotPolicy(p Policy) Policy {
	if p.MaxChannels == 0 && len(p.AllowedChannelTypes) == 0 && len(p.AllowedChannelRequests) == 0 &&
		len(p.AllowedUpstreamRequests) == 0 && len(p.AllowedGlobalRequests) == 0 {
		return DefaultPolicy()
	}
	return Policy{
		AllowedChannelTypes:     slices.Clone(p.AllowedChannelTypes),
		AllowedChannelRequests:  slices.Clone(p.AllowedChannelRequests),
		AllowedUpstreamRequests: slices.Clone(p.AllowedUpstreamRequests),
		AllowedGlobalRequests:   slices.Clone(p.AllowedGlobalRequests),
		MaxChannels:             p.MaxChannels,
	}
}
