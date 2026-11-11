// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package ssh

import (
	"context"
	"net"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh/hostkey"
	"github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh/injectauth"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/masking"
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
	// RecordingEnabled is set by the session input decoder when the
	// authorized session requires recording. The registered worker handler
	// then fails closed unless a recording factory is installed.
	RecordingEnabled bool
	// Masking, when non-nil, is set by the session input decoder when the
	// authorized session requires masking. The registered worker handler then
	// compiles the effective policy and fails closed (refuses the session)
	// when the policy cannot be compiled or no audit emitter is installed.
	Masking *MaskingInput
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
	recording         RecordingFactory
	recordingRequired bool
	masking           MaskingPolicy
	maskingRequired   bool
	maskingAudit      *maskingAuditConfig
	guardrails        *guardrailConfig
}

// WithRecordingFactory makes HandleSession wrap its upstream with f. Without
// it, sessions are relayed unrecorded exactly as before. A nil f is ignored.
func WithRecordingFactory(f RecordingFactory) HandleOption {
	return func(o *handleOptions) { o.recording = f }
}

// WithRecordingRequired makes HandleSession refuse the session, before the
// upstream is dialled, unless a non-nil RecordingFactory is configured and it
// returns a usable upstream. It is evaluated inside HandleSession so that a
// target requiring recording can never be relayed unrecorded because the
// factory was left unset or set to nil by the caller.
func WithRecordingRequired() HandleOption {
	return func(o *handleOptions) { o.recordingRequired = true }
}

// WithMasking makes HandleSession redact everything flowing from the target
// towards the client (channel data and extended data) using p. Redaction is
// applied below the recording wrapper, so recordings never contain unmasked
// bytes. If a redactor cannot be built, fails or panics, the channel and the
// session are terminated and no unscanned bytes are delivered. Without it,
// sessions are relayed exactly as before. A nil p is ignored.
//
// Only channel data and extended data from the target are masked. Channel
// requests from the target (for example the message in an exit-signal request)
// and global request replies pass through unmasked; this is a deliberate limit
// of this option.
//
// Note that the redactor holds back up to its maximum pattern length of
// output until more data arrives or the stream ends.
func WithMasking(p MaskingPolicy) HandleOption {
	return func(o *handleOptions) { o.masking = p }
}

type maskingAuditConfig struct {
	emitter     masking.Emitter
	principalID string
	window      time.Duration
}

// WithMaskingAudit makes HandleSession emit counts-only masking audit events
// (internal/masking.Event: session id, rule set id, detector label, count and
// time window; never matched values) through em, aggregated over window and
// flushed when a channel ends. If em fails the channel and the session are
// terminated and nothing further is delivered. It has no effect without
// WithMasking, and it is refused (the session is rejected) when em is nil or
// the ids or window are invalid.
func WithMaskingAudit(em masking.Emitter, principalID string, window time.Duration) HandleOption {
	return func(o *handleOptions) {
		o.maskingAudit = &maskingAuditConfig{emitter: em, principalID: principalID, window: window}
	}
}

// WithMaskingRequired makes HandleSession refuse the session, before the
// upstream is dialled, unless a usable non-nil MaskingPolicy is configured.
// It is evaluated inside HandleSession so a target requiring masking can never
// be relayed unmasked because the policy was left unset or nil by the caller.
func WithMaskingRequired() HandleOption {
	return func(o *handleOptions) { o.maskingRequired = true }
}

// isNilValue reports whether v is nil, including a typed nil pointer wrapped
// in a non-nil interface.
func isNilValue(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return rv.IsNil()
	}
	return false
}

// isNilUpstream reports whether u is nil, including a typed nil pointer
// wrapped in a non-nil interface.
func isNilUpstream(u Upstream) bool {
	if u == nil {
		return true
	}
	v := reflect.ValueOf(u)
	switch v.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return v.IsNil()
	}
	return false
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
	if isNilValue(opts.masking) && opts.maskingRequired {
		rejected(ReasonMaskingUnavailable)
		return errors.New(ctx, errors.InvalidParameter, op, "masking is required but no masking policy is configured")
	}
	if !isNilValue(opts.masking) {
		if err := checkMaskingPolicy(opts.masking); err != nil {
			rejected(ReasonMaskingUnavailable)
			return errors.New(ctx, errors.InvalidParameter, op, "masking policy unusable")
		}
		// Masking sits below recording so recordings only hold masked bytes.
		mu := newMaskingUpstream(upstream, opts.masking)
		if ac := opts.maskingAudit; ac != nil {
			ma, err := newMaskAudit(ctx, cfg.Authorization.SessionId, ac.principalID, ac.window, ac.emitter)
			if err != nil {
				rejected(ReasonMaskingUnavailable)
				return errors.New(ctx, errors.InvalidParameter, op, "masking audit unusable")
			}
			mu.withAudit(ma)
		}
		upstream = mu
	}
	if opts.recording == nil && opts.recordingRequired {
		rejected(ReasonRecordingUnavailable)
		return errors.New(ctx, errors.InvalidParameter, op, "recording is required but no recording factory is configured")
	}
	if opts.recording != nil {
		wrapped, err := opts.recording.Wrap(ctx, cfg.Authorization, upstream)
		if err != nil {
			rejected(ReasonRecordingUnavailable)
			return errors.Wrap(ctx, err, op, errors.WithMsg("recording unavailable"))
		}
		if isNilUpstream(wrapped) {
			rejected(ReasonRecordingUnavailable)
			return errors.New(ctx, errors.Internal, op, "recording factory returned no upstream")
		}
		upstream = wrapped
	}
	if opts.guardrails != nil {
		// Guardrails sit above recording so blocked commands never reach it or the target.
		g, err := startGuardrails(ctx, opts.guardrails, cfg.Authorization.SessionId, upstream)
		if err != nil {
			rejected(ReasonGuardrailsUnavailable)
			return errors.New(ctx, errors.InvalidParameter, op, "guardrails unusable")
		}
		upstream = g
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
