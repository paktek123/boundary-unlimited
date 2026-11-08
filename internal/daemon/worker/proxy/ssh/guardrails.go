// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package ssh

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/hashicorp/boundary/internal/guardrails"
	"golang.org/x/crypto/ssh"
)

// errGuardrails is returned to the relay when guardrails refuse or end a
// channel. It never carries command text, a rule or a panic value.
var errGuardrails = errors.New("ssh: guardrails refused the request")

// GuardrailOption configures WithGuardrails.
type GuardrailOption func(*guardrailConfig)

type guardrailConfig struct {
	compiled         *guardrails.Compiled
	emitter          guardrails.Emitter
	principalId      string
	blockLimit       int
	allowInteractive bool
}

// WithGuardrailPrincipalId sets the principal recorded in guardrail audit
// events. It is required: a session without a principal id is refused.
func WithGuardrailPrincipalId(id string) GuardrailOption {
	return func(c *guardrailConfig) { c.principalId = id }
}

// WithGuardrailBlockLimit sets the number of blocked commands after which the
// session is terminated. The default is guardrails.DefaultBlocksBeforeTerminate;
// values outside 1..20 refuse the session.
func WithGuardrailBlockLimit(n int) GuardrailOption {
	return func(c *guardrailConfig) { c.blockLimit = n }
}

// WithGuardrailAllowInteractive permits shell and subsystem requests, which
// guardrails cannot inspect (enforcement is best effort). The session is
// refused unless the best-effort audit event could be emitted at session start.
func WithGuardrailAllowInteractive() GuardrailOption {
	return func(c *guardrailConfig) { c.allowInteractive = true }
}

// WithGuardrails makes HandleSession evaluate every exec request against
// compiled before it is forwarded. Block and review verdicts reject the
// request, close the channel and forward nothing to the target (the review
// flow is a later slice, so review currently behaves like block but emits a
// review event). Shell and subsystem requests are refused unless
// WithGuardrailAllowInteractive is given. The session ends after the Nth
// blocked command. A nil compiled set, a nil emitter, a missing principal id
// or an invalid limit refuse the session before the target is dialled; an
// evaluator error or panic blocks the command. Without this option sessions
// are relayed exactly as before. Command text is never logged or emitted.
func WithGuardrails(compiled *guardrails.Compiled, emitter guardrails.Emitter, opts ...GuardrailOption) HandleOption {
	return func(o *handleOptions) {
		c := &guardrailConfig{compiled: compiled, emitter: emitter, blockLimit: guardrails.DefaultBlocksBeforeTerminate}
		for _, f := range opts {
			f(c)
		}
		o.guardrails = c
	}
}

// emitSafe emits e and reports whether it succeeded; a panic counts as failure.
func (c *guardrailConfig) emitSafe(ctx context.Context, build func() (guardrails.Event, error)) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	if isNilValue(c.emitter) {
		return false
	}
	e, err := build()
	if err != nil {
		return false
	}
	return c.emitter.Emit(ctx, e) == nil
}

// startGuardrails validates the configuration and, when interactive access is
// allowed, emits the best-effort event. It returns a usable upstream wrapper
// or an error that refuses the session.
func startGuardrails(ctx context.Context, c *guardrailConfig, sessionId string, inner Upstream) (Upstream, error) {
	if c == nil || c.compiled == nil || isNilValue(c.emitter) || c.principalId == "" ||
		c.compiled.RuleSetHash() == "" {
		return nil, errGuardrails
	}
	counter, err := guardrails.NewBlockCounter(c.blockLimit)
	if err != nil {
		return nil, errGuardrails
	}
	if c.allowInteractive {
		if !c.emitSafe(ctx, func() (guardrails.Event, error) {
			return guardrails.NewInteractiveBestEffortEvent(sessionId, c.principalId, c.compiled.RuleSetHash(), time.Now())
		}) {
			return nil, errGuardrails
		}
	}
	return &guardUpstream{inner: inner, cfg: c, sessionId: sessionId, counter: counter}, nil
}

type guardUpstream struct {
	inner     Upstream
	cfg       *guardrailConfig
	sessionId string
	counter   *guardrails.BlockCounter
}

func (u *guardUpstream) Dial(ctx context.Context) (UpstreamConn, error) {
	c, err := u.inner.Dial(ctx)
	if err != nil {
		return nil, err
	}
	return &guardConn{UpstreamConn: c, u: u, ctx: ctx}, nil
}

type guardConn struct {
	UpstreamConn
	u   *guardUpstream
	ctx context.Context

	mu         sync.Mutex
	terminated bool
}

func (c *guardConn) isTerminated() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.terminated
}

func (c *guardConn) OpenChannel(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	if c.isTerminated() {
		return nil, nil, errGuardrails
	}
	ch, reqs, err := c.UpstreamConn.OpenChannel(name, data)
	if err != nil {
		return nil, nil, err
	}
	return &guardChannel{Channel: ch, conn: c}, reqs, nil
}

type guardChannel struct {
	ssh.Channel
	conn *guardConn

	mu      sync.Mutex
	blocked bool
}

// parseExec extracts the command from an exec request payload (RFC 4254
// section 6.5: a single length-prefixed string with nothing after it).
func parseExec(payload []byte) ([]byte, bool) {
	if len(payload) < 4 {
		return nil, false
	}
	n := binary.BigEndian.Uint32(payload)
	if uint64(n) != uint64(len(payload)-4) {
		return nil, false
	}
	return payload[4:], true
}

func (g *guardChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	g.mu.Lock()
	blocked := g.blocked
	g.mu.Unlock()
	if blocked {
		return false, errGuardrails
	}
	cfg := g.conn.u.cfg
	switch name {
	case "shell", "subsystem":
		if !cfg.allowInteractive {
			return false, errGuardrails
		}
		return g.Channel.SendRequest(name, wantReply, payload)
	case "exec":
		return g.exec(wantReply, payload)
	}
	return g.Channel.SendRequest(name, wantReply, payload)
}

func (g *guardChannel) exec(wantReply bool, payload []byte) (bool, error) {
	u := g.conn.u
	cmd, ok := parseExec(payload)
	var d guardrails.Decision
	if ok {
		d = g.evaluate(cmd)
	} else {
		d = guardrails.Decision{Verdict: guardrails.VerdictBlock, RuleSetHash: u.cfg.compiled.RuleSetHash()}
	}
	if d.Verdict == guardrails.VerdictAllow {
		return g.Channel.SendRequest("exec", wantReply, payload)
	}
	// Block or review (or anything unknown): nothing is forwarded.
	g.mu.Lock()
	g.blocked = true
	g.mu.Unlock()
	ctx, hash, sid, pid := g.conn.ctx, u.cfg.compiled.RuleSetHash(), u.sessionId, u.cfg.principalId
	if d.Verdict == guardrails.VerdictReview {
		u.cfg.emitSafe(ctx, func() (guardrails.Event, error) {
			return guardrails.NewReviewRequestedEvent(sid, pid, d.RuleID, hash, time.Now())
		})
	} else {
		u.cfg.emitSafe(ctx, func() (guardrails.Event, error) {
			return guardrails.NewBlockedEvent(sid, pid, d.RuleID, hash, 1, time.Now())
		})
	}
	// Review does not count towards termination; it is still not forwarded.
	if d.Verdict != guardrails.VerdictReview && u.counter.Record() {
		u.cfg.emitSafe(ctx, func() (guardrails.Event, error) {
			return guardrails.NewSessionTerminatedEvent(sid, pid, hash, u.counter.Count(), time.Now())
		})
		g.conn.mu.Lock()
		g.conn.terminated = true
		g.conn.mu.Unlock()
		_ = g.Close()
		_ = g.conn.Close()
		return false, errGuardrails
	}
	_ = g.Close()
	return false, errGuardrails
}

// evaluate never panics and never returns Allow on failure.
func (g *guardChannel) evaluate(cmd []byte) (d guardrails.Decision) {
	c := g.conn.u.cfg.compiled
	defer func() {
		if recover() != nil {
			d = guardrails.Decision{Verdict: guardrails.VerdictBlock, RuleSetHash: c.RuleSetHash()}
		}
	}()
	return c.Evaluate(cmd)
}
