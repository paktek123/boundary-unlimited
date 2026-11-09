// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package ssh

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/hashicorp/boundary/internal/masking"
	"golang.org/x/crypto/ssh"
)

// MaskingPolicy is the effective masking configuration of one session. It is
// satisfied by *masking.Policy.
type MaskingPolicy interface {
	// NewRedactor returns a redactor writing masked output to w. The options
	// (for example masking.WithOnRedact) are applied in addition to the
	// policy's own settings, which always take precedence.
	NewRedactor(w io.Writer, opt ...masking.Option) (*masking.Redactor, error)
	// RuleSetHash identifies the effective rule set. It must not be empty.
	RuleSetHash() string
}

// errMasking is returned to the relay when masking fails. It carries no
// scanned data, rule, offset or panic value.
var errMasking = errors.New("ssh: masking failed; channel terminated")

// maskingUpstream wraps an Upstream so that everything flowing from the target
// towards the client is redacted before it is delivered. It is installed
// below the recording wrapper, so recordings only ever contain masked bytes.
type maskingUpstream struct {
	inner  Upstream
	policy MaskingPolicy
	audit  *maskAudit // nil: no audit events
}

var _ Upstream = (*maskingUpstream)(nil)

func newMaskingUpstream(inner Upstream, p MaskingPolicy) *maskingUpstream {
	return &maskingUpstream{inner: inner, policy: p}
}

// withAudit makes the upstream count redactions into a, for counts-only audit
// events. It returns u for chaining.
func (u *maskingUpstream) withAudit(a *maskAudit) *maskingUpstream {
	u.audit = a
	return u
}

func (u *maskingUpstream) Dial(ctx context.Context) (UpstreamConn, error) {
	c, err := u.inner.Dial(ctx)
	if err != nil {
		return nil, err
	}
	return &maskingConn{inner: c, policy: u.policy, audit: u.audit}, nil
}

// checkMaskingPolicy proves p can build and close a redactor, so a broken
// policy refuses the session before the target is dialled.
func checkMaskingPolicy(p MaskingPolicy) (err error) {
	defer func() {
		if recover() != nil {
			err = errMasking
		}
	}()
	if isNilValue(p) || p.RuleSetHash() == "" {
		return errMasking
	}
	r, err := p.NewRedactor(io.Discard)
	if err != nil || r == nil {
		return errMasking
	}
	if r.Close() != nil {
		return errMasking
	}
	return nil
}

type maskingConn struct {
	inner  UpstreamConn
	policy MaskingPolicy
	audit  *maskAudit
}

var _ UpstreamConn = (*maskingConn)(nil)

func (c *maskingConn) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	return c.inner.SendRequest(name, wantReply, payload)
}

func (c *maskingConn) Close() error { return c.inner.Close() }

func (c *maskingConn) OpenChannel(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	ch, reqs, err := c.inner.OpenChannel(name, data)
	if err != nil {
		return nil, nil, err
	}
	// terminate ends the whole session: the channel and the upstream
	// connection are closed so nothing else is relayed.
	terminate := func() {
		_ = ch.Close()
		_ = c.inner.Close()
	}
	out, err := newMaskReaderAudit(c.policy, ch, terminate, c.audit)
	if err != nil {
		terminate()
		return nil, nil, errMasking
	}
	errR, err := newMaskReaderAudit(c.policy, ch.Stderr(), terminate, c.audit)
	if err != nil {
		out.discard()
		terminate()
		return nil, nil, errMasking
	}
	return &maskChannel{Channel: ch, out: out, errR: errR, stderr: ch.Stderr(), audit: c.audit}, reqs, nil
}

type maskChannel struct {
	ssh.Channel
	out    *maskReader
	errR   *maskReader
	stderr io.ReadWriter
	audit  *maskAudit
}

func (c *maskChannel) Read(p []byte) (int, error) { return c.out.Read(p) }

func (c *maskChannel) Stderr() io.ReadWriter {
	return struct {
		io.Reader
		io.Writer
	}{c.errR, c.stderr}
}

func (c *maskChannel) Close() error {
	err := c.Channel.Close()
	c.out.discard()
	c.errR.discard()
	// Flush the counts-only events; an emitter failure is reported to the
	// relay as a masking failure.
	if aerr := c.audit.flush(); aerr != nil && err == nil {
		err = errMasking
	}
	return err
}

// sink collects redactor output until the relay reads it.
type sink struct{ b []byte }

func (s *sink) Write(p []byte) (int, error) {
	s.b = append(s.b, p...)
	return len(p), nil
}

func (s *sink) wipe() {
	clear(s.b[:cap(s.b)])
	s.b = nil
}

// maskReader turns the push-style Redactor into a pull-style reader. Bytes
// are only returned after the redactor has scanned them; on any error the held
// and pending bytes are wiped and never delivered.
type maskReader struct {
	src       io.Reader
	terminate func()

	mu     sync.Mutex
	red    *masking.Redactor
	out    sink
	buf    []byte
	err    error // sticky; io.EOF after a clean, flushed end of stream
	closed bool
	audit  *maskAudit
}

func newMaskReader(p MaskingPolicy, src io.Reader, terminate func()) (*maskReader, error) {
	return newMaskReaderAudit(p, src, terminate, nil)
}

func newMaskReaderAudit(p MaskingPolicy, src io.Reader, terminate func(), a *maskAudit) (m *maskReader, err error) {
	defer func() {
		if recover() != nil {
			m, err = nil, errMasking
		}
	}()
	if isNilValue(p) || p.RuleSetHash() == "" {
		return nil, errMasking
	}
	m = &maskReader{src: src, terminate: terminate, buf: make([]byte, 32<<10), audit: a}
	var opts []masking.Option
	if cb := a.callback(p.RuleSetHash()); cb != nil {
		opts = append(opts, masking.WithOnRedact(cb))
	}
	r, err := p.NewRedactor(&m.out, opts...)
	if err != nil || r == nil {
		return nil, errMasking
	}
	m.red = r
	return m, nil
}

// failLocked discards everything held, closes the redactor (its output is
// wiped, never delivered) and returns the error to hand to the relay. It must
// only run on the goroutine that owns m.buf (the one inside Read).
func (m *maskReader) failLocked() error {
	if m.err == nil || m.err == io.EOF {
		m.err = errMasking
	}
	m.wipeLocked(true)
	return m.err
}

// wipeLocked closes the redactor and wipes the output sink. m.buf is only
// cleared when wipeBuf is set: the reading goroutine may be filling it from
// the source at this moment, so every other goroutine must leave it alone.
func (m *maskReader) wipeLocked(wipeBuf bool) {
	if m.red != nil {
		func() {
			defer func() { _ = recover() }()
			_ = m.red.Close()
		}()
		m.red = nil
	}
	m.out.wipe()
	if wipeBuf {
		clear(m.buf)
	}
}

// discard releases the redactor and wipes the sink; used when the channel is
// closed. It never touches m.buf (owned by the reader). Safe to call
// repeatedly and concurrently with Read.
func (m *maskReader) discard() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	if m.err == nil {
		m.err = io.ErrClosedPipe
	}
	m.wipeLocked(false)
}

// next returns buffered masked bytes or a sticky error. done is false when the
// caller must read more from the source.
func (m *maskReader) next(p []byte) (n int, done bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.out.b) > 0 {
		n = copy(p, m.out.b)
		clear(m.out.b[:n])
		m.out.b = m.out.b[n:]
		return n, true, nil
	}
	if m.err != nil {
		return 0, true, m.err
	}
	return 0, false, nil
}

// feed pushes one source read through the redactor. terminate reports that
// the session must be ended; err is then the error for the relay.
func (m *maskReader) feed(rn int, rerr error) (terminate bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.red == nil {
		clear(m.buf)
		return false, m.err
	}
	if rn > 0 {
		_, werr := m.red.Write(m.buf[:rn])
		clear(m.buf[:rn])
		if werr != nil || m.audit.failed() {
			return true, m.failLocked()
		}
	}
	switch {
	case rerr == io.EOF:
		// Clean end of stream: scan and release what is held.
		if cerr := m.red.Close(); cerr != nil || m.audit.failed() || m.audit.flush() != nil {
			return true, m.failLocked()
		}
		m.red = nil
		m.err = io.EOF
	case rerr != nil:
		// Any other source error: held bytes are discarded, not flushed.
		m.err = rerr
		m.wipeLocked(true)
	}
	return false, nil
}

func (m *maskReader) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	defer func() {
		if recover() != nil {
			// No lock is held here: every locked section is a helper with
			// its own deferred unlock.
			m.mu.Lock()
			err = m.failLocked()
			m.mu.Unlock()
			n = 0
			m.terminate()
		}
	}()
	for {
		if n, done, err := m.next(p); done {
			return n, err
		}
		// Read without holding the lock so discard can interrupt.
		rn, rerr := m.src.Read(m.buf)
		if term, ferr := m.feed(rn, rerr); ferr != nil {
			if term {
				m.terminate()
			}
			return 0, ferr
		}
	}
}

// maskAudit feeds redaction counts of every channel of one session into one
// masking.Aggregator. Only counts and rule/detector labels ever reach the
// emitter, never matched bytes. The first emitter failure is sticky: every
// reader then fails closed and the session is terminated.
type maskAudit struct {
	ctx context.Context
	agg *masking.Aggregator

	mu  sync.Mutex
	err error
}

// newMaskAudit builds the per-session audit state. sessionID and principalID
// are validated by masking.NewAggregator.
func newMaskAudit(ctx context.Context, sessionID, principalID string, window time.Duration, em masking.Emitter) (*maskAudit, error) {
	if em == nil {
		return nil, errMasking
	}
	agg, err := masking.NewAggregator(sessionID, principalID, window, em, nil)
	if err != nil {
		return nil, errMasking
	}
	return &maskAudit{ctx: ctx, agg: agg}, nil
}

// callback returns the masking.WithOnRedact callback for the rule set, or nil
// when a is nil. The rule set hash is the rule id of the event; the detector
// is the rule's replacement label.
func (a *maskAudit) callback(ruleSetID string) func(detector string, n int) {
	if a == nil {
		return nil
	}
	return func(detector string, n int) {
		if err := a.agg.Add(a.ctx, ruleSetID, detector, n); err != nil {
			a.fail()
		}
	}
}

func (a *maskAudit) fail() {
	a.mu.Lock()
	a.err = errMasking
	a.mu.Unlock()
}

func (a *maskAudit) failed() bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.err != nil
}

// flush emits the pending counts. A failure is sticky.
func (a *maskAudit) flush() error {
	if a == nil {
		return nil
	}
	if err := a.agg.Flush(a.ctx); err != nil {
		a.fail()
		return errMasking
	}
	return nil
}
