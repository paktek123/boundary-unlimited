// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/hashicorp/boundary/internal/masking"
	"golang.org/x/crypto/ssh"
)

// MaskingPolicy is the effective masking configuration of one session. It is
// satisfied by *masking.Policy.
type MaskingPolicy interface {
	// NewRedactor returns a redactor writing masked output to w.
	NewRedactor(w io.Writer) (*masking.Redactor, error)
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
}

var _ Upstream = (*maskingUpstream)(nil)

func newMaskingUpstream(inner Upstream, p MaskingPolicy) *maskingUpstream {
	return &maskingUpstream{inner: inner, policy: p}
}

func (u *maskingUpstream) Dial(ctx context.Context) (UpstreamConn, error) {
	c, err := u.inner.Dial(ctx)
	if err != nil {
		return nil, err
	}
	return &maskingConn{inner: c, policy: u.policy}, nil
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
	out, err := newMaskReader(c.policy, ch, terminate)
	if err != nil {
		terminate()
		return nil, nil, errMasking
	}
	errR, err := newMaskReader(c.policy, ch.Stderr(), terminate)
	if err != nil {
		out.discard()
		terminate()
		return nil, nil, errMasking
	}
	return &maskChannel{Channel: ch, out: out, errR: errR, stderr: ch.Stderr()}, reqs, nil
}

type maskChannel struct {
	ssh.Channel
	out    *maskReader
	errR   *maskReader
	stderr io.ReadWriter
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
}

func newMaskReader(p MaskingPolicy, src io.Reader, terminate func()) (m *maskReader, err error) {
	defer func() {
		if recover() != nil {
			m, err = nil, errMasking
		}
	}()
	if isNilValue(p) || p.RuleSetHash() == "" {
		return nil, errMasking
	}
	m = &maskReader{src: src, terminate: terminate, buf: make([]byte, 32<<10)}
	r, err := p.NewRedactor(&m.out)
	if err != nil || r == nil {
		return nil, errMasking
	}
	m.red = r
	return m, nil
}

// failLocked discards everything held, closes the redactor (its output is
// wiped, never delivered) and returns the error to hand to the relay.
func (m *maskReader) failLocked() error {
	if m.err == nil || m.err == io.EOF {
		m.err = errMasking
	}
	m.wipeLocked()
	return m.err
}

func (m *maskReader) wipeLocked() {
	if m.red != nil {
		func() {
			defer func() { _ = recover() }()
			_ = m.red.Close()
		}()
		m.red = nil
	}
	m.out.wipe()
	clear(m.buf)
}

// discard releases the redactor and wipes buffers; used when the channel is
// closed. Safe to call repeatedly and concurrently with Read.
func (m *maskReader) discard() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	if m.err == nil {
		m.err = io.ErrClosedPipe
	}
	m.wipeLocked()
}

func (m *maskReader) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	defer func() {
		if recover() != nil {
			m.mu.Lock()
			n, err = 0, m.failLocked()
			m.mu.Unlock()
			m.terminate()
		}
	}()
	for {
		m.mu.Lock()
		if len(m.out.b) > 0 {
			n = copy(p, m.out.b)
			clear(m.out.b[:n])
			m.out.b = m.out.b[n:]
			m.mu.Unlock()
			return n, nil
		}
		if m.err != nil {
			err = m.err
			m.mu.Unlock()
			return 0, err
		}
		m.mu.Unlock()

		// Read without holding the lock so discard/Close can interrupt.
		rn, rerr := m.src.Read(m.buf)

		m.mu.Lock()
		if m.closed || m.red == nil {
			clear(m.buf)
			err = m.err
			m.mu.Unlock()
			return 0, err
		}
		if rn > 0 {
			_, werr := m.red.Write(m.buf[:rn])
			clear(m.buf[:rn])
			if werr != nil {
				err = m.failLocked()
				m.mu.Unlock()
				m.terminate()
				return 0, err
			}
		}
		switch {
		case rerr == io.EOF:
			// Clean end of stream: scan and release what is held.
			if cerr := m.red.Close(); cerr != nil {
				err = m.failLocked()
				m.mu.Unlock()
				m.terminate()
				return 0, err
			}
			m.red = nil
			m.err = io.EOF
		case rerr != nil:
			// Any other source error: held bytes are discarded, not flushed.
			m.err = rerr
			m.wipeLocked()
		}
		m.mu.Unlock()
	}
}
