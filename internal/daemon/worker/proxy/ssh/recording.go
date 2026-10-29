// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/hashicorp/boundary/internal/bsr/ssh/recorder"
	"github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh/recguard"
	berrors "github.com/hashicorp/boundary/internal/errors"
	"golang.org/x/crypto/ssh"
)

// ScratchReserver reserves local recording capacity. It is satisfied by
// *scratch.Store.
type ScratchReserver interface {
	Reserve(sessionID string, capacity int64) error
	Discard(sessionID string) error
}

// RecordingDeps are the dependencies of NewRecordingUpstream. All fields are
// required.
type RecordingDeps struct {
	// SessionId identifies the recording in the scratch store.
	SessionId string
	// Capacity is the number of bytes reserved in Scratch before the upstream
	// is dialled.
	Capacity int64
	// Scratch is checked for capacity before the inner dial.
	Scratch ScratchReserver
	// Recorder records the connection. Its BSR session should write into the
	// scratch store. It is closed (finalised) when the upstream connection is
	// closed.
	Recorder *recorder.Recorder
	// Terminator and Marker are called once, through a recguard.Guard, when a
	// recording write fails. Terminator is called while the connection's
	// recording lock is held, so it must not block waiting for this
	// connection's channels or goroutines to finish; it should only signal.
	Terminator recguard.Terminator
	Marker     recguard.Marker
	// NewChannelId generates BSR channel ids. Optional; defaults to
	// bsr.NewChannelId.
	NewChannelId func() (string, error)
}

func (d RecordingDeps) validate(ctx context.Context) error {
	const op = "ssh.RecordingDeps.validate"
	switch {
	case d.SessionId == "":
		return errNew(ctx, op, "missing session id")
	case d.Capacity < 0:
		return errNew(ctx, op, "negative capacity")
	case d.Scratch == nil:
		return errNew(ctx, op, "missing scratch store")
	case d.Recorder == nil:
		return errNew(ctx, op, "missing recorder")
	case d.Terminator == nil:
		return errNew(ctx, op, "missing terminator")
	case d.Marker == nil:
		return errNew(ctx, op, "missing marker")
	}
	return nil
}

// RecordingUpstream wraps an Upstream so every channel's data in both
// directions and every channel request is recorded before it is delivered.
// It fails closed: if recording capacity is not available, Dial fails before
// the inner dial; if a recording write fails mid-session, the guard terminates
// the session, marks the recording incomplete and every channel and the
// upstream connection are closed.
type RecordingUpstream struct {
	inner Upstream
	deps  RecordingDeps
}

var _ Upstream = (*RecordingUpstream)(nil)

// NewRecordingUpstream returns an Upstream that records the connections of
// inner. A RecordingUpstream supports a single Dial: the scratch reservation
// is per session.
func NewRecordingUpstream(ctx context.Context, inner Upstream, deps RecordingDeps) (*RecordingUpstream, error) {
	const op = "ssh.NewRecordingUpstream"
	if inner == nil {
		return nil, errNew(ctx, op, "missing inner upstream")
	}
	if err := deps.validate(ctx); err != nil {
		return nil, err
	}
	return &RecordingUpstream{inner: inner, deps: deps}, nil
}

// Dial reserves scratch capacity and then dials the inner upstream.
func (u *RecordingUpstream) Dial(ctx context.Context) (UpstreamConn, error) {
	const op = "ssh.RecordingUpstream.Dial"
	if err := u.deps.Scratch.Reserve(u.deps.SessionId, u.deps.Capacity); err != nil {
		return nil, berrors.Wrap(ctx, err, berrors.Op(op), berrors.WithMsg("reserving recording capacity"))
	}
	inner, err := u.inner.Dial(ctx)
	if err != nil {
		_ = u.deps.Scratch.Discard(u.deps.SessionId)
		return nil, berrors.Wrap(ctx, err, berrors.Op(op))
	}
	newId := u.deps.NewChannelId
	if newId == nil {
		newId = bsr.NewChannelId
	}
	rc := &recordingConn{inner: inner, rec: u.deps.Recorder, newId: newId, open: map[*recChannel]struct{}{}, done: make(chan struct{})}
	rc.sink = &opSink{}
	g, err := recguard.New(rc.sink, &connTerminator{rc: rc, term: u.deps.Terminator}, u.deps.Marker)
	if err != nil {
		_ = inner.Close()
		return nil, berrors.Wrap(ctx, err, berrors.Op(op))
	}
	rc.guard = g
	return rc, nil
}

var errRecordingClosed = errors.New("ssh: recording finalised, connection closed")

// opSink adapts recorder calls to a recguard.Sink: Write runs the operation
// set by the caller and reports len(p) on success. Callers serialise access.
type opSink struct{ op func() error }

func (s *opSink) Write(p []byte) (int, error) {
	if err := s.op(); err != nil {
		return 0, err
	}
	return len(p), nil
}

// connTerminator closes the whole upstream connection and all channels, then
// calls the configured Terminator.
type connTerminator struct {
	rc   *recordingConn
	term recguard.Terminator
}

func (t *connTerminator) Terminate(ctx context.Context, reason string) error {
	t.rc.closeAll()
	return t.term.Terminate(ctx, reason)
}

type recordingConn struct {
	inner UpstreamConn
	rec   *recorder.Recorder
	newId func() (string, error)

	mu    sync.Mutex // serialises recording operations and guards the fields below
	sink  *opSink
	guard *recguard.Guard
	open  map[*recChannel]struct{}

	done      chan struct{} // closed when the connection is closed; unblocks request forwarding
	doneOnce  sync.Once
	closeOnce sync.Once
	finalErr  error
	closed    bool
}

var _ UpstreamConn = (*recordingConn)(nil)

// record runs op through the guard. It must not be called with rc.mu held.
func (rc *recordingConn) record(op func() error) error {
	rc.mu.Lock()
	if rc.closed {
		// The connection is being finalised; nothing more may be delivered,
		// but this is not a recording failure.
		rc.mu.Unlock()
		return errRecordingClosed
	}
	rc.sink.op = op
	_, err := rc.guard.Write([]byte{0})
	rc.mu.Unlock()
	return err
}

// closeAll closes the inner connection and every open channel. It runs from
// the guard's trip inside record, so rc.mu is already held by the caller; it
// closes the embedded ssh.Channel directly to avoid recChannel.Close, which
// takes rc.mu.
func (rc *recordingConn) closeAll() {
	rc.doneOnce.Do(func() { close(rc.done) })
	for ch := range rc.open {
		_ = ch.Channel.Close()
	}
	_ = rc.inner.Close()
}

// FinalizeErr returns the error from finalising the recording, if any, after
// Close has been called.
func (rc *recordingConn) FinalizeErr() error {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.finalErr
}

// Close closes the inner connection and finalises the recording. A
// finalisation failure marks the recording incomplete and is returned.
func (rc *recordingConn) Close() error {
	var err error
	rc.closeOnce.Do(func() {
		// Setting closed under mu waits for an in-flight recording operation
		// and makes later ones fail without tripping the guard.
		rc.mu.Lock()
		rc.closed = true
		rc.mu.Unlock()
		rc.doneOnce.Do(func() { close(rc.done) })
		innerErr := rc.inner.Close()
		recErr := rc.rec.Close()
		var markErr error
		if recErr != nil && !rc.guard.Tripped() {
			// Route the failure through the guard so the recording is marked
			// incomplete and the session terminated exactly once.
			rc.mu.Lock()
			rc.sink.op = func() error { return recErr }
			_, _ = rc.guard.Write([]byte{0})
			rc.mu.Unlock()
			markErr = rc.guard.Err()
		}
		rc.mu.Lock()
		if recErr != nil {
			rc.finalErr = fmt.Errorf("ssh.recordingConn.Close: finalising recording: %w", errors.Join(recErr, markErr))
		}
		err = errors.Join(innerErr, rc.finalErr)
		rc.mu.Unlock()
	})
	return err
}

func (rc *recordingConn) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	return rc.inner.SendRequest(name, wantReply, payload)
}

func (rc *recordingConn) OpenChannel(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	const op = "ssh.recordingConn.OpenChannel"
	id, err := rc.newId()
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", op, err)
	}
	var cr *recorder.ChannelRecorder
	if err := rc.record(func() (err error) {
		cr, err = rc.rec.Channel(name, id)
		return err
	}); err != nil {
		return nil, nil, fmt.Errorf("%s: starting channel recording: %w", op, err)
	}
	ch, reqs, err := rc.inner.OpenChannel(name, data)
	if err != nil {
		_ = cr.Close()
		return nil, nil, err
	}
	rch := &recChannel{Channel: ch, rc: rc, cr: cr}
	rc.mu.Lock()
	rc.open[rch] = struct{}{}
	rc.mu.Unlock()

	out := make(chan *ssh.Request)
	go rch.recordUpstreamRequests(reqs, out)
	return rch, out, nil
}

// recChannel records a channel's traffic before delivering it. Inbound is
// client to target, matching internal/bsr.
type recChannel struct {
	ssh.Channel
	rc *recordingConn
	cr *recorder.ChannelRecorder
}

func (c *recChannel) Write(p []byte) (int, error) {
	if err := c.rc.record(func() error { return c.cr.WriteData(bsr.Inbound, p) }); err != nil {
		return 0, err
	}
	return c.Channel.Write(p)
}

func (c *recChannel) Read(p []byte) (int, error) {
	n, err := c.Channel.Read(p)
	if n > 0 {
		if rerr := c.rc.record(func() error { return c.cr.WriteData(bsr.Outbound, p[:n]) }); rerr != nil {
			return 0, rerr
		}
	}
	return n, err
}

// SendRequest records a client-to-target request before sending it.
func (c *recChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	req := &ssh.Request{Type: name, WantReply: wantReply, Payload: payload}
	if err := c.rc.record(func() error { return c.cr.WriteRequest(bsr.Inbound, req) }); err != nil {
		return false, err
	}
	return c.Channel.SendRequest(name, wantReply, payload)
}

func (c *recChannel) Stderr() io.ReadWriter {
	return &recStderr{c: c, inner: c.Channel.Stderr()}
}

func (c *recChannel) Close() error {
	c.rc.mu.Lock()
	delete(c.rc.open, c)
	c.rc.mu.Unlock()
	return c.Channel.Close()
}

// recordUpstreamRequests records target-to-client requests (for example
// exit-status) and forwards them. Once the guard has tripped, requests are
// refused instead of delivered.
func (c *recChannel) recordUpstreamRequests(in <-chan *ssh.Request, out chan<- *ssh.Request) {
	defer close(out)
	for r := range in {
		if err := c.rc.record(func() error { return c.cr.WriteRequest(bsr.Outbound, r) }); err != nil {
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
			continue
		}
		select {
		case out <- r:
		case <-c.rc.done:
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
		}
	}
}

// recStderr records the extended-data stream. Target output is Outbound.
type recStderr struct {
	c     *recChannel
	inner io.ReadWriter
}

func (s *recStderr) Read(p []byte) (int, error) {
	n, err := s.inner.Read(p)
	if n > 0 {
		if rerr := s.c.rc.record(func() error { return s.c.cr.WriteData(bsr.Outbound, p[:n]) }); rerr != nil {
			return 0, rerr
		}
	}
	return n, err
}

func (s *recStderr) Write(p []byte) (int, error) {
	if err := s.c.rc.record(func() error { return s.c.cr.WriteData(bsr.Inbound, p) }); err != nil {
		return 0, err
	}
	return s.inner.Write(p)
}

func errNew(ctx context.Context, op, msg string) error {
	return berrors.New(ctx, berrors.InvalidParameter, berrors.Op(op), msg)
}
