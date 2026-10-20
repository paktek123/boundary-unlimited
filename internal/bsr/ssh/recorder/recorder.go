// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package recorder records SSH channel traffic into a BSR (Boundary Session
// Recording) connection container using internal/bsr and internal/bsr/ssh.
//
// It is a library only: nothing in the worker, API or targets uses it yet.
//
// The recorder is fail-closed: after the first write error every later call
// returns that error, so a caller can terminate the session rather than
// continue unrecorded.
//
// Directions follow the BSR convention used by internal/bsr/convert:
// bsr.Inbound is client to target, bsr.Outbound is target to client.
package recorder

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/boundary/internal/bsr"
	bssh "github.com/hashicorp/boundary/internal/bsr/ssh"
	"github.com/hashicorp/boundary/internal/storage"
	gssh "golang.org/x/crypto/ssh"
)

var directions = []bsr.Direction{bsr.Inbound, bsr.Outbound}

// Option configures a Recorder.
type Option func(*options)

type options struct {
	now func() time.Time
}

// WithClock overrides the time source, for tests.
func WithClock(now func() time.Time) Option {
	return func(o *options) { o.now = now }
}

func getOpts(opt ...Option) options {
	o := options{now: time.Now}
	for _, f := range opt {
		f(&o)
	}
	return o
}

// Recorder records the channels of a single SSH connection.
type Recorder struct {
	ctx    context.Context
	now    func() time.Time
	sessID string
	connID string
	conn   *bsr.Connection
	start  time.Time

	mu       sync.Mutex
	err      error
	closed   bool
	channels []*ChannelRecorder
}

// NewRecorder creates the connection container connectionId in session, which
// must have been created with bsr.WithSupportsMultiplex(true). The caller owns
// session and must close it.
func NewRecorder(ctx context.Context, session *bsr.Session, connectionId string, opt ...Option) (*Recorder, error) {
	const op = "recorder.NewRecorder"
	switch {
	case session == nil || session.Meta == nil:
		return nil, fmt.Errorf("%s: missing session: %w", op, bsr.ErrInvalidParameter)
	case connectionId == "":
		return nil, fmt.Errorf("%s: missing connection id: %w", op, bsr.ErrInvalidParameter)
	}
	o := getOpts(opt...)
	conn, err := session.NewConnection(ctx, &bsr.ConnectionRecordingMeta{Id: connectionId})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return &Recorder{ctx: ctx, now: o.now, sessID: session.Meta.Id, connID: connectionId, conn: conn, start: o.now()}, nil
}

// Channel starts recording a channel with the given SSH channel type and BSR
// channel id. All four chunk files (requests and messages, each direction) are
// created with their header.
func (r *Recorder) Channel(channelType, channelId string) (*ChannelRecorder, error) {
	const op = "recorder.(Recorder).Channel"
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return nil, r.err
	}
	if r.closed {
		return nil, fmt.Errorf("%s: recorder closed", op)
	}
	if channelId == "" || channelType == "" {
		return nil, fmt.Errorf("%s: missing channel id or type: %w", op, bsr.ErrInvalidParameter)
	}
	c, err := newChannelRecorder(r, channelType, channelId)
	if err != nil {
		r.err = fmt.Errorf("%s: %w", op, err)
		return nil, r.err
	}
	r.channels = append(r.channels, c)
	return c, nil
}

// Close closes all channels, writes the connection summary and closes the
// connection container. It is idempotent and returns the first error seen.
func (r *Recorder) Close() error {
	const op = "recorder.(Recorder).Close"
	r.mu.Lock()
	if r.closed {
		defer r.mu.Unlock()
		return r.err
	}
	r.closed = true
	chans := append([]*ChannelRecorder(nil), r.channels...)
	r.mu.Unlock()

	var up, down uint64
	firstErr := func(e error) {
		r.mu.Lock()
		if r.err == nil {
			r.err = e
		}
		r.mu.Unlock()
	}
	for _, c := range chans {
		if err := c.Close(); err != nil {
			firstErr(err)
		}
		u, d := c.bytes()
		up += u
		down += d
	}
	sum := &bsr.BaseConnectionSummary{
		Id:           r.connID,
		ChannelCount: uint64(len(chans)),
		StartTime:    r.start,
		EndTime:      r.now(),
		BytesUp:      up,
		BytesDown:    down,
	}
	r.mu.Lock()
	if r.err != nil {
		sum.Errors = bsr.SummaryError{Message: r.err.Error()}
	}
	r.mu.Unlock()
	if err := r.conn.EncodeSummary(r.ctx, sum); err != nil {
		firstErr(fmt.Errorf("%s: %w", op, err))
	}
	if err := r.conn.Close(r.ctx); err != nil {
		firstErr(fmt.Errorf("%s: %w", op, err))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

type dirWriter struct {
	w   storage.Writer
	enc *bsr.ChunkEncoder
}

// ChannelRecorder records one SSH channel. It is safe for concurrent use.
type ChannelRecorder struct {
	r           *Recorder
	ctx         context.Context
	channelType string
	channelId   string
	ch          *bsr.Channel
	start       time.Time

	mu       sync.Mutex
	err      error
	closed   bool
	messages map[bsr.Direction]*dirWriter
	requests map[bsr.Direction]*dirWriter
	up, down uint64
	program  bssh.SessionProgram
	subsys   string
}

func newChannelRecorder(r *Recorder, channelType, channelId string) (*ChannelRecorder, error) {
	ch, err := r.conn.NewChannel(r.ctx, &bsr.ChannelRecordingMeta{Id: channelId, Type: channelType})
	if err != nil {
		return nil, err
	}
	c := &ChannelRecorder{
		r: r, ctx: r.ctx, channelType: channelType, channelId: channelId, ch: ch, start: r.now(),
		messages: map[bsr.Direction]*dirWriter{}, requests: map[bsr.Direction]*dirWriter{},
		program: bssh.NotApplicable,
	}
	if channelType == "session" {
		c.program = bssh.None
	}
	for _, d := range directions {
		mw, err := ch.NewMessagesWriter(r.ctx, d)
		if err != nil {
			return nil, err
		}
		if c.messages[d], err = c.start0(mw, d); err != nil {
			return nil, err
		}
		rw, err := ch.NewRequestsWriter(r.ctx, d)
		if err != nil {
			return nil, err
		}
		if c.requests[d], err = c.start0(rw, d); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// start0 writes the BSR magic and header chunk to w.
func (c *ChannelRecorder) start0(w storage.Writer, d bsr.Direction) (*dirWriter, error) {
	if _, err := w.Write(bsr.Magic.Bytes()); err != nil {
		return nil, err
	}
	enc, err := bsr.NewChunkEncoder(c.ctx, w, bsr.NoCompression, bsr.NoEncryption)
	if err != nil {
		return nil, err
	}
	h, err := bsr.NewHeader(c.ctx, bssh.Protocol, d, bsr.NewTimestamp(c.r.now()), bsr.NoCompression, bsr.NoEncryption, c.r.sessID)
	if err != nil {
		return nil, err
	}
	if _, err := enc.Encode(c.ctx, h); err != nil {
		return nil, err
	}
	return &dirWriter{w: w, enc: enc}, nil
}

func (c *ChannelRecorder) fail(err error) error {
	if c.err == nil {
		c.err = err
	}
	return c.err
}

// WriteData records channel data travelling in direction dir. Data larger than
// bssh.MaxPacketSize is split across chunks.
func (c *ChannelRecorder) WriteData(dir bsr.Direction, data []byte) error {
	const op = "recorder.(ChannelRecorder).WriteData"
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.usable(op, dir); err != nil {
		return err
	}
	for len(data) > 0 {
		n := len(data)
		if n > bssh.MaxPacketSize {
			n = bssh.MaxPacketSize
		}
		chunk, err := bssh.NewDataChunk(c.ctx, dir, bsr.NewTimestamp(c.r.now()), data[:n])
		if err != nil {
			return c.fail(fmt.Errorf("%s: %w", op, err))
		}
		if _, err := c.messages[dir].enc.Encode(c.ctx, chunk); err != nil {
			return c.fail(fmt.Errorf("%s: %w", op, err))
		}
		if dir == bsr.Inbound {
			c.up += uint64(n)
		} else {
			c.down += uint64(n)
		}
		data = data[n:]
	}
	return nil
}

// WriteRequest records an SSH channel request travelling in direction dir.
// Requests with an unrecognized type, or a payload that cannot be parsed, are
// recorded verbatim as unknown requests rather than dropped.
func (c *ChannelRecorder) WriteRequest(dir bsr.Direction, req *gssh.Request) error {
	const op = "recorder.(ChannelRecorder).WriteRequest"
	if req == nil {
		return fmt.Errorf("%s: nil request: %w", op, bsr.ErrInvalidParameter)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.usable(op, dir); err != nil {
		return err
	}
	ts := bsr.NewTimestamp(c.r.now())
	chunk, err := newRequestChunk(c.ctx, dir, ts, req)
	if err != nil {
		chunk, err = bssh.NewUnknownRequest(c.ctx, dir, ts, req)
		if err != nil {
			return c.fail(fmt.Errorf("%s: %w", op, err))
		}
	}
	if _, err := c.requests[dir].enc.Encode(c.ctx, chunk); err != nil {
		return c.fail(fmt.Errorf("%s: %w", op, err))
	}
	if dir == bsr.Inbound && c.channelType == "session" {
		switch req.Type {
		case bssh.ShellRequestType:
			c.program = bssh.Shell
		case bssh.ExecRequestType:
			c.program = bssh.Exec
		case bssh.SubsystemRequestType:
			c.program = bssh.Subsystem
			var s struct{ Name string }
			if gssh.Unmarshal(req.Payload, &s) == nil {
				c.subsys = s.Name
			}
		}
	}
	return nil
}

func (c *ChannelRecorder) usable(op string, dir bsr.Direction) error {
	if c.err != nil {
		return c.err
	}
	if c.closed {
		return fmt.Errorf("%s: channel recorder closed", op)
	}
	if !bsr.ValidDirection(dir) {
		return fmt.Errorf("%s: invalid direction: %w", op, bsr.ErrInvalidParameter)
	}
	return nil
}

func (c *ChannelRecorder) bytes() (uint64, uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.up, c.down
}

// Close writes the end chunks, the channel summary and closes the channel
// container. It is idempotent and returns the first error seen.
func (c *ChannelRecorder) Close() error {
	const op = "recorder.(ChannelRecorder).Close"
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return c.err
	}
	c.closed = true
	for _, set := range []map[bsr.Direction]*dirWriter{c.messages, c.requests} {
		for _, d := range directions {
			dw := set[d]
			end, err := bsr.NewEnd(c.ctx, bssh.Protocol, d, bsr.NewTimestamp(c.r.now()))
			if err == nil {
				_, err = dw.enc.Encode(c.ctx, end) // closes the writer
			}
			if err != nil {
				c.fail(fmt.Errorf("%s: %w", op, err))
			}
		}
	}
	sum := &bssh.ChannelSummary{
		ChannelSummary: &bsr.BaseChannelSummary{
			Id:                    c.channelId,
			ConnectionRecordingId: c.r.connID,
			StartTime:             c.start,
			EndTime:               c.r.now(),
			BytesUp:               c.up,
			BytesDown:             c.down,
			ChannelType:           c.channelType,
		},
		SessionProgram:        c.program,
		SubsystemName:         c.subsys,
		ExecProgram:           bssh.ExecApplicationProgramNotApplicable,
		FileTransferDirection: bssh.FileTransferNotApplicable,
	}
	if c.program == bssh.Exec {
		sum.ExecProgram = bssh.Unknown
	}
	if err := c.ch.EncodeSummary(c.ctx, sum); err != nil {
		c.fail(fmt.Errorf("%s: %w", op, err))
	}
	if err := c.ch.Close(c.ctx); err != nil {
		c.fail(fmt.Errorf("%s: %w", op, err))
	}
	return c.err
}

func newRequestChunk(ctx context.Context, d bsr.Direction, t *bsr.Timestamp, r *gssh.Request) (bsr.Chunk, error) {
	switch r.Type {
	case bssh.BreakRequestType:
		return bssh.NewBreakRequest(ctx, d, t, r)
	case bssh.CancelTCPIPForwardRequestType:
		return bssh.NewCancelTCPIPForwardRequest(ctx, d, t, r)
	case bssh.EnvRequestType:
		return bssh.NewEnvRequest(ctx, d, t, r)
	case bssh.ExecRequestType:
		return bssh.NewExecRequest(ctx, d, t, r)
	case bssh.ExitSignalRequestType:
		return bssh.NewExitSignalRequest(ctx, d, t, r)
	case bssh.ExitStatusRequestType:
		return bssh.NewExitStatusRequest(ctx, d, t, r)
	case bssh.PtyRequestType:
		return bssh.NewPtyRequest(ctx, d, t, r)
	case bssh.ShellRequestType:
		return bssh.NewShellRequest(ctx, d, t, r)
	case bssh.SignalRequestType:
		return bssh.NewSignalRequest(ctx, d, t, r)
	case bssh.SubsystemRequestType:
		return bssh.NewSubsystemRequest(ctx, d, t, r)
	case bssh.TCPIPForwardRequestType:
		return bssh.NewTCPIPForwardRequest(ctx, d, t, r)
	case bssh.WindowChangeRequestType:
		return bssh.NewWindowChangeRequest(ctx, d, t, r)
	case bssh.X11ForwardingRequestType:
		return bssh.NewX11ForwardingRequest(ctx, d, t, r)
	case bssh.XonXoffRequestType:
		return bssh.NewXonXoffRequest(ctx, d, t, r)
	}
	return bssh.NewUnknownRequest(ctx, d, t, r)
}
