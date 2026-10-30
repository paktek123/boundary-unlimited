// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/hashicorp/boundary/internal/bsr/kms"
	"github.com/hashicorp/boundary/internal/bsr/ssh/recorder"
	"github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh/recguard"
	"github.com/hashicorp/boundary/internal/daemon/worker/recording/bsrfs"
	"github.com/hashicorp/boundary/internal/daemon/worker/recording/upload"
	berrors "github.com/hashicorp/boundary/internal/errors"
)

// finalizeTimeout bounds finalisation (finish, upload, discard) of one
// recording when its session closes.
const finalizeTimeout = 5 * time.Minute

// RecordingScratch is the local recording store used by the factory. It is
// satisfied by *scratch.Store.
type RecordingScratch interface {
	ScratchReserver
	bsrfs.Store
}

// RecordingFinalizer finishes a recording and submits it for upload. It is
// satisfied by *finalize.Finalizer. A failed finalisation must keep the
// scratch data.
type RecordingFinalizer interface {
	Finalize(ctx context.Context, sessionID string) (upload.Result, error)
}

// FinalizeReporter is told the outcome of every finalisation, so a failure to
// finalise is never silent. It must not block.
type FinalizeReporter interface {
	RecordingFinalized(ctx context.Context, sessionID string, res upload.Result, err error)
}

// SessionRecordingSpec carries the per-session inputs of a recording. They
// come from the authorised session (never from the client).
type SessionRecordingSpec struct {
	Meta        *bsr.SessionRecordingMeta
	SessionMeta *bsr.SessionMeta
	Keys        *kms.Keys
	// ConnectionId identifies the recorded connection in the BSR.
	ConnectionId string
	// Capacity is the number of scratch bytes reserved for the session.
	Capacity int64
	// Terminator and Marker are used when a recording write fails; see
	// RecordingDeps.
	Terminator recguard.Terminator
	Marker     recguard.Marker
}

// SpecProvider resolves the recording inputs for an authorised session.
type SpecProvider interface {
	RecordingSpec(ctx context.Context, auth Authorization) (SessionRecordingSpec, error)
}

// RecordingFactoryDeps are the dependencies of NewRecordingFactory. All
// fields are required.
type RecordingFactoryDeps struct {
	Scratch   RecordingScratch
	Finalizer RecordingFinalizer
	Specs     SpecProvider
	Reporter  FinalizeReporter
}

type recordingFactory struct {
	deps RecordingFactoryDeps
}

var _ RecordingFactory = (*recordingFactory)(nil)

// NewRecordingFactory returns the RecordingFactory that records each session
// as a BSR into the local scratch store and finalises it when the session's
// upstream connection closes. It fails closed: a missing dependency is a
// constructor error, and any scratch, spec or recorder error while wrapping
// refuses the session. It is not wired into the worker yet.
func NewRecordingFactory(deps RecordingFactoryDeps) (RecordingFactory, error) {
	const op = "ssh.NewRecordingFactory"
	ctx := context.Background()
	switch {
	case deps.Scratch == nil:
		return nil, errNew(ctx, op, "missing scratch store")
	case deps.Finalizer == nil:
		return nil, errNew(ctx, op, "missing finalizer")
	case deps.Specs == nil:
		return nil, errNew(ctx, op, "missing spec provider")
	case deps.Reporter == nil:
		return nil, errNew(ctx, op, "missing reporter")
	}
	return &recordingFactory{deps: deps}, nil
}

// Wrap reserves scratch space, builds the BSR recorder over it and returns
// the recording upstream. A reservation failure (for example quota exceeded)
// returns an error before anything is dialled.
func (f *recordingFactory) Wrap(ctx context.Context, auth Authorization, inner Upstream) (Upstream, error) {
	const op = "ssh.recordingFactory.Wrap"
	if inner == nil {
		return nil, errNew(ctx, op, "missing inner upstream")
	}
	spec, err := f.deps.Specs.RecordingSpec(ctx, auth)
	if err != nil {
		return nil, berrors.Wrap(ctx, err, berrors.Op(op), berrors.WithMsg("resolving recording spec"))
	}
	if spec.Meta == nil || spec.SessionMeta == nil || spec.Keys == nil || spec.ConnectionId == "" {
		return nil, errNew(ctx, op, "incomplete recording spec")
	}
	sid := auth.SessionId
	if err := f.deps.Scratch.Reserve(sid, spec.Capacity); err != nil {
		return nil, berrors.Wrap(ctx, err, berrors.Op(op), berrors.WithMsg("reserving recording capacity"))
	}
	// Nothing has been recorded yet, so the reservation can be dropped if
	// setup fails.
	fail := func(err error, msg string) (Upstream, error) {
		_ = f.deps.Scratch.Discard(sid)
		return nil, berrors.Wrap(ctx, err, berrors.Op(op), berrors.WithMsg(msg))
	}
	fs, err := bsrfs.New(f.deps.Scratch, sid)
	if err != nil {
		return fail(err, "creating recording storage")
	}
	sess, err := bsr.NewSession(ctx, spec.Meta, spec.SessionMeta, fs, spec.Keys, bsr.WithSupportsMultiplex(true))
	if err != nil {
		return fail(err, "creating BSR session")
	}
	rec, err := recorder.NewRecorder(ctx, sess, spec.ConnectionId)
	if err != nil {
		return fail(err, "creating BSR recorder")
	}
	ru, err := NewRecordingUpstream(ctx, inner, RecordingDeps{
		SessionId: sid,
		Capacity:  spec.Capacity,
		// The capacity was reserved above, before the BSR meta files were
		// written, so the dial must not reserve it again.
		Scratch:    &reservedScratch{ScratchReserver: f.deps.Scratch},
		Recorder:   rec,
		Terminator: spec.Terminator,
		Marker:     spec.Marker,
	})
	if err != nil {
		return fail(err, "creating recording upstream")
	}
	return &finalizingUpstream{inner: ru, f: f, sessionId: sid, ctx: context.WithoutCancel(ctx)}, nil
}

// reservedScratch makes the first Reserve a no-op because the factory has
// already reserved the session's capacity.
type reservedScratch struct {
	ScratchReserver
	once sync.Once
}

func (r *reservedScratch) Reserve(sessionID string, capacity int64) error {
	skipped := false
	r.once.Do(func() { skipped = true })
	if skipped {
		return nil
	}
	return r.ScratchReserver.Reserve(sessionID, capacity)
}

// finalizingUpstream finalises the recording when the connection it dials is
// closed.
type finalizingUpstream struct {
	inner     *RecordingUpstream
	f         *recordingFactory
	sessionId string
	ctx       context.Context
}

func (u *finalizingUpstream) Dial(ctx context.Context) (UpstreamConn, error) {
	conn, err := u.inner.Dial(ctx)
	if err != nil {
		return nil, err
	}
	return &finalizingConn{UpstreamConn: conn, u: u}, nil
}

type finalizingConn struct {
	UpstreamConn
	u    *finalizingUpstream
	once sync.Once
	err  error
}

// Close closes the recording connection and then finalises the recording
// exactly once. Finalisation failures keep the scratch data (for orphan
// recovery), are reported, and are returned; nothing is discarded here.
func (c *finalizingConn) Close() error {
	c.once.Do(func() {
		closeErr := c.UpstreamConn.Close()
		ctx, cancel := context.WithTimeout(c.u.ctx, finalizeTimeout)
		defer cancel()
		res, ferr := c.u.f.deps.Finalizer.Finalize(ctx, c.u.sessionId)
		c.u.f.deps.Reporter.RecordingFinalized(ctx, c.u.sessionId, res, ferr)
		if ferr != nil {
			ferr = fmt.Errorf("ssh.recordingFactory: finalising recording: %w", ferr)
		}
		c.err = errors.Join(closeErr, ferr)
	})
	return c.err
}
