// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package upload implements the retry/backoff manager for uploading finished
// session recordings, per the "Failure modes" section of
// docs/rfc/ssh-session-recording.md: when an upload fails the recording stays
// on scratch, is reported pending and an event is emitted. A recording is
// never deleted by this package, and an invalid recording is never uploaded.
//
// The package is a standalone library and is not wired into the worker.
package upload

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"
)

// Recording identifies a finished recording on scratch storage.
type Recording struct {
	SessionID string
	// Dir is the directory holding the finished recording.
	Dir string
}

// Uploader uploads a finished recording. It must return nil only after the
// upload has succeeded.
type Uploader interface {
	Upload(ctx context.Context, rec Recording) error
}

// Validator checks that a recording is valid (typically wrapping
// bsr.Validate). An invalid recording is never uploaded.
type Validator interface {
	Validate(ctx context.Context, rec Recording) error
}

// Clock abstracts time so tests can run without real sleeping.
type Clock interface {
	// Sleep blocks for d or until ctx is done, returning ctx.Err() in the
	// latter case.
	Sleep(ctx context.Context, d time.Duration) error
}

// EventType is the kind of event emitted.
type EventType string

const (
	// EventRetry is emitted after a failed attempt that will be retried.
	EventRetry EventType = "retry"
	// EventPending is emitted when attempts are exhausted; the recording
	// stays on scratch and is reported pending.
	EventPending EventType = "pending"
	// EventInvalid is emitted when validation fails; nothing is uploaded.
	EventInvalid EventType = "invalid"
	// EventUploaded is emitted after a verified successful upload.
	EventUploaded EventType = "uploaded"
)

// Event describes something the operator may need to know about.
type Event struct {
	Type      EventType
	SessionID string
	Attempt   int
	Err       error
}

// EventSink receives events. Implementations must not block for long.
type EventSink interface {
	Emit(Event)
}

// Status is the outcome of Submit.
type Status int

const (
	// StatusUploaded means the recording was uploaded.
	StatusUploaded Status = iota
	// StatusPending means the recording is still on scratch and not uploaded.
	StatusPending
	// StatusInvalid means validation failed; the recording was not uploaded.
	StatusInvalid
	// StatusCanceled means the context ended before the upload completed;
	// the recording is still on scratch.
	StatusCanceled
)

// Result reports the outcome of Submit.
type Result struct {
	Status   Status
	Attempts int
	Err      error
}

// Options configure a Manager. Zero values for the numeric fields select the
// defaults.
type Options struct {
	BaseDelay   time.Duration // default 1s
	MaxDelay    time.Duration // default 5m
	MaxAttempts int           // default 5
	// OnUploaded is called only after a successful upload, so a scratch
	// store can delete files only after a verified upload. It is never
	// called on failure.
	OnUploaded func(Recording)
	// Jitter returns a value in [0,1); default math/rand/v2.Float64.
	Jitter func() float64
}

// Manager uploads recordings with capped exponential backoff and jitter.
type Manager struct {
	up    Uploader
	val   Validator
	clock Clock
	sink  EventSink
	opts  Options
}

// New creates a Manager. All of the collaborators are required.
func New(up Uploader, val Validator, clock Clock, sink EventSink, opts Options) (*Manager, error) {
	switch {
	case up == nil:
		return nil, errors.New("upload: uploader is required")
	case val == nil:
		return nil, errors.New("upload: validator is required")
	case clock == nil:
		return nil, errors.New("upload: clock is required")
	case sink == nil:
		return nil, errors.New("upload: event sink is required")
	}
	if opts.BaseDelay < 0 || opts.MaxDelay < 0 || opts.MaxAttempts < 0 {
		return nil, errors.New("upload: negative option")
	}
	if opts.BaseDelay == 0 {
		opts.BaseDelay = time.Second
	}
	if opts.MaxDelay == 0 {
		opts.MaxDelay = 5 * time.Minute
	}
	if opts.MaxAttempts == 0 {
		opts.MaxAttempts = 5
	}
	if opts.MaxDelay < opts.BaseDelay {
		return nil, errors.New("upload: max delay is below base delay")
	}
	if opts.Jitter == nil {
		opts.Jitter = rand.Float64
	}
	return &Manager{up: up, val: val, clock: clock, sink: sink, opts: opts}, nil
}

// backoff returns the delay after the given (1-based) failed attempt:
// min(max, base*2^(attempt-1)) scaled by a jitter factor in [0.5, 1.0).
func (m *Manager) backoff(attempt int) time.Duration {
	d := m.opts.BaseDelay
	for i := 1; i < attempt && d < m.opts.MaxDelay; i++ {
		d *= 2
	}
	if d > m.opts.MaxDelay || d <= 0 {
		d = m.opts.MaxDelay
	}
	return time.Duration(float64(d) * (0.5 + m.opts.Jitter()/2))
}

// Submit validates and uploads rec, retrying failed uploads. Submit blocks
// until the outcome is known or ctx is done, and runs no goroutines of its
// own. The recording is never deleted here.
func (m *Manager) Submit(ctx context.Context, rec Recording) Result {
	if err := m.val.Validate(ctx, rec); err != nil {
		if ctx.Err() != nil {
			return Result{Status: StatusCanceled, Err: ctx.Err()}
		}
		m.sink.Emit(Event{Type: EventInvalid, SessionID: rec.SessionID, Err: err})
		return Result{Status: StatusInvalid, Err: fmt.Errorf("upload: recording %q is invalid: %w", rec.SessionID, err)}
	}
	var last error
	for attempt := 1; attempt <= m.opts.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return Result{Status: StatusCanceled, Attempts: attempt - 1, Err: err}
		}
		err := m.up.Upload(ctx, rec)
		if err == nil {
			if m.opts.OnUploaded != nil {
				m.opts.OnUploaded(rec)
			}
			m.sink.Emit(Event{Type: EventUploaded, SessionID: rec.SessionID, Attempt: attempt})
			return Result{Status: StatusUploaded, Attempts: attempt}
		}
		last = err
		if ctx.Err() != nil {
			return Result{Status: StatusCanceled, Attempts: attempt, Err: ctx.Err()}
		}
		if attempt == m.opts.MaxAttempts {
			break
		}
		m.sink.Emit(Event{Type: EventRetry, SessionID: rec.SessionID, Attempt: attempt, Err: err})
		if serr := m.clock.Sleep(ctx, m.backoff(attempt)); serr != nil {
			return Result{Status: StatusCanceled, Attempts: attempt, Err: serr}
		}
	}
	m.sink.Emit(Event{Type: EventPending, SessionID: rec.SessionID, Attempt: m.opts.MaxAttempts, Err: last})
	return Result{
		Status:   StatusPending,
		Attempts: m.opts.MaxAttempts,
		Err:      fmt.Errorf("upload: recording %q pending after %d attempts: %w", rec.SessionID, m.opts.MaxAttempts, last),
	}
}
