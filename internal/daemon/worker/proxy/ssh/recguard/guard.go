// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package recguard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
)

// ErrRecordingFailed is returned by every write once the guard has failed,
// including the write that caused the failure.
var ErrRecordingFailed = errors.New("recguard: recording failed, session terminated")

const failureReason = "session recording write failed"

// Sink receives recorded channel data and requests.
type Sink interface {
	Write(p []byte) (int, error)
}

// Terminator terminates the session with a reason.
type Terminator interface {
	Terminate(ctx context.Context, reason string) error
}

// Marker marks the recording as incomplete.
type Marker interface {
	MarkIncomplete(ctx context.Context, reason string) error
}

// Guard wraps a Sink and fails closed: after the first failure the session is
// terminated once, the recording is marked incomplete once, and all later
// writes return an error without reaching the sink.
type Guard struct {
	sink Sink
	term Terminator
	mark Marker

	mu      sync.Mutex
	tripped bool
	cleanup error
}

var _ io.Writer = (*Guard)(nil)

// New returns a Guard. It returns an error if any dependency is nil.
func New(sink Sink, term Terminator, mark Marker) (*Guard, error) {
	switch {
	case isNil(sink):
		return nil, errors.New("recguard: nil sink")
	case isNil(term):
		return nil, errors.New("recguard: nil terminator")
	case isNil(mark):
		return nil, errors.New("recguard: nil marker")
	}
	return &Guard{sink: sink, term: term, mark: mark}, nil
}

// Write writes p to the sink. Any error or short write trips the guard.
// Writes are serialized, so the sink never sees concurrent calls.
func (g *Guard) Write(p []byte) (int, error) {
	return g.WriteContext(context.Background(), p)
}

// WriteContext is Write with a context passed to the terminator and marker.
func (g *Guard) WriteContext(ctx context.Context, p []byte) (int, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.tripped {
		return 0, ErrRecordingFailed
	}
	n, err := g.sink.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err == nil {
		return n, nil
	}
	g.trip(ctx)
	return n, ErrRecordingFailed
}

// Tripped reports whether the guard has failed.
func (g *Guard) Tripped() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.tripped
}

// Err returns the combined errors from the terminator and marker if either
// failed when the guard tripped. It returns nil if the guard has not tripped
// or both calls succeeded.
func (g *Guard) Err() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.cleanup
}

// trip must be called with g.mu held and runs at most once. The recording is
// marked incomplete even if terminating the session fails.
func (g *Guard) trip(ctx context.Context) {
	g.tripped = true
	var termErr, markErr error
	if err := g.term.Terminate(ctx, failureReason); err != nil {
		termErr = fmt.Errorf("recguard: terminate session: %w", err)
	}
	if err := g.mark.MarkIncomplete(ctx, failureReason); err != nil {
		markErr = fmt.Errorf("recguard: mark recording incomplete: %w", err)
	}
	g.cleanup = errors.Join(termErr, markErr)
}

// isNil reports whether v is nil or holds a nil pointer, map, func or slice.
func isNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Func, reflect.Slice, reflect.Interface, reflect.Chan:
		return rv.IsNil()
	}
	return false
}
