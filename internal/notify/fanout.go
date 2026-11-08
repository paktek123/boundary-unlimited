// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package notify

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Fan-out limits.
const (
	DefaultFanOutTimeout = 10 * time.Second
	MaxFanOutTimeout     = time.Minute
	MaxFanOutNotifiers   = 32
)

// Errors in the aggregated error returned by FanOut.Notify. They are fixed
// text: the underlying error of a failing notifier is deliberately dropped,
// because it may carry a destination URL or other secret.
var (
	ErrInvalidFanOut    = errors.New("notify: invalid fan-out configuration")
	ErrNotifierFailed   = errors.New("notify: notifier failed")
	ErrNotifierTimeout  = errors.New("notify: notifier timed out")
	ErrNotifierPanicked = errors.New("notify: notifier panicked")
	ErrFanOutCancelled  = errors.New("notify: fan-out cancelled")
)

// FanOut is a Notifier that delivers each event to several notifiers
// concurrently. One slow, failing or panicking notifier does not block or fail
// the others: every notifier gets its own timeout, and the aggregated error
// lists only the index and a fixed reason for each one that did not succeed.
//
// A notifier that ignores its context and never returns is abandoned when its
// timeout expires; its goroutine ends whenever the notifier eventually returns.
type FanOut struct {
	notifiers []Notifier
	timeout   time.Duration
}

// NewFanOut returns a FanOut. timeout <= 0 selects DefaultFanOutTimeout; a
// timeout above MaxFanOutTimeout, no notifiers, more than MaxFanOutNotifiers
// or a nil notifier is an error.
func NewFanOut(timeout time.Duration, notifiers ...Notifier) (*FanOut, error) {
	if timeout <= 0 {
		timeout = DefaultFanOutTimeout
	}
	if timeout > MaxFanOutTimeout || len(notifiers) == 0 || len(notifiers) > MaxFanOutNotifiers {
		return nil, ErrInvalidFanOut
	}
	for _, n := range notifiers {
		if n == nil {
			return nil, ErrInvalidFanOut
		}
	}
	return &FanOut{notifiers: append([]Notifier(nil), notifiers...), timeout: timeout}, nil
}

// Notify implements Notifier. It returns nil only if every notifier succeeded.
func (f *FanOut) Notify(ctx context.Context, e Event) error {
	if f == nil || len(f.notifiers) == 0 {
		return ErrInvalidFanOut
	}
	if err := e.Validate(); err != nil {
		return err
	}
	errs := make([]error, len(f.notifiers))
	var wg sync.WaitGroup
	for i, n := range f.notifiers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = f.deliver(ctx, i, n, e)
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}

func (f *FanOut) deliver(ctx context.Context, i int, n Notifier, e Event) error {
	nctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()
	// Buffered so an abandoned notifier can still finish without blocking.
	done := make(chan error, 1)
	go func() {
		defer func() {
			if recover() != nil { // the value is discarded: it may hold secrets
				done <- ErrNotifierPanicked
			}
		}()
		if err := n.Notify(nctx, e); err != nil {
			done <- ErrNotifierFailed
			return
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("notifier %d: %w", i, err)
		}
		return nil
	case <-nctx.Done():
		// Prefer a result that raced in with the deadline.
		select {
		case err := <-done:
			if err != nil {
				return fmt.Errorf("notifier %d: %w", i, err)
			}
			return nil
		default:
		}
		if ctx.Err() != nil {
			return fmt.Errorf("notifier %d: %w", i, ErrFanOutCancelled)
		}
		return fmt.Errorf("notifier %d: %w", i, ErrNotifierTimeout)
	}
}

// RecorderNotifier is a concurrency-safe in-memory Notifier for tests. If Err
// is set, Notify records nothing and returns it.
type RecorderNotifier struct {
	mu     sync.Mutex
	Err    error
	events []Event
}

// Notify implements Notifier.
func (r *RecorderNotifier) Notify(_ context.Context, e Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Err != nil {
		return r.Err
	}
	r.events = append(r.events, e)
	return nil
}

// Events returns a copy of the recorded events.
func (r *RecorderNotifier) Events() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Event(nil), r.events...)
}
