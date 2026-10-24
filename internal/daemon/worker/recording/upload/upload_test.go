// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package upload

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeUploader struct {
	failures int // number of initial calls that fail
	calls    int
	err      error
	cancel   context.CancelFunc // if set, called on first upload
}

func (f *fakeUploader) Upload(ctx context.Context, _ Recording) error {
	f.calls++
	if f.cancel != nil {
		f.cancel()
	}
	if f.calls <= f.failures {
		if f.err != nil {
			return f.err
		}
		return errors.New("boom")
	}
	return nil
}

type fakeValidator struct{ err error }

func (f fakeValidator) Validate(context.Context, Recording) error { return f.err }

type fakeClock struct {
	sleeps []time.Duration
	cancel context.CancelFunc // if set, called on first sleep
}

func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	c.sleeps = append(c.sleeps, d)
	if c.cancel != nil {
		c.cancel()
	}
	return ctx.Err()
}

type fakeSink struct {
	mu     sync.Mutex
	events []Event
}

func (s *fakeSink) Emit(e Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

func (s *fakeSink) types() []EventType {
	var out []EventType
	for _, e := range s.events {
		out = append(out, e.Type)
	}
	return out
}

var rec = Recording{SessionID: "s_1", Dir: "/scratch/s_1"}

func newMgr(t *testing.T, up Uploader, val Validator, clk Clock, sink EventSink, opts Options) *Manager {
	t.Helper()
	if opts.Jitter == nil {
		opts.Jitter = func() float64 { return 0.999999 }
	}
	m, err := New(up, val, clk, sink, opts)
	require.NoError(t, err)
	return m
}

func TestNewValidation(t *testing.T) {
	up, val, clk, sink := &fakeUploader{}, fakeValidator{}, &fakeClock{}, &fakeSink{}
	_, err := New(nil, val, clk, sink, Options{})
	assert.Error(t, err)
	_, err = New(up, nil, clk, sink, Options{})
	assert.Error(t, err)
	_, err = New(up, val, nil, sink, Options{})
	assert.Error(t, err)
	_, err = New(up, val, clk, nil, Options{})
	assert.Error(t, err)
	_, err = New(up, val, clk, sink, Options{BaseDelay: time.Minute, MaxDelay: time.Second})
	assert.Error(t, err)
	_, err = New(up, val, clk, sink, Options{MaxAttempts: -1})
	assert.Error(t, err)
}

func TestSubmitSuccessFirstTry(t *testing.T) {
	up, clk, sink := &fakeUploader{}, &fakeClock{}, &fakeSink{}
	var uploaded []Recording
	m := newMgr(t, up, fakeValidator{}, clk, sink, Options{OnUploaded: func(r Recording) { uploaded = append(uploaded, r) }})
	res := m.Submit(context.Background(), rec)
	assert.Equal(t, Result{Status: StatusUploaded, Attempts: 1}, res)
	assert.Equal(t, []Recording{rec}, uploaded)
	assert.Empty(t, clk.sleeps)
	assert.Equal(t, []EventType{EventUploaded}, sink.types())
}

func TestSubmitSuccessAfterFailures(t *testing.T) {
	up, clk, sink := &fakeUploader{failures: 3}, &fakeClock{}, &fakeSink{}
	called := 0
	m := newMgr(t, up, fakeValidator{}, clk, sink, Options{
		BaseDelay: time.Second, MaxDelay: 3 * time.Second, MaxAttempts: 5,
		OnUploaded: func(Recording) { called++ },
	})
	res := m.Submit(context.Background(), rec)
	assert.Equal(t, StatusUploaded, res.Status)
	assert.Equal(t, 4, res.Attempts)
	assert.Equal(t, 1, called)
	require.Len(t, clk.sleeps, 3)
	// jitter ~1.0: 1s, 2s, then capped at 3s.
	for i, want := range []time.Duration{time.Second, 2 * time.Second, 3 * time.Second} {
		assert.InDelta(t, float64(want), float64(clk.sleeps[i]), float64(time.Millisecond), "sleep %d", i)
		assert.LessOrEqual(t, clk.sleeps[i], want)
	}
	assert.Equal(t, []EventType{EventRetry, EventRetry, EventRetry, EventUploaded}, sink.types())
}

func TestBackoffJitterBounds(t *testing.T) {
	m := newMgr(t, &fakeUploader{}, fakeValidator{}, &fakeClock{}, &fakeSink{}, Options{
		BaseDelay: time.Second, MaxDelay: 8 * time.Second, Jitter: func() float64 { return 0 },
	})
	assert.Equal(t, 500*time.Millisecond, m.backoff(1))
	assert.Equal(t, 4*time.Second, m.backoff(4)) // 8s * 0.5
	assert.Equal(t, 4*time.Second, m.backoff(50), "capped, no overflow")
}

func TestSubmitExhaustion(t *testing.T) {
	up := &fakeUploader{failures: 100, err: errors.New("bucket down")}
	clk, sink := &fakeClock{}, &fakeSink{}
	called := 0
	m := newMgr(t, up, fakeValidator{}, clk, sink, Options{MaxAttempts: 3, OnUploaded: func(Recording) { called++ }})
	res := m.Submit(context.Background(), rec)
	assert.Equal(t, StatusPending, res.Status)
	assert.Equal(t, 3, res.Attempts)
	assert.ErrorContains(t, res.Err, "bucket down")
	assert.Equal(t, 3, up.calls)
	assert.Equal(t, 0, called, "OnUploaded never called on failure")
	assert.Len(t, clk.sleeps, 2)
	assert.Equal(t, []EventType{EventRetry, EventRetry, EventPending}, sink.types())
	assert.Equal(t, "s_1", sink.events[2].SessionID)
}

func TestSubmitValidationFailure(t *testing.T) {
	up, clk, sink := &fakeUploader{}, &fakeClock{}, &fakeSink{}
	called := 0
	m := newMgr(t, up, fakeValidator{err: errors.New("bad checksum")}, clk, sink, Options{OnUploaded: func(Recording) { called++ }})
	res := m.Submit(context.Background(), rec)
	assert.Equal(t, StatusInvalid, res.Status)
	assert.ErrorContains(t, res.Err, "bad checksum")
	assert.Equal(t, 0, up.calls, "invalid recording is never uploaded")
	assert.Equal(t, 0, called)
	assert.Equal(t, []EventType{EventInvalid}, sink.types())
}

func TestSubmitCancelDuringBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	up := &fakeUploader{failures: 100}
	clk, sink := &fakeClock{cancel: cancel}, &fakeSink{}
	called := 0
	m := newMgr(t, up, fakeValidator{}, clk, sink, Options{MaxAttempts: 5, OnUploaded: func(Recording) { called++ }})
	before := runtime.NumGoroutine()
	res := m.Submit(ctx, rec)
	assert.Equal(t, StatusCanceled, res.Status)
	assert.ErrorIs(t, res.Err, context.Canceled)
	assert.Equal(t, 1, up.calls, "no retries after cancellation")
	assert.Equal(t, 0, called)
	assert.NotContains(t, sink.types(), EventPending)
	assert.LessOrEqual(t, runtime.NumGoroutine(), before, "no goroutines leaked")
}

func TestSubmitCancelBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	up := &fakeUploader{}
	m := newMgr(t, up, fakeValidator{}, &fakeClock{}, &fakeSink{}, Options{})
	res := m.Submit(ctx, rec)
	assert.Equal(t, StatusCanceled, res.Status)
	assert.Equal(t, 0, up.calls)
}

func TestSubmitCancelDuringUpload(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	up := &fakeUploader{failures: 100, cancel: cancel}
	clk := &fakeClock{}
	m := newMgr(t, up, fakeValidator{}, clk, &fakeSink{}, Options{})
	res := m.Submit(ctx, rec)
	assert.Equal(t, StatusCanceled, res.Status)
	assert.Equal(t, 1, up.calls)
	assert.Empty(t, clk.sleeps)
}
