// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package sinkqueue

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/event"
	"github.com/stretchr/testify/require"
)

type fakeClock struct {
	mu      sync.Mutex
	now     time.Duration
	waiters []waiter
}

type waiter struct {
	at time.Duration
	ch chan time.Time
}

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	c.waiters = append(c.waiters, waiter{at: c.now + d, ch: ch})
	return ch
}

func (c *fakeClock) pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.waiters)
}

// blockUntil waits (bounded) until n timers are pending.
func (c *fakeClock) blockUntil(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for c.pending() < n {
		require.True(t, time.Now().Before(deadline), "timeout waiting for %d timers", n)
		time.Sleep(time.Millisecond) // real-time polling only; the batcher itself never sleeps
	}
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now += d
	var rest []waiter
	for _, w := range c.waiters {
		if w.at <= c.now {
			w.ch <- time.Time{}
		} else {
			rest = append(rest, w)
		}
	}
	c.waiters = rest
}

type fakeSender struct {
	mu       sync.Mutex
	failures int // fail this many calls first
	always   bool
	calls    int
	got      [][]string
	gotCh    chan struct{}
}

func newSender() *fakeSender { return &fakeSender{gotCh: make(chan struct{}, 1000)} }

func (s *fakeSender) Send(ctx context.Context, batch [][]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.always || s.failures > 0 {
		if s.failures > 0 {
			s.failures--
		}
		return errors.New("boom")
	}
	var b []string
	for _, e := range batch {
		b = append(b, string(e))
	}
	s.got = append(s.got, b)
	s.gotCh <- struct{}{}
	return nil
}

func (s *fakeSender) wait(t *testing.T) {
	t.Helper()
	select {
	case <-s.gotCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for batch")
	}
}

func (s *fakeSender) batches() [][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]string(nil), s.got...)
}

func cfg(s Sender, c Clock, g event.DeliveryGuarantee) Config {
	return Config{
		Sender: s, MaxEntries: 10, MaxBytes: 10, BatchSize: 2, FlushInterval: time.Minute,
		MaxAttempts: 3, BaseBackoff: time.Second, MaxBackoff: 4 * time.Second,
		Guarantee: g, Clock: c, Jitter: func() float64 { return 0 },
	}
}

func TestConfigValidation(t *testing.T) {
	s := newSender()
	tests := map[string]func(*Config){
		"nil sender":        func(c *Config) { c.Sender = nil },
		"zero entries":      func(c *Config) { c.MaxEntries = 0 },
		"entries too big":   func(c *Config) { c.MaxEntries = HardMaxEntries + 1 },
		"bytes too big":     func(c *Config) { c.MaxBytes = HardMaxBytes + 1 },
		"batch > entries":   func(c *Config) { c.BatchSize = 11 },
		"zero interval":     func(c *Config) { c.FlushInterval = 0 },
		"attempts too many": func(c *Config) { c.MaxAttempts = HardMaxAttempts + 1 },
		"zero attempts":     func(c *Config) { c.MaxAttempts = 0 },
		"max<base backoff":  func(c *Config) { c.MaxBackoff = time.Millisecond },
		"bad guarantee":     func(c *Config) { c.Guarantee = "nope" },
	}
	for name, f := range tests {
		t.Run(name, func(t *testing.T) {
			c := cfg(s, &fakeClock{}, event.Enforced)
			f(&c)
			_, err := New(c)
			require.ErrorIs(t, err, ErrInvalidConfig)
		})
	}
}

func TestFlushOnSize(t *testing.T) {
	s, clk := newSender(), &fakeClock{}
	b, err := New(cfg(s, clk, event.BestEffort))
	require.NoError(t, err)
	require.NoError(t, b.Enqueue([]byte("a")))
	require.NoError(t, b.Enqueue([]byte("b")))
	s.wait(t)
	require.Equal(t, [][]string{{"a", "b"}}, s.batches())
	require.NoError(t, b.Close(context.Background()))
	require.EqualValues(t, 2, b.Sent())
}

func TestFlushOnInterval(t *testing.T) {
	s, clk := newSender(), &fakeClock{}
	b, err := New(cfg(s, clk, event.Enforced))
	require.NoError(t, err)
	require.NoError(t, b.Enqueue([]byte("a")))
	clk.blockUntil(t, 1)
	clk.advance(time.Minute)
	s.wait(t)
	require.Equal(t, [][]string{{"a"}}, s.batches())
	require.NoError(t, b.Close(context.Background()))
}

func TestRetryThenSuccess(t *testing.T) {
	s, clk := newSender(), &fakeClock{}
	s.failures = 2
	b, err := New(cfg(s, clk, event.Enforced))
	require.NoError(t, err)
	require.NoError(t, b.Enqueue([]byte("a")))
	require.NoError(t, b.Enqueue([]byte("b")))
	clk.blockUntil(t, 2) // interval + first backoff
	clk.advance(time.Second)
	clk.blockUntil(t, 2) // interval + second backoff
	clk.advance(2 * time.Second)
	s.wait(t)
	require.Equal(t, 3, s.calls)
	require.NoError(t, b.Close(context.Background()))
	require.EqualValues(t, 0, b.Dropped())
}

func TestRetriesExhaustedBestEffortDropsAndContinues(t *testing.T) {
	s, clk := newSender(), &fakeClock{}
	s.always = true
	b, err := New(cfg(s, clk, event.BestEffort))
	require.NoError(t, err)
	require.NoError(t, b.Enqueue([]byte("a")))
	require.NoError(t, b.Enqueue([]byte("b")))
	clk.blockUntil(t, 2)
	clk.advance(time.Second)
	clk.blockUntil(t, 2)
	clk.advance(2 * time.Second)
	deadline := time.Now().Add(5 * time.Second)
	for b.Dropped() != 2 {
		require.True(t, time.Now().Before(deadline))
		time.Sleep(time.Millisecond)
	}
	require.NoError(t, b.Enqueue([]byte("c")), "best effort keeps accepting")
	// The sender still fails and the fake clock never advances, so end the
	// drain with a cancelled context; the remainder is counted as dropped.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = b.Close(ctx)
	require.ErrorIs(t, err, ErrDropped)
	require.EqualValues(t, 3, b.Dropped())
}

func TestRetriesExhaustedEnforcedFailsClosed(t *testing.T) {
	s, clk := newSender(), &fakeClock{}
	s.always = true
	b, err := New(cfg(s, clk, event.Enforced))
	require.NoError(t, err)
	require.NoError(t, b.Enqueue([]byte("a")))
	require.NoError(t, b.Enqueue([]byte("b")))
	clk.blockUntil(t, 2)
	clk.advance(time.Second)
	clk.blockUntil(t, 2)
	clk.advance(2 * time.Second)
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := b.Enqueue([]byte("x"))
		if errors.Is(err, ErrDeliveryFailed) {
			break
		}
		require.True(t, time.Now().Before(deadline), "enqueue must fail once delivery failed")
		time.Sleep(time.Millisecond)
	}
	err = b.Close(context.Background())
	require.ErrorIs(t, err, ErrDeliveryFailed)
	require.ErrorIs(t, err, ErrRetriesExhausted)
}

func TestQueueFull(t *testing.T) {
	t.Run("enforced rejects", func(t *testing.T) {
		b, err := New(cfg(newSender(), &fakeClock{}, event.Enforced))
		require.NoError(t, err)
		require.NoError(t, b.Enqueue([]byte("123456")))
		require.ErrorIs(t, b.Enqueue([]byte("123456")), ErrQueueFull)
		require.ErrorIs(t, b.Enqueue(make([]byte, 11)), ErrEntryTooLarge)
		require.EqualValues(t, 0, b.Dropped())
		require.NoError(t, b.Close(context.Background()))
	})
	t.Run("best effort drops oldest", func(t *testing.T) {
		s := newSender()
		b, err := New(cfg(s, &fakeClock{}, event.BestEffort))
		require.NoError(t, err)
		require.NoError(t, b.Enqueue([]byte("123456")))
		require.NoError(t, b.Enqueue([]byte("abcdef")))
		require.EqualValues(t, 1, b.Dropped())
		require.ErrorIs(t, b.Close(context.Background()), ErrDropped)
		require.Equal(t, [][]string{{"abcdef"}}, s.batches())
	})
}

func TestCloseFlushesAndIsIdempotent(t *testing.T) {
	s := newSender()
	b, err := New(cfg(s, &fakeClock{}, event.Enforced))
	require.NoError(t, err)
	require.NoError(t, b.Enqueue([]byte("a")))
	require.NoError(t, b.Close(context.Background()))
	require.NoError(t, b.Close(context.Background()))
	require.Equal(t, [][]string{{"a"}}, s.batches())
	require.ErrorIs(t, b.Enqueue([]byte("b")), ErrClosed)
	select {
	case <-b.done:
	default:
		t.Fatal("worker goroutine still running after Close")
	}
}

func TestCloseContextCancelReportsDropped(t *testing.T) {
	s, clk := newSender(), &fakeClock{}
	s.always = true
	b, err := New(cfg(s, clk, event.BestEffort))
	require.NoError(t, err)
	require.NoError(t, b.Enqueue([]byte("a")))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = b.Close(ctx)
	require.ErrorIs(t, err, ErrDropped)
	require.EqualValues(t, 1, b.Dropped())
}

func TestCloseContextCancelEnforcedReportsDeliveryFailed(t *testing.T) {
	s, clk := newSender(), &fakeClock{}
	s.always = true
	b, err := New(cfg(s, clk, event.Enforced))
	require.NoError(t, err)
	require.NoError(t, b.Enqueue([]byte("a")))
	require.NoError(t, b.Enqueue([]byte("b")))
	clk.blockUntil(t, 2) // worker is in the first backoff wait
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = b.Close(ctx)
	require.ErrorIs(t, err, ErrDeliveryFailed)
	require.ErrorIs(t, err, context.Canceled)
	require.EqualValues(t, 2, b.Dropped())
}

func TestConcurrentEnqueueAccounting(t *testing.T) {
	s := newSender()
	c := cfg(s, nil, event.BestEffort)
	c.Clock = nil
	c.MaxEntries, c.MaxBytes, c.BatchSize = 1000, 1000, 10
	b, err := New(c)
	require.NoError(t, err)
	var wg sync.WaitGroup
	const workers, per = 8, 100
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				_ = b.Enqueue([]byte(fmt.Sprintf("%d", w)))
			}
		}(w)
	}
	wg.Wait()
	_ = b.Close(context.Background())
	require.EqualValues(t, workers*per, b.Sent()+b.Dropped())
}
