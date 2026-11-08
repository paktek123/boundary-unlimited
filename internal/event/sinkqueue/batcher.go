// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

// Package sinkqueue is a transport-agnostic, bounded batching queue with
// retry/backoff for event sinks. It opens no connections, reads no
// configuration and is not wired into the event system yet.
//
// Delivery guarantees follow event.DeliveryGuarantee:
//
//   - Enforced fails closed: a full queue makes Enqueue return ErrQueueFull,
//     and a batch whose retries are exhausted makes the Batcher permanently
//     failed (Enqueue returns ErrDeliveryFailed, Close returns an error), so
//     the caller can stop rather than silently lose audit events.
//   - BestEffort (and the default) drops the oldest entries when full and
//     drops a batch whose retries are exhausted; every drop is counted.
package sinkqueue

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/boundary/internal/event"
)

// Hard limits. Configuration above them is rejected, never clamped.
const (
	HardMaxEntries  = 100_000
	HardMaxBytes    = 64 << 20
	HardMaxAttempts = 10
)

// Errors.
var (
	ErrInvalidConfig    = errors.New("sinkqueue: invalid configuration")
	ErrQueueFull        = errors.New("sinkqueue: queue is full")
	ErrEntryTooLarge    = errors.New("sinkqueue: entry exceeds the queue byte limit")
	ErrClosed           = errors.New("sinkqueue: batcher is closed")
	ErrDeliveryFailed   = errors.New("sinkqueue: delivery failed and the delivery guarantee is enforced")
	ErrRetriesExhausted = errors.New("sinkqueue: retries exhausted")
	ErrDropped          = errors.New("sinkqueue: entries were dropped")
)

// Sender delivers one batch. It must respect ctx.
type Sender interface {
	Send(ctx context.Context, batch [][]byte) error
}

// Clock abstracts time so tests need no sleeps.
type Clock interface {
	After(d time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// Config configures a Batcher. All of Sender, MaxEntries, MaxBytes, BatchSize,
// FlushInterval, MaxAttempts, BaseBackoff and MaxBackoff are required.
type Config struct {
	Sender        Sender
	MaxEntries    int
	MaxBytes      int
	BatchSize     int // flush when this many entries are queued; <= MaxEntries
	FlushInterval time.Duration
	MaxAttempts   int // total send attempts per batch
	BaseBackoff   time.Duration
	MaxBackoff    time.Duration
	Guarantee     event.DeliveryGuarantee

	// Clock and Jitter are optional (tests). Jitter returns a value in [0,1).
	Clock  Clock
	Jitter func() float64
}

func (c Config) validate() error {
	switch {
	case c.Sender == nil,
		c.MaxEntries <= 0 || c.MaxEntries > HardMaxEntries,
		c.MaxBytes <= 0 || c.MaxBytes > HardMaxBytes,
		c.BatchSize <= 0 || c.BatchSize > c.MaxEntries,
		c.FlushInterval <= 0,
		c.MaxAttempts <= 0 || c.MaxAttempts > HardMaxAttempts,
		c.BaseBackoff <= 0 || c.MaxBackoff < c.BaseBackoff:
		return ErrInvalidConfig
	}
	switch c.Guarantee {
	case event.DefaultDeliveryGuarantee, event.BestEffort, event.Enforced:
	default:
		return ErrInvalidConfig
	}
	return nil
}

// Batcher is a bounded batching queue. Create it with New.
//
// Memory bound: MaxEntries and MaxBytes limit the QUEUED entries. A batch that
// is being sent (and retried) has left the queue, so worst-case memory is
// about the queue limit plus one batch (at most BatchSize entries).
type Batcher struct {
	cfg   Config
	clock Clock

	mu      sync.Mutex
	q       [][]byte
	bytes   int
	closed  bool
	failErr error

	dropped atomic.Uint64
	sent    atomic.Uint64

	wake    chan struct{}
	closing chan struct{}
	done    chan struct{}
	cancel  context.CancelFunc
	once    sync.Once
}

// New validates cfg and starts the single worker goroutine.
func New(cfg Config) (*Batcher, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	b := &Batcher{
		cfg:     cfg,
		clock:   cfg.Clock,
		wake:    make(chan struct{}, 1),
		closing: make(chan struct{}),
		done:    make(chan struct{}),
	}
	if b.clock == nil {
		b.clock = realClock{}
	}
	if b.cfg.Jitter == nil {
		b.cfg.Jitter = rand.Float64
	}
	ctx, cancel := context.WithCancel(context.Background())
	b.cancel = cancel
	go b.run(ctx)
	return b, nil
}

// Dropped returns the number of entries dropped so far.
func (b *Batcher) Dropped() uint64 { return b.dropped.Load() }

// Sent returns the number of entries successfully delivered so far.
func (b *Batcher) Sent() uint64 { return b.sent.Load() }

// Enqueue copies entry into the queue.
func (b *Batcher) Enqueue(entry []byte) error {
	if len(entry) > b.cfg.MaxBytes {
		return ErrEntryTooLarge
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return ErrClosed
	}
	if b.failErr != nil {
		b.mu.Unlock()
		return ErrDeliveryFailed
	}
	full := func() bool {
		return len(b.q)+1 > b.cfg.MaxEntries || b.bytes+len(entry) > b.cfg.MaxBytes
	}
	if full() {
		if b.cfg.Guarantee == event.Enforced {
			b.mu.Unlock()
			return ErrQueueFull
		}
		for full() && len(b.q) > 0 {
			b.bytes -= len(b.q[0])
			b.q[0] = nil
			b.q = b.q[1:]
			b.dropped.Add(1)
		}
	}
	b.q = append(b.q, append([]byte(nil), entry...))
	b.bytes += len(entry)
	n := len(b.q)
	b.mu.Unlock()
	if n >= b.cfg.BatchSize {
		select {
		case b.wake <- struct{}{}:
		default:
		}
	}
	return nil
}

// takeBatch pops up to BatchSize entries. With onlyFull it returns nothing
// unless a full batch is queued.
func (b *Batcher) takeBatch(onlyFull bool) [][]byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failErr != nil || len(b.q) == 0 || (onlyFull && len(b.q) < b.cfg.BatchSize) {
		return nil
	}
	n := b.cfg.BatchSize
	if n > len(b.q) {
		n = len(b.q)
	}
	batch := b.q[:n:n]
	b.q = b.q[n:]
	for _, e := range batch {
		b.bytes -= len(e)
	}
	return batch
}

func (b *Batcher) backoff(attempt int) time.Duration {
	d := b.cfg.BaseBackoff
	for i := 1; i < attempt && d < b.cfg.MaxBackoff; i++ {
		d *= 2
	}
	if d > b.cfg.MaxBackoff {
		d = b.cfg.MaxBackoff
	}
	return time.Duration(float64(d) * (0.5 + b.cfg.Jitter()/2))
}

func (b *Batcher) send(ctx context.Context, batch [][]byte) error {
	var err error
	for attempt := 1; attempt <= b.cfg.MaxAttempts; attempt++ {
		if err = b.cfg.Sender.Send(ctx, batch); err == nil {
			return nil
		}
		if attempt == b.cfg.MaxAttempts {
			break
		}
		select {
		case <-b.clock.After(b.backoff(attempt)):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return fmt.Errorf("%w: %w", ErrRetriesExhausted, err)
}

// deliver sends one batch and applies the delivery guarantee on failure.
func (b *Batcher) deliver(ctx context.Context, batch [][]byte) {
	if err := b.send(ctx, batch); err != nil {
		if b.cfg.Guarantee == event.Enforced {
			b.mu.Lock()
			if b.failErr == nil {
				b.failErr = err
			}
			// The failed batch is neither delivered nor silently lost: it is
			// counted as dropped and the Batcher is failed for good.
			b.mu.Unlock()
		}
		b.dropped.Add(uint64(len(batch)))
		return
	}
	b.sent.Add(uint64(len(batch)))
}

func (b *Batcher) run(ctx context.Context) {
	defer close(b.done)
	tick := b.clock.After(b.cfg.FlushInterval)
	for {
		select {
		case <-b.wake:
			for batch := b.takeBatch(true); batch != nil; batch = b.takeBatch(true) {
				b.deliver(ctx, batch)
			}
		case <-tick:
			for batch := b.takeBatch(false); batch != nil; batch = b.takeBatch(false) {
				b.deliver(ctx, batch)
			}
			tick = b.clock.After(b.cfg.FlushInterval)
		case <-b.closing:
			for batch := b.takeBatch(false); batch != nil; batch = b.takeBatch(false) {
				if ctx.Err() != nil {
					b.dropped.Add(uint64(len(batch)))
					continue
				}
				b.deliver(ctx, batch)
			}
			// Anything left (failed Batcher) is dropped and counted.
			b.mu.Lock()
			left := len(b.q)
			b.q, b.bytes = nil, 0
			b.mu.Unlock()
			b.dropped.Add(uint64(left))
			return
		}
	}
}

// Close stops accepting entries, flushes what is queued and waits for the
// worker. If ctx ends first, in-flight work is cancelled and the remainder is
// counted as dropped. It returns an error wrapping ErrDropped when anything was
// ever dropped, and the delivery failure for an Enforced Batcher. It is safe to
// call more than once.
func (b *Batcher) Close(ctx context.Context) error {
	b.once.Do(func() {
		b.mu.Lock()
		b.closed = true
		b.mu.Unlock()
		close(b.closing)
	})
	select {
	case <-b.done:
	case <-ctx.Done():
		b.cancel()
		<-b.done
	}
	b.cancel()
	b.mu.Lock()
	fail := b.failErr
	b.mu.Unlock()
	if fail != nil {
		return fmt.Errorf("%w: %w (dropped %d)", ErrDeliveryFailed, fail, b.Dropped())
	}
	if d := b.Dropped(); d > 0 {
		return fmt.Errorf("%w: %d", ErrDropped, d)
	}
	return nil
}
