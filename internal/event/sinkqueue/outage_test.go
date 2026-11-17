// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package sinkqueue

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/event"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stuckSender simulates a collector that is down: Send blocks until its
// context ends.
type stuckSender struct{ started chan struct{} }

func (s *stuckSender) Send(ctx context.Context, _ [][]byte) error {
	select {
	case s.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return ctx.Err()
}

// Outage criterion of the security decision on #55: with the endpoint down a
// best-effort producer is never blocked, queued memory stays inside the cap,
// and the drop counter rises.
func TestBestEffortOutageNeverBlocksProducer(t *testing.T) {
	s := &stuckSender{started: make(chan struct{}, 1)}
	c := cfg(s, &fakeClock{}, event.BestEffort)
	c.MaxEntries, c.MaxBytes, c.BatchSize = 10, 1000, 2
	b, err := New(c)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 5000; i++ {
			// entries are small, so only the entry cap can be hit
			assert.NoError(t, b.Enqueue([]byte("entry-0123")))
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("producer was blocked by an unreachable endpoint")
	}
	// at most one batch is in flight and at most MaxEntries are queued
	assert.GreaterOrEqual(t, b.Dropped(), uint64(5000-c.MaxEntries-c.BatchSize))
	assert.EqualValues(t, 0, b.Sent())

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	assert.Error(t, b.Close(ctx), "close reports what was lost")
}

// Enforced never drops silently: a full queue is reported to the producer.
func TestEnforcedOutageReportsQueueFull(t *testing.T) {
	s := &stuckSender{started: make(chan struct{}, 1)}
	c := cfg(s, &fakeClock{}, event.Enforced)
	c.MaxEntries, c.MaxBytes, c.BatchSize = 4, 1000, 2
	b, err := New(c)
	require.NoError(t, err)
	var full bool
	for i := 0; i < 100 && !full; i++ {
		full = b.Enqueue([]byte("entry")) == ErrQueueFull
	}
	assert.True(t, full)
	assert.EqualValues(t, 0, b.Dropped())
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = b.Close(ctx)
}
