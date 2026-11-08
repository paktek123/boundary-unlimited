// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package notify

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/accessrequest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fanoutCanary = "https://hooks.example.test/T000/B000/CANARYSECRET?token=abc123"

type funcNotifier func(ctx context.Context, e Event) error

func (f funcNotifier) Notify(ctx context.Context, e Event) error { return f(ctx, e) }

var (
	t0    = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	t1    = t0.Add(time.Hour)
	t2    = t0.Add(2 * time.Hour)
	goodE = Event{Type: "access_request.requested", RequestID: "ar_1", ScopeID: "o_1", Timestamp: t0, Summary: "x"}
)

func TestFromAccessRequest(t *testing.T) {
	req := accessrequest.Request{Id: "ar_1", ScopeId: "o_1", RequesterId: "u_1", Justification: "CANARY-JUSTIFICATION password=hunter2",
		Grants: []string{"ids=*;type=target;actions=*"}, CreatedAt: t0, DecidedAt: t1, DecidedBy: "u_2", ExpiresAt: t2}
	tests := []struct {
		kind Kind
		typ  string
		ts   time.Time
	}{
		{KindRequested, "access_request.requested", t0},
		{KindApproved, "access_request.approved", t1},
		{KindDenied, "access_request.denied", t1},
		{KindCancelled, "access_request.cancelled", t1},
		{KindExpired, "access_request.expired", t2},
	}
	for _, tt := range tests {
		t.Run(string(tt.kind), func(t *testing.T) {
			e, err := FromAccessRequest(req, tt.kind)
			require.NoError(t, err)
			assert.Equal(t, tt.typ, e.Type)
			assert.Equal(t, "ar_1", e.RequestID)
			assert.Equal(t, "o_1", e.ScopeID)
			assert.True(t, e.Timestamp.Equal(tt.ts))
			assert.Equal(t, summaries[tt.kind], e.Summary)
			assert.NoError(t, e.Validate())
			all := fmt.Sprintf("%#v", e)
			for _, leak := range []string{"CANARY", "hunter2", "u_1", "u_2", "target"} {
				assert.NotContains(t, all, leak)
			}
		})
	}
	t.Run("expired without expiry falls back to decided", func(t *testing.T) {
		r := req
		r.ExpiresAt = time.Time{}
		e, err := FromAccessRequest(r, KindExpired)
		require.NoError(t, err)
		assert.True(t, e.Timestamp.Equal(t1))
	})
	t.Run("errors", func(t *testing.T) {
		_, err := FromAccessRequest(req, "bogus")
		assert.ErrorIs(t, err, ErrInvalidEvent)
		_, err = FromAccessRequest(accessrequest.Request{ScopeId: "o_1", CreatedAt: t0}, KindRequested)
		assert.ErrorIs(t, err, ErrInvalidEvent)
		_, err = FromAccessRequest(accessrequest.Request{Id: "ar_1", CreatedAt: t0}, KindRequested)
		assert.ErrorIs(t, err, ErrInvalidEvent)
		_, err = FromAccessRequest(accessrequest.Request{Id: "ar_1", ScopeId: "o_1"}, KindApproved)
		assert.ErrorIs(t, err, ErrInvalidEvent)
	})
}

func TestNewFanOutValidation(t *testing.T) {
	ok := &RecorderNotifier{}
	for name, fn := range map[string]func() (*FanOut, error){
		"none":     func() (*FanOut, error) { return NewFanOut(0) },
		"nil":      func() (*FanOut, error) { return NewFanOut(0, ok, nil) },
		"long":     func() (*FanOut, error) { return NewFanOut(MaxFanOutTimeout+1, ok) },
		"too many": func() (*FanOut, error) { return NewFanOut(0, make([]Notifier, MaxFanOutNotifiers+1)...) },
	} {
		_, err := fn()
		assert.ErrorIs(t, err, ErrInvalidFanOut, name)
	}
	f, err := NewFanOut(0, ok)
	require.NoError(t, err)
	assert.Equal(t, DefaultFanOutTimeout, f.timeout)
}

func TestFanOutIsolatesFailures(t *testing.T) {
	good1, good2 := &RecorderNotifier{}, &RecorderNotifier{}
	failing := funcNotifier(func(context.Context, Event) error { return errors.New("post " + fanoutCanary + " failed") })
	hanging := funcNotifier(func(ctx context.Context, _ Event) error { <-make(chan struct{}); return nil }) // ignores ctx
	slow := funcNotifier(func(ctx context.Context, _ Event) error { <-ctx.Done(); return ctx.Err() })
	panicking := funcNotifier(func(context.Context, Event) error { panic(fanoutCanary) })

	f, err := NewFanOut(100*time.Millisecond, good1, failing, hanging, slow, panicking, good2)
	require.NoError(t, err)

	start := time.Now()
	err = f.Notify(context.Background(), goodE)
	assert.Less(t, time.Since(start), 5*time.Second)
	require.Error(t, err)

	assert.Equal(t, []Event{goodE}, good1.Events())
	assert.Equal(t, []Event{goodE}, good2.Events())

	assert.ErrorIs(t, err, ErrNotifierFailed)
	assert.ErrorIs(t, err, ErrNotifierTimeout)
	assert.ErrorIs(t, err, ErrNotifierPanicked)
	for _, s := range []string{err.Error(), fmt.Sprintf("%v %+v %#v", err, err, err)} {
		assert.NotContains(t, s, "CANARYSECRET")
		assert.NotContains(t, s, "hooks.example.test")
		assert.NotContains(t, s, "token=")
	}
	assert.Contains(t, err.Error(), "notifier 1:")
	assert.NotContains(t, err.Error(), "notifier 0:")
}

func TestFanOutAllSucceed(t *testing.T) {
	a, b := &RecorderNotifier{}, &RecorderNotifier{}
	f, err := NewFanOut(0, a, b)
	require.NoError(t, err)
	require.NoError(t, f.Notify(context.Background(), goodE))
	assert.Len(t, a.Events(), 1)
	assert.Len(t, b.Events(), 1)
}

func TestFanOutRejectsInvalidEventAndNil(t *testing.T) {
	a := &RecorderNotifier{}
	f, _ := NewFanOut(0, a)
	bad := goodE
	bad.Type = "Bad Type"
	assert.ErrorIs(t, f.Notify(context.Background(), bad), ErrInvalidEvent)
	assert.Empty(t, a.Events())
	var nilF *FanOut
	assert.ErrorIs(t, nilF.Notify(context.Background(), goodE), ErrInvalidFanOut)
}

func TestFanOutParentCancel(t *testing.T) {
	f, _ := NewFanOut(time.Minute, funcNotifier(func(ctx context.Context, _ Event) error { <-make(chan struct{}); return nil }))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := f.Notify(ctx, goodE)
	assert.ErrorIs(t, err, ErrFanOutCancelled)
}

func TestRecorderNotifierError(t *testing.T) {
	boom := errors.New("boom")
	r := &RecorderNotifier{Err: boom}
	assert.ErrorIs(t, r.Notify(context.Background(), goodE), boom)
	assert.Empty(t, r.Events())
	assert.False(t, strings.Contains(fmt.Sprint(r.Events()), "x"))
}
