// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package accessrequest

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

type fakeClock struct{ t time.Time }

func (c fakeClock) Now() time.Time { return c.t }

func newReq(t *testing.T) Request {
	t.Helper()
	r, err := New(fakeClock{t0}, "ar_1", "u_req", "p_1", []string{"ids=*;actions=authorize-session"}, "need prod access", time.Hour)
	require.NoError(t, err)
	return r
}

func TestNew(t *testing.T) {
	g := []string{"g"}
	tests := []struct {
		name                 string
		clock                Clock
		id, requester, scope string
		grants               []string
		just                 string
		dur                  time.Duration
		opts                 []Option
		wantErr              error
	}{
		{"ok", fakeClock{t0}, "i", "u", "p", g, "why", time.Hour, nil, nil},
		{"nil clock", nil, "i", "u", "p", g, "why", time.Hour, nil, ErrInvalidInput},
		{"zero clock", fakeClock{}, "i", "u", "p", g, "why", time.Hour, nil, ErrInvalidInput},
		{"no id", fakeClock{t0}, " ", "u", "p", g, "why", time.Hour, nil, ErrInvalidInput},
		{"no requester", fakeClock{t0}, "i", "", "p", g, "why", time.Hour, nil, ErrInvalidInput},
		{"no scope", fakeClock{t0}, "i", "u", "", g, "why", time.Hour, nil, ErrInvalidInput},
		{"no grants", fakeClock{t0}, "i", "u", "p", nil, "why", time.Hour, nil, ErrInvalidInput},
		{"empty grant", fakeClock{t0}, "i", "u", "p", []string{" "}, "why", time.Hour, nil, ErrInvalidInput},
		{"too many grants", fakeClock{t0}, "i", "u", "p", []string{"a", "b"}, "why", time.Hour, []Option{WithMaxGrants(1)}, ErrInvalidInput},
		{"no justification", fakeClock{t0}, "i", "u", "p", g, "  ", time.Hour, nil, ErrInvalidInput},
		{"long justification", fakeClock{t0}, "i", "u", "p", g, strings.Repeat("x", DefaultMaxJustification+1), time.Hour, nil, ErrInvalidInput},
		{"zero duration", fakeClock{t0}, "i", "u", "p", g, "why", 0, nil, ErrInvalidInput},
		{"negative duration", fakeClock{t0}, "i", "u", "p", g, "why", -time.Hour, nil, ErrInvalidInput},
		{"over default max", fakeClock{t0}, "i", "u", "p", g, "why", 9 * time.Hour, nil, ErrDurationTooLong},
		{"exactly default max", fakeClock{t0}, "i", "u", "p", g, "why", 8 * time.Hour, nil, nil},
		{"custom max", fakeClock{t0}, "i", "u", "p", g, "why", 2 * time.Hour, []Option{WithMaxDuration(time.Hour)}, ErrDurationTooLong},
		{"bad option", fakeClock{t0}, "i", "u", "p", g, "why", time.Hour, []Option{WithMaxDuration(0)}, ErrInvalidInput},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := New(tc.clock, tc.id, tc.requester, tc.scope, tc.grants, tc.just, tc.dur, tc.opts...)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				assert.Equal(t, Request{}, r)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, StatePending, r.State)
			assert.Equal(t, t0, r.CreatedAt)
		})
	}
}

func TestNewCopiesGrants(t *testing.T) {
	g := []string{"a"}
	r, err := New(fakeClock{t0}, "i", "u", "p", g, "why", time.Hour)
	require.NoError(t, err)
	g[0] = "changed"
	assert.Equal(t, "a", r.Grants[0])
}

func TestApprove(t *testing.T) {
	maxAge := DefaultMaxPendingAge
	tests := []struct {
		name     string
		mutate   func(*Request)
		approver string
		now      time.Time
		wantErr  error
		wantExp  time.Time
	}{
		{"ok", nil, "u_appr", t0.Add(time.Minute), nil, t0.Add(time.Minute + time.Hour)},
		{"self approval", nil, "u_req", t0, ErrSelfApproval, time.Time{}},
		{"no approver", nil, "", t0, ErrInvalidInput, time.Time{}},
		{"zero now", nil, "u_appr", time.Time{}, ErrInvalidInput, time.Time{}},
		{"already approved", func(r *Request) { r.State = StateApproved }, "u_appr", t0, ErrInvalidTransition, time.Time{}},
		{"already denied", func(r *Request) { r.State = StateDenied }, "u_appr", t0, ErrInvalidTransition, time.Time{}},
		{"cancelled", func(r *Request) { r.State = StateCancelled }, "u_appr", t0, ErrInvalidTransition, time.Time{}},
		{"expired", func(r *Request) { r.State = StateExpired }, "u_appr", t0, ErrInvalidTransition, time.Time{}},
		{"unknown state", func(r *Request) { r.State = "weird" }, "u_appr", t0, ErrInvalidState, time.Time{}},
		{"zero state", func(r *Request) { r.State = "" }, "u_appr", t0, ErrInvalidState, time.Time{}},
		{"just before max age", nil, "u_appr", t0.Add(maxAge - time.Nanosecond), nil, t0.Add(maxAge - time.Nanosecond + time.Hour)},
		{"exactly max age", nil, "u_appr", t0.Add(maxAge), ErrPendingExpired, time.Time{}},
		{"duration over max", func(r *Request) { r.Duration = 9 * time.Hour }, "u_appr", t0, ErrDurationTooLong, time.Time{}},
		{"zero duration", func(r *Request) { r.Duration = 0 }, "u_appr", t0, ErrInvalidInput, time.Time{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newReq(t)
			if tc.mutate != nil {
				tc.mutate(&r)
			}
			before := r
			got, err := Approve(r, tc.approver, tc.now)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				assert.Equal(t, before, got, "request must be unchanged on error")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, StateApproved, got.State)
			assert.Equal(t, tc.approver, got.DecidedBy)
			assert.Equal(t, tc.now, got.DecidedAt)
			assert.Equal(t, tc.wantExp, got.ExpiresAt)
			assert.Equal(t, before, r, "argument must not be mutated")
		})
	}
}

func TestApproveExpiryNeverExceedsCap(t *testing.T) {
	r := newReq(t)
	got, err := Approve(r, "u_appr", t0.Add(DefaultMaxPendingAge-time.Second))
	require.NoError(t, err)
	assert.False(t, got.ExpiresAt.After(r.CreatedAt.Add(DefaultMaxPendingAge+r.Duration)))
}

func TestDenyCancelRevoke(t *testing.T) {
	t.Run("deny ok", func(t *testing.T) {
		got, err := Deny(newReq(t), "u_appr", t0)
		require.NoError(t, err)
		assert.Equal(t, StateDenied, got.State)
	})
	t.Run("deny by requester", func(t *testing.T) {
		_, err := Deny(newReq(t), "u_req", t0)
		require.ErrorIs(t, err, ErrSelfApproval)
	})
	t.Run("double decision", func(t *testing.T) {
		d, err := Deny(newReq(t), "u_appr", t0)
		require.NoError(t, err)
		_, err = Deny(d, "u_appr2", t0)
		require.ErrorIs(t, err, ErrInvalidTransition)
		_, err = Approve(d, "u_appr2", t0)
		require.ErrorIs(t, err, ErrInvalidTransition)
		_, err = Cancel(d, "u_req", t0)
		require.ErrorIs(t, err, ErrInvalidTransition)
	})
	t.Run("deny after max age", func(t *testing.T) {
		_, err := Deny(newReq(t), "u_appr", t0.Add(DefaultMaxPendingAge))
		require.ErrorIs(t, err, ErrPendingExpired)
	})
	t.Run("cancel ok", func(t *testing.T) {
		got, err := Cancel(newReq(t), "u_req", t0)
		require.NoError(t, err)
		assert.Equal(t, StateCancelled, got.State)
	})
	t.Run("cancel by other", func(t *testing.T) {
		_, err := Cancel(newReq(t), "u_other", t0)
		require.ErrorIs(t, err, ErrNotRequester)
	})
	t.Run("cancel approved", func(t *testing.T) {
		a, err := Approve(newReq(t), "u_appr", t0)
		require.NoError(t, err)
		_, err = Cancel(a, "u_req", t0)
		require.ErrorIs(t, err, ErrInvalidTransition)
	})
	t.Run("revoke ok", func(t *testing.T) {
		a, err := Approve(newReq(t), "u_appr", t0)
		require.NoError(t, err)
		got, err := Revoke(a, "u_admin", t0.Add(time.Minute))
		require.NoError(t, err)
		assert.Equal(t, StateRevoked, got.State)
		assert.False(t, got.Active(t0.Add(time.Minute)))
	})
	t.Run("revoke pending", func(t *testing.T) {
		_, err := Revoke(newReq(t), "u_admin", t0)
		require.ErrorIs(t, err, ErrInvalidTransition)
	})
	t.Run("revoke at expiry", func(t *testing.T) {
		a, err := Approve(newReq(t), "u_appr", t0)
		require.NoError(t, err)
		_, err = Revoke(a, "u_admin", a.ExpiresAt)
		require.ErrorIs(t, err, ErrInvalidTransition)
	})
	t.Run("revoke twice", func(t *testing.T) {
		a, _ := Approve(newReq(t), "u_appr", t0)
		rv, err := Revoke(a, "u_admin", t0)
		require.NoError(t, err)
		_, err = Revoke(rv, "u_admin", t0)
		require.ErrorIs(t, err, ErrInvalidTransition)
	})
}

func TestExpire(t *testing.T) {
	approved, err := Approve(newReq(t), "u_appr", t0)
	require.NoError(t, err)
	tests := []struct {
		name string
		in   Request
		now  time.Time
		want State
		err  error
	}{
		{"pending within age", newReq(t), t0.Add(DefaultMaxPendingAge - time.Nanosecond), StatePending, nil},
		{"pending exactly max age", newReq(t), t0.Add(DefaultMaxPendingAge), StateExpired, nil},
		{"approved before expiry", approved, approved.ExpiresAt.Add(-time.Nanosecond), StateApproved, nil},
		{"approved exactly at expiry", approved, approved.ExpiresAt, StateExpired, nil},
		{"approved after expiry", approved, approved.ExpiresAt.Add(time.Hour), StateExpired, nil},
		{"unknown state", Request{State: "x"}, t0, "x", ErrInvalidState},
		{"zero state", Request{}, t0, "", ErrInvalidState},
		{"zero now", newReq(t), time.Time{}, StatePending, ErrInvalidInput},
		{"approved without expiry", Request{State: StateApproved, RequesterId: "u", CreatedAt: t0}, t0, StateApproved, ErrInvalidInput},
	}
	for _, s := range []State{StateDenied, StateCancelled, StateExpired, StateRevoked} {
		r := newReq(t)
		r.State = s
		tests = append(tests, struct {
			name string
			in   Request
			now  time.Time
			want State
			err  error
		}{"terminal " + string(s), r, t0.Add(1000 * time.Hour), s, nil})
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Expire(tc.in, tc.now)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				assert.Equal(t, tc.in, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got.State)
			// idempotent
			again, err := Expire(got, tc.now)
			require.NoError(t, err)
			assert.Equal(t, got, again)
		})
	}
}

func TestActive(t *testing.T) {
	a, err := Approve(newReq(t), "u_appr", t0)
	require.NoError(t, err)
	assert.True(t, a.Active(t0))
	assert.True(t, a.Active(a.ExpiresAt.Add(-time.Nanosecond)))
	assert.False(t, a.Active(a.ExpiresAt), "exactly at expiry is not active")
	assert.False(t, a.Active(time.Time{}))
	assert.False(t, newReq(t).Active(t0))
	assert.False(t, Request{State: StateApproved}.Active(t0), "approved without expiry is not active")
}

func TestStateTerminal(t *testing.T) {
	assert.False(t, StatePending.Terminal())
	assert.False(t, StateApproved.Terminal())
	for _, s := range []State{StateDenied, StateCancelled, StateExpired, StateRevoked} {
		assert.True(t, s.Terminal())
	}
}

func TestSystemClock(t *testing.T) {
	assert.False(t, SystemClock{}.Now().IsZero())
}
