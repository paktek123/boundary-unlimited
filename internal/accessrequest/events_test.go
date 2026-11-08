// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package accessrequest

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func eventFixture(t *testing.T) (pending, approved, denied, cancelled, expired Request, now time.Time) {
	t.Helper()
	now = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	var err error
	pending, err = New(fixedClock(now), "ar_1", "u_req", "p_1", []string{"ids=ttcp_1;actions=authorize-session"}, "debug outage", time.Hour)
	require.NoError(t, err)
	later := now.Add(time.Minute)
	approved, err = Approve(pending, "u_app", later)
	require.NoError(t, err)
	denied, err = Deny(pending, "u_app", later)
	require.NoError(t, err)
	cancelled, err = Cancel(pending, "u_req", later)
	require.NoError(t, err)
	expired, err = Expire(approved, approved.ExpiresAt)
	require.NoError(t, err)
	require.Equal(t, StateExpired, expired.State)
	return
}

type fixedClock time.Time

func (c fixedClock) Now() time.Time { return time.Time(c) }

func TestEventConstructors(t *testing.T) {
	pending, approved, denied, cancelled, expired, now := eventFixture(t)
	g := pending.Grants[0]
	tests := []struct {
		name string
		got  func() (Event, error)
		want Event
	}{
		{"create", func() (Event, error) { return NewCreateEvent(pending) },
			Event{Type: EventCreate, RequestId: "ar_1", RequesterId: "u_req", Grants: []string{g}, At: now}},
		{"approve", func() (Event, error) { return NewApproveEvent(approved) },
			Event{Type: EventApprove, RequestId: "ar_1", RequesterId: "u_req", ApproverId: "u_app", Grants: []string{g}, At: approved.DecidedAt, NotAfter: approved.ExpiresAt}},
		{"deny", func() (Event, error) { return NewDenyEvent(denied) },
			Event{Type: EventDeny, RequestId: "ar_1", RequesterId: "u_req", ApproverId: "u_app", Grants: []string{g}, At: denied.DecidedAt}},
		{"cancel", func() (Event, error) { return NewCancelEvent(cancelled) },
			Event{Type: EventCancel, RequestId: "ar_1", RequesterId: "u_req", ApproverId: "u_req", Grants: []string{g}, At: cancelled.DecidedAt}},
		{"expire", func() (Event, error) { return NewExpireEvent(expired, approved.ExpiresAt) },
			Event{Type: EventExpire, RequestId: "ar_1", RequesterId: "u_req", Grants: []string{g}, At: approved.ExpiresAt, NotAfter: approved.ExpiresAt}},
		{"overlay", func() (Event, error) {
			return NewOverlayAuthorizedEvent(approved, g, approved.DecidedAt.Add(time.Second))
		},
			Event{Type: EventOverlayAuthorized, RequestId: "ar_1", RequesterId: "u_req", ApproverId: "u_app", Grants: []string{g}, At: approved.DecidedAt.Add(time.Second), NotAfter: approved.ExpiresAt}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.got()
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestEventConstructorRejections(t *testing.T) {
	pending, approved, denied, cancelled, expired, _ := eventFixture(t)
	g := pending.Grants[0]
	inWindow := approved.DecidedAt.Add(time.Second)
	tests := []struct {
		name string
		call func() (Event, error)
		want error
	}{
		{"approve on pending", func() (Event, error) { return NewApproveEvent(pending) }, ErrInvalidTransition},
		{"deny on approved", func() (Event, error) { return NewDenyEvent(approved) }, ErrInvalidTransition},
		{"cancel on denied", func() (Event, error) { return NewCancelEvent(denied) }, ErrInvalidTransition},
		{"expire on cancelled", func() (Event, error) { return NewExpireEvent(cancelled, inWindow) }, ErrInvalidTransition},
		{"overlay on expired", func() (Event, error) { return NewOverlayAuthorizedEvent(expired, g, inWindow) }, ErrInvalidTransition},
		{"overlay at expiry instant", func() (Event, error) { return NewOverlayAuthorizedEvent(approved, g, approved.ExpiresAt) }, ErrInvalidTransition},
		{"overlay unrelated grant", func() (Event, error) { return NewOverlayAuthorizedEvent(approved, "id=*;actions=*", inWindow) }, ErrInvalidInput},
		{"create missing id", func() (Event, error) { r := pending; r.Id = ""; return NewCreateEvent(r) }, ErrInvalidInput},
		{"create zero time", func() (Event, error) { r := pending; r.CreatedAt = time.Time{}; return NewCreateEvent(r) }, ErrInvalidInput},
		{"expire zero time", func() (Event, error) { return NewExpireEvent(expired, time.Time{}) }, ErrInvalidInput},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := tt.call()
			require.ErrorIs(t, err, tt.want)
			assert.Equal(t, Event{}, e)
		})
	}
}

// TestEventRedaction passes secret-looking input through every constructor
// and expects rejection, with the value absent from the error.
func TestEventRedaction(t *testing.T) {
	pending, approved, _, _, _, _ := eventFixture(t)
	secrets := []string{
		"-----BEGIN PRIVATE KEY-----",
		"AKIAIOSFODNN7EXAMPLE",
		"eyJhbGciOiJIUzI1NiJ9.e30.sig",
		"Bearer abcdef",
		"password=hunter2",
		"token: abc",
		"api_key=zzz",
	}
	for _, s := range secrets {
		t.Run(s, func(t *testing.T) {
			// via grant
			r := pending
			r.Grants = []string{s}
			_, err := NewCreateEvent(r)
			require.ErrorIs(t, err, ErrSensitiveField)
			assert.NotContains(t, err.Error(), s)
			// via requester id
			r = pending
			r.RequesterId = s
			_, err = NewCreateEvent(r)
			require.ErrorIs(t, err, ErrSensitiveField)
			// via approver id on approve
			a := approved
			a.DecidedBy = s
			_, err = NewApproveEvent(a)
			require.ErrorIs(t, err, ErrSensitiveField)
			// via overlay grant
			a = approved
			a.Grants = []string{s}
			_, err = NewOverlayAuthorizedEvent(a, s, a.DecidedAt.Add(time.Second))
			require.ErrorIs(t, err, ErrSensitiveField)
		})
	}
	r := pending
	r.Grants = []string{"ids=a;\nactions=read"}
	_, err := NewCreateEvent(r)
	assert.ErrorIs(t, err, ErrInvalidInput)
}

// TestEventStructHasOnlyAllowedFields fails if a field is added, so that a
// reviewer must consciously decide whether it could carry a credential. The
// justification is intentionally not a field.
func TestEventStructHasOnlyAllowedFields(t *testing.T) {
	allowed := map[string]reflect.Type{
		"Type": reflect.TypeOf(EventType("")), "RequestId": reflect.TypeOf(""), "RequesterId": reflect.TypeOf(""),
		"ApproverId": reflect.TypeOf(""), "Grants": reflect.TypeOf([]string(nil)),
		"At": reflect.TypeOf(time.Time{}), "NotAfter": reflect.TypeOf(time.Time{}),
	}
	typ := reflect.TypeOf(Event{})
	require.Equal(t, len(allowed), typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		want, ok := allowed[f.Name]
		require.True(t, ok, "unexpected field %s", f.Name)
		assert.Equal(t, want, f.Type, f.Name)
	}
}

func TestRecordingEmitter(t *testing.T) {
	pending, _, _, _, _, _ := eventFixture(t)
	e, err := NewCreateEvent(pending)
	require.NoError(t, err)

	var em RecordingEmitter
	var _ Emitter = &em
	require.NoError(t, em.Emit(context.Background(), e))
	got := em.Events()
	require.Len(t, got, 1)
	assert.Equal(t, e, got[0])
	got[0].Grants[0] = "mutated"
	assert.Equal(t, e.Grants, em.Events()[0].Grants, "copies are isolated")

	boom := errors.New("sink down")
	fail := &RecordingEmitter{Err: boom}
	assert.ErrorIs(t, fail.Emit(context.Background(), e), boom)
	assert.Empty(t, fail.Events(), "nothing recorded on failure")
}
