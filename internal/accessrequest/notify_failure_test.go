// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package accessrequest

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const nfCanary = "https://hooks.example.test/T0/B0/SECRET?token=abc123"

type hangNotifier struct{ release chan struct{} }

func (h hangNotifier) Notify(context.Context, NotifyKind, Request) error {
	<-h.release // ignores its context on purpose
	return nil
}

func eventTypes(em *RecordingEmitter) []EventType {
	var out []EventType
	for _, e := range em.Events() {
		out = append(out, e.Type)
	}
	return out
}

func TestService_NotifyFailureIsAuditedAndNeverChangesState(t *testing.T) {
	ctx := context.Background()
	release := make(chan struct{})
	defer close(release)
	cases := map[string]Notifier{
		"error":   &recNotifier{err: errors.New("post " + nfCanary + " returned 500")},
		"panic":   &recNotifier{boom: true},
		"timeout": hangNotifier{release},
	}
	for name, n := range cases {
		t.Run(name, func(t *testing.T) {
			f := newSvc(t)
			f.svc.cfg.Notifier = n
			f.svc.cfg.NotifyTimeout = 50 * time.Millisecond
			start := time.Now()
			r := f.create(t)
			ap, err := f.svc.Approve(ctx, approver, r.Id)
			require.NoError(t, err)
			assert.Equal(t, StateApproved, ap.State)
			assert.Less(t, time.Since(start), 5*time.Second)
			stored, err := f.repo.Get(ctx, r.Id)
			require.NoError(t, err)
			assert.Equal(t, StateApproved, stored.State)

			assert.Equal(t, []EventType{EventCreate, EventNotifyFailed, EventApprove, EventNotifyFailed}, eventTypes(f.audit))
			for _, e := range f.audit.Events() {
				s := fmt.Sprintf("%+v %#v", e, e)
				assert.NotContains(t, s, nfCanary)
				assert.NotContains(t, s, "token=")
				assert.NotContains(t, s, svcCanary)
			}
		})
	}
}

func TestService_NotifySuccessEmitsNoFailureEvent(t *testing.T) {
	f := newSvc(t)
	f.create(t)
	assert.Equal(t, []EventType{EventCreate}, eventTypes(f.audit))
}

func TestService_NoNotifierUnchanged(t *testing.T) {
	f := newSvc(t)
	f.svc.cfg.Notifier = nil
	r := f.create(t)
	_, err := f.svc.Approve(context.Background(), approver, r.Id)
	require.NoError(t, err)
	assert.Equal(t, []EventType{EventCreate, EventApprove}, eventTypes(f.audit))
}

func TestService_FailedAuditOfNotifyFailureIsIgnored(t *testing.T) {
	f := newSvc(t)
	f.svc.cfg.Notifier = &recNotifier{err: errors.New("x")}
	// the sink accepts the lifecycle event, then fails: only notify-failed errors
	f.svc.cfg.Audit = &failOnTypeEmitter{typ: EventNotifyFailed}
	r, err := f.svc.Create(context.Background(), reqr, "o_1", []string{grantA}, "j", time.Hour)
	require.NoError(t, err)
	assert.Equal(t, StatePending, r.State)
}

type failOnTypeEmitter struct{ typ EventType }

func (f *failOnTypeEmitter) Emit(_ context.Context, e Event) error {
	if e.Type == f.typ {
		return errors.New("sink down")
	}
	return nil
}

func TestNewNotifyFailedEvent(t *testing.T) {
	r := Request{Id: "ar_1", RequesterId: "u_1", Grants: []string{grantA}, Justification: svcCanary}
	e, err := NewNotifyFailedEvent(r, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	assert.Equal(t, EventNotifyFailed, e.Type)
	assert.Empty(t, e.Grants)
	assert.NotContains(t, fmt.Sprintf("%+v", e), svcCanary)
	_, err = NewNotifyFailedEvent(r, time.Time{})
	require.Error(t, err)
}

func TestSweeper_NotifiesExpiryAndAuditsFailure(t *testing.T) {
	ctx := context.Background()
	f := newSvc(t)
	r := f.create(t)
	_, err := f.svc.Approve(ctx, approver, r.Id)
	require.NoError(t, err)
	now := f.clock.t.Add(2 * time.Hour)

	n := &recNotifier{}
	em := &RecordingEmitter{}
	sw, err := NewSweeper(f.repo, em, WithSweeperNotifier(n))
	require.NoError(t, err)
	res, err := sw.Run(ctx, now)
	require.NoError(t, err)
	assert.Equal(t, 1, res.Expired)
	require.Len(t, n.kinds, 1)
	assert.Equal(t, NotifyExpired, n.kinds[0])
	assert.Equal(t, []EventType{EventExpire}, eventTypes(em))

	// a failing notifier is audited and the expiry still stands
	f2 := newSvc(t)
	r2 := f2.create(t)
	_, err = f2.svc.Approve(ctx, approver, r2.Id)
	require.NoError(t, err)
	em2 := &RecordingEmitter{}
	sw2, err := NewSweeper(f2.repo, em2, WithSweeperNotifier(&recNotifier{err: errors.New(nfCanary)}))
	require.NoError(t, err)
	res, err = sw2.Run(ctx, now)
	require.NoError(t, err)
	assert.Equal(t, 1, res.Expired)
	assert.Equal(t, []EventType{EventExpire, EventNotifyFailed}, eventTypes(em2))
	stored, _ := f2.repo.Get(ctx, r2.Id)
	assert.Equal(t, StateExpired, stored.State)
}

func TestService_CancelledCallerContextStillDeliversAndUsesInjectedClock(t *testing.T) {
	f := newSvc(t)
	cctx, cancel := context.WithCancel(context.Background())
	r := f.create(t)
	cancel() // caller gone after the state change committed
	f.svc.notify(cctx, NotifyApproved, r)
	assert.Contains(t, f.note.kinds, NotifyApproved, "delivery must not be skipped by a cancelled caller context")
	assert.NotContains(t, eventTypes(f.audit), EventNotifyFailed)

	f.svc.cfg.Notifier = &recNotifier{err: errors.New("x")}
	f.svc.notify(context.Background(), NotifyApproved, r)
	evs := f.audit.Events()
	require.Equal(t, EventNotifyFailed, evs[len(evs)-1].Type)
	assert.True(t, evs[len(evs)-1].At.Equal(f.clock.t), "failure event uses the injected clock")
}
