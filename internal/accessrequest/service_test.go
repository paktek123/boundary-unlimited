// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package accessrequest

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const svcCanary = "CANARY-justification-77ab"

type svcClock struct{ t time.Time }

func (c *svcClock) Now() time.Time { return c.t }

type recNotifier struct {
	mu    sync.Mutex
	got   []Request
	kinds []NotifyKind
	err   error
	boom  bool
}

func (n *recNotifier) Notify(_ context.Context, k NotifyKind, r Request) error {
	if n.boom {
		panic("notifier exploded " + svcCanary)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.got = append(n.got, r)
	n.kinds = append(n.kinds, k)
	return n.err
}

type svcFix struct {
	svc   *Service
	repo  *MemRepository
	audit *RecordingEmitter
	note  *recNotifier
	clock *svcClock
}

func newSvc(t *testing.T) *svcFix {
	t.Helper()
	f := &svcFix{repo: NewMemRepository(), audit: &RecordingEmitter{}, note: &recNotifier{},
		clock: &svcClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}}
	n := 0
	var err error
	f.svc, err = NewService(ServiceConfig{
		Repo: f.repo, Policy: DefaultApprovalPolicy(), Audit: f.audit, Notifier: f.note, Clock: f.clock,
		NewId: func() (string, error) { n++; return fmt.Sprintf("ar_%d", n), nil },
	})
	require.NoError(t, err)
	return f
}

var (
	reqr     = Actor{Id: "u_req"}
	grantA   = "ids=ttcp_1;actions=read"
	approver = Actor{Id: "u_app", CanApprove: true, Grants: []string{grantA}}
)

func (f *svcFix) create(t *testing.T) Request {
	t.Helper()
	r, err := f.svc.Create(context.Background(), reqr, "o_1", []string{grantA}, svcCanary, time.Hour)
	require.NoError(t, err)
	return r
}

func TestService_HappyPaths(t *testing.T) {
	ctx := context.Background()
	f := newSvc(t)
	r := f.create(t)
	assert.Equal(t, StatePending, r.State)
	assert.Equal(t, GrantHash(r.Grants), r.GrantHash)

	ap, err := f.svc.Approve(ctx, approver, r.Id)
	require.NoError(t, err)
	assert.Equal(t, StateApproved, ap.State)
	assert.Equal(t, f.clock.t.Add(time.Hour), ap.ExpiresAt)
	require.NoError(t, VerifyApprovedGrants(ap))

	r2 := f.create(t)
	d, err := f.svc.Deny(ctx, approver, r2.Id)
	require.NoError(t, err)
	assert.Equal(t, StateDenied, d.State)

	r3 := f.create(t)
	c, err := f.svc.Cancel(ctx, reqr, r3.Id)
	require.NoError(t, err)
	assert.Equal(t, StateCancelled, c.State)

	var types []EventType
	for _, e := range f.audit.Events() {
		types = append(types, e.Type)
	}
	assert.Equal(t, []EventType{EventCreate, EventApprove, EventCreate, EventDeny, EventCreate, EventCancel}, types)
	assert.Len(t, f.note.kinds, 6)
}

func TestService_Rejections(t *testing.T) {
	ctx := context.Background()
	t.Run("ttl above max", func(t *testing.T) {
		f := newSvc(t)
		_, err := f.svc.Create(ctx, reqr, "o_1", []string{grantA}, "j", 25*time.Hour)
		require.ErrorIs(t, err, ErrDurationTooLong)
		assert.Empty(t, f.audit.Events())
	})
	t.Run("self approval", func(t *testing.T) {
		f := newSvc(t)
		r := f.create(t)
		me := Actor{Id: reqr.Id, CanApprove: true, Grants: []string{grantA}}
		_, err := f.svc.Approve(ctx, me, r.Id)
		require.ErrorIs(t, err, ErrSelfApproval)
	})
	t.Run("missing approve action", func(t *testing.T) {
		f := newSvc(t)
		r := f.create(t)
		_, err := f.svc.Approve(ctx, Actor{Id: "u_app", Grants: []string{grantA}}, r.Id)
		require.ErrorIs(t, err, ErrApproverNotAuthorized)
		_, err = f.svc.Deny(ctx, Actor{Id: "u_app"}, r.Id)
		require.ErrorIs(t, err, ErrApproverNotAuthorized)
	})
	t.Run("missing grant superset", func(t *testing.T) {
		f := newSvc(t)
		r := f.create(t)
		_, err := f.svc.Approve(ctx, Actor{Id: "u_app", CanApprove: true}, r.Id)
		require.ErrorIs(t, err, ErrGrantsNotHeld)
	})
	t.Run("grants changed", func(t *testing.T) {
		f := newSvc(t)
		r := f.create(t)
		r.Grants = []string{"ids=ttcp_2;actions=read"}
		_, err := f.repo.Update(ctx, r)
		require.NoError(t, err)
		_, err = f.svc.Approve(ctx, Actor{Id: "u_app", CanApprove: true, Grants: r.Grants}, r.Id)
		require.ErrorIs(t, err, ErrGrantsChanged)
	})
	t.Run("only requester cancels", func(t *testing.T) {
		f := newSvc(t)
		r := f.create(t)
		_, err := f.svc.Cancel(ctx, approver, r.Id)
		require.ErrorIs(t, err, ErrNotRequester)
	})
	t.Run("approve twice", func(t *testing.T) {
		f := newSvc(t)
		r := f.create(t)
		_, err := f.svc.Approve(ctx, approver, r.Id)
		require.NoError(t, err)
		_, err = f.svc.Approve(ctx, approver, r.Id)
		require.ErrorIs(t, err, ErrInvalidTransition)
	})
	t.Run("unknown id", func(t *testing.T) {
		f := newSvc(t)
		_, err := f.svc.Approve(ctx, approver, "nope")
		require.ErrorIs(t, err, ErrNotFound)
	})
}

type panicAudit struct{}

func (panicAudit) Emit(context.Context, Event) error { panic("audit " + svcCanary) }

func TestService_AuditFailureFailsClosed(t *testing.T) {
	ctx := context.Background()
	f := newSvc(t)
	r := f.create(t)
	for _, sink := range []AuditSink{&RecordingEmitter{Err: errors.New("down")}, panicAudit{}} {
		f.svc.cfg.Audit = sink
		_, err := f.svc.Approve(ctx, approver, r.Id)
		require.Error(t, err)
		assert.NotContains(t, err.Error(), svcCanary)
		got, err := f.repo.Get(ctx, r.Id)
		require.NoError(t, err)
		assert.Equal(t, StatePending, got.State, "request must be unchanged")
		_, err = f.svc.Create(ctx, reqr, "o_1", []string{grantA}, "j", time.Hour)
		require.Error(t, err)
	}
	all, err := f.repo.List(ctx, ListFilter{})
	require.NoError(t, err)
	assert.Len(t, all, 1, "failed audit must not create a request")
}

func TestService_NotifierFailureIgnored(t *testing.T) {
	ctx := context.Background()
	for _, n := range []*recNotifier{{err: errors.New("hook down")}, {boom: true}} {
		f := newSvc(t)
		f.svc.cfg.Notifier = n
		r := f.create(t)
		ap, err := f.svc.Approve(ctx, approver, r.Id)
		require.NoError(t, err)
		assert.Equal(t, StateApproved, ap.State)
	}
}

func TestService_CanaryNeverReachesAuditOrNotifier(t *testing.T) {
	ctx := context.Background()
	f := newSvc(t)
	r := f.create(t)
	_, err := f.svc.Approve(ctx, approver, r.Id)
	require.NoError(t, err)
	for _, e := range f.audit.Events() {
		assert.NotContains(t, fmt.Sprintf("%+v", e), svcCanary)
	}
	require.NotEmpty(t, f.note.got)
	for _, g := range f.note.got {
		assert.Empty(t, g.Justification)
		assert.False(t, strings.Contains(fmt.Sprintf("%+v", g), svcCanary))
	}
	stored, err := f.repo.Get(ctx, r.Id)
	require.NoError(t, err)
	assert.Equal(t, svcCanary, stored.Justification, "stored request keeps the justification")
}

func TestNewService_FailsClosed(t *testing.T) {
	ok := ServiceConfig{Repo: NewMemRepository(), Policy: DefaultApprovalPolicy(), Audit: &RecordingEmitter{},
		Clock: SystemClock{}, NewId: func() (string, error) { return "x", nil }}
	_, err := NewService(ok)
	require.NoError(t, err)
	var nilRepo *MemRepository
	for name, mut := range map[string]func(*ServiceConfig){
		"no repo":    func(c *ServiceConfig) { c.Repo = nil },
		"typed nil":  func(c *ServiceConfig) { c.Repo = nilRepo },
		"no audit":   func(c *ServiceConfig) { c.Audit = nil },
		"no clock":   func(c *ServiceConfig) { c.Clock = nil },
		"no id gen":  func(c *ServiceConfig) { c.NewId = nil },
		"zero ttl":   func(c *ServiceConfig) { c.Policy = ApprovalPolicy{} },
		"bad option": func(c *ServiceConfig) { c.Options = []Option{WithMaxGrants(-1)} },
	} {
		t.Run(name, func(t *testing.T) {
			c := ok
			mut(&c)
			_, err := NewService(c)
			require.Error(t, err)
		})
	}
}
