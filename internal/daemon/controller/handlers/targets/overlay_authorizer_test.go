// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package targets

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/accessrequest"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type ovClock struct{ t time.Time }

func (c ovClock) Now() time.Time { return c.t }

type ovSource struct {
	reqs []accessrequest.Request
	err  error
	boom bool
}

func (s ovSource) OverlayRequests(context.Context, string, string) ([]accessrequest.Request, error) {
	if s.boom {
		panic("source exploded")
	}
	return s.reqs, s.err
}

type ovAudit struct {
	events []accessrequest.Event
	err    error
}

func (a *ovAudit) Emit(_ context.Context, e accessrequest.Event) error {
	if a.err != nil {
		return a.err
	}
	a.events = append(a.events, e)
	return nil
}

var (
	ovNow   = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	ovGrant = "ids=ttcp_aaaaaaaaaa;type=target;actions=authorize-session"
)

func ovReq(state accessrequest.State, mut func(*accessrequest.Request)) accessrequest.Request {
	r := accessrequest.Request{
		Id: "ar_1", RequesterId: "u_req", ScopeId: "p_1", Grants: []string{ovGrant},
		State: state, CreatedAt: ovNow.Add(-2 * time.Hour), DecidedAt: ovNow.Add(-time.Hour),
		DecidedBy: "u_app", ExpiresAt: ovNow.Add(time.Hour),
	}
	if mut != nil {
		mut(&r)
	}
	return r
}

// allowed evaluates the overlay grants like auth.Verify does (perms.Parse then
// ACL) for the given target id and action.
func allowed(t *testing.T, tuples []perms.GrantTuple, targetID string, a action.Type) bool {
	t.Helper()
	var gs []perms.Grant
	for _, tup := range tuples {
		g, err := perms.Parse(context.Background(), tup, perms.WithUserId("u_req"), perms.WithSkipFinalValidation(true))
		require.NoError(t, err)
		gs = append(gs, g)
	}
	res := perms.NewACL(gs...).Allowed(perms.Resource{ScopeId: "p_1", Id: targetID, Type: resource.Target}, a, "u_req")
	return res.Authorized
}

func TestAccessRequestOverlay(t *testing.T) {
	ctx := context.Background()
	mk := func(src ovSource, audit *ovAudit) AccessRequestOverlay {
		return AccessRequestOverlay{Source: src, Clock: ovClock{ovNow}, Audit: audit}
	}

	t.Run("approved and unexpired allows exactly the approved action", func(t *testing.T) {
		au := &ovAudit{}
		got, err := mk(ovSource{reqs: []accessrequest.Request{ovReq(accessrequest.StateApproved, nil)}}, au).OverlayGrants(ctx, "u_req", "p_1")
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.True(t, allowed(t, got, "ttcp_aaaaaaaaaa", action.AuthorizeSession))
		assert.False(t, allowed(t, got, "ttcp_aaaaaaaaaa", action.Delete), "different action")
		assert.False(t, allowed(t, got, "ttcp_bbbbbbbbbb", action.AuthorizeSession), "different target")
		require.Len(t, au.events, 1)
		assert.Equal(t, accessrequest.EventOverlayAuthorized, au.events[0].Type)
		assert.NotContains(t, fmt.Sprintf("%+v", au.events[0]), "secret")
	})

	for _, st := range []accessrequest.State{
		accessrequest.StatePending, accessrequest.StateDenied, accessrequest.StateCancelled,
		accessrequest.StateExpired, accessrequest.StateRevoked,
	} {
		t.Run("state "+string(st)+" gives nothing", func(t *testing.T) {
			au := &ovAudit{}
			got, err := mk(ovSource{reqs: []accessrequest.Request{ovReq(st, nil)}}, au).OverlayGrants(ctx, "u_req", "p_1")
			require.NoError(t, err)
			assert.Empty(t, got)
			assert.Empty(t, au.events)
		})
	}

	t.Run("approved but past expiry gives nothing", func(t *testing.T) {
		r := ovReq(accessrequest.StateApproved, func(r *accessrequest.Request) { r.ExpiresAt = ovNow })
		got, err := mk(ovSource{reqs: []accessrequest.Request{r}}, &ovAudit{}).OverlayGrants(ctx, "u_req", "p_1")
		require.NoError(t, err)
		assert.Empty(t, got)
	})
	t.Run("another user's request gives nothing", func(t *testing.T) {
		r := ovReq(accessrequest.StateApproved, func(r *accessrequest.Request) { r.RequesterId = "u_other" })
		got, _ := mk(ovSource{reqs: []accessrequest.Request{r}}, &ovAudit{}).OverlayGrants(ctx, "u_req", "p_1")
		assert.Empty(t, got)
	})
	t.Run("request for another scope gives nothing", func(t *testing.T) {
		r := ovReq(accessrequest.StateApproved, func(r *accessrequest.Request) { r.ScopeId = "p_2" })
		got, _ := mk(ovSource{reqs: []accessrequest.Request{r}}, &ovAudit{}).OverlayGrants(ctx, "u_req", "p_1")
		assert.Empty(t, got)
	})
	t.Run("wildcard grant is dropped", func(t *testing.T) {
		r := ovReq(accessrequest.StateApproved, func(r *accessrequest.Request) { r.Grants = []string{"ids=*;type=*;actions=*"} })
		got, _ := mk(ovSource{reqs: []accessrequest.Request{r}}, &ovAudit{}).OverlayGrants(ctx, "u_req", "p_1")
		assert.Empty(t, got)
	})

	fails := map[string]AccessRequestOverlay{
		"source error": mk(ovSource{err: errors.New("db down")}, &ovAudit{}),
		"source panic": mk(ovSource{boom: true}, &ovAudit{}),
		"audit error": mk(ovSource{reqs: []accessrequest.Request{ovReq(accessrequest.StateApproved, nil)}},
			&ovAudit{err: errors.New("sink down")}),
		"no audit sink": {Source: ovSource{reqs: []accessrequest.Request{ovReq(accessrequest.StateApproved, nil)}}, Clock: ovClock{ovNow}},
		"no clock":      {Source: ovSource{reqs: []accessrequest.Request{ovReq(accessrequest.StateApproved, nil)}}, Audit: &ovAudit{}},
		"no source":     {Clock: ovClock{ovNow}, Audit: &ovAudit{}},
		"zero clock":    {Source: ovSource{reqs: []accessrequest.Request{ovReq(accessrequest.StateApproved, nil)}}, Clock: ovClock{}, Audit: &ovAudit{}},
	}
	for name, o := range fails {
		t.Run("fail closed: "+name, func(t *testing.T) {
			got, err := o.OverlayGrants(ctx, "u_req", "p_1")
			require.Error(t, err)
			assert.Empty(t, got)
			assert.NotContains(t, err.Error(), ovGrant)
		})
	}
}

func TestWithGrantOverlay(t *testing.T) {
	assert.Nil(t, Service{}.grantOverlay)
	assert.Nil(t, Service{}.WithGrantOverlay(nil).grantOverlay)
	var typedNil *nilOverlay
	assert.Nil(t, Service{}.WithGrantOverlay(typedNil).grantOverlay)
	assert.NotNil(t, Service{}.WithGrantOverlay(AccessRequestOverlay{}).grantOverlay)
}

type nilOverlay struct{}

func (*nilOverlay) OverlayGrants(context.Context, string, string) ([]perms.GrantTuple, error) {
	return nil, nil
}
