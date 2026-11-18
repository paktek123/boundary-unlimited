// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package controller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/accessrequest"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const arGrant = "ids=ttcp_aaaaaaaaaa;type=target;actions=authorize-session"

type arClock struct{ t time.Time }

func (c arClock) Now() time.Time { return c.t }

type failingRepo struct{ accessrequest.Repository }

func (failingRepo) List(context.Context, accessrequest.ListFilter) ([]accessrequest.Request, error) {
	return nil, errors.New("db down canary-dsn")
}

func approvedRepo(t *testing.T, now time.Time) accessrequest.Repository {
	t.Helper()
	repo := accessrequest.NewMemRepositoryWithClock(func() time.Time { return now })
	_, err := repo.Create(context.Background(), accessrequest.Request{
		Id: "ar_1", RequesterId: "u_req", ScopeId: "p_1", Grants: []string{arGrant},
		State: accessrequest.StateApproved, CreatedAt: now.Add(-2 * time.Hour), DecidedAt: now.Add(-time.Hour),
		DecidedBy: "u_app", ExpiresAt: now.Add(time.Hour), Duration: time.Hour,
	})
	require.NoError(t, err)
	return repo
}

func TestNewAccessRequestOverlayGrantsExactlyTheApprovedGrant(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	rec := &accessrequest.RecordingEmitter{}
	p := newAccessRequestOverlay(approvedRepo(t, now), arClock{now}, rec)
	require.NotNil(t, p)
	got, err := p.OverlayGrants(context.Background(), "u_req", "p_1")
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, arGrant, got[0].Grant)
	assert.Len(t, rec.Events(), 1)

	other, err := p.OverlayGrants(context.Background(), "u_other", "p_1")
	require.NoError(t, err)
	assert.Empty(t, other, "another user gets nothing")
	otherScope, err := p.OverlayGrants(context.Background(), "u_req", "p_2")
	require.NoError(t, err)
	assert.Empty(t, otherScope, "another scope gets nothing")
}

func TestNewAccessRequestOverlayMissingDependenciesLeaveItUnset(t *testing.T) {
	now := time.Now()
	rec := &accessrequest.RecordingEmitter{}
	assert.Nil(t, newAccessRequestOverlay(nil, arClock{now}, rec))
	assert.Nil(t, newAccessRequestOverlay(approvedRepo(t, now), nil, rec))
	assert.Nil(t, newAccessRequestOverlay(approvedRepo(t, now), arClock{now}, nil))
}

func TestAccessRequestOverlayErrorsGiveNoGrants(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	p := newAccessRequestOverlay(failingRepo{}, arClock{now}, &accessrequest.RecordingEmitter{})
	got, err := p.OverlayGrants(context.Background(), "u_req", "p_1")
	require.ErrorIs(t, err, accessrequest.ErrOverlayUnavailable)
	assert.Empty(t, got)
	assert.NotContains(t, err.Error(), "canary-dsn")
}

func TestAccessRequestSysEmitter(t *testing.T) {
	ev := accessrequest.Event{Type: accessrequest.EventOverlayAuthorized, RequestId: "ar_1", RequesterId: "u_req", Grants: []string{arGrant}}
	var gotMsg string
	var gotArgs []any
	e := accessRequestSysEmitter{write: func(_ context.Context, _ event.Op, msg string, args ...any) {
		gotMsg, gotArgs = msg, args
	}}
	require.NoError(t, e.Emit(context.Background(), ev))
	assert.Equal(t, "access-request.overlay-authorized", gotMsg)
	assert.Contains(t, gotArgs, "ar_1")
	assert.True(t, strings.Contains(strings.Join(argStrings(gotArgs), ","), "u_req"))

	// A missing writer fails closed so the overlay gives no grant.
	require.Error(t, accessRequestSysEmitter{}.Emit(context.Background(), ev))
	p := newAccessRequestOverlay(approvedRepo(t, time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)),
		arClock{time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}, accessRequestSysEmitter{})
	got, err := p.OverlayGrants(context.Background(), "u_req", "p_1")
	require.ErrorIs(t, err, accessrequest.ErrOverlayUnavailable)
	assert.Empty(t, got)
}

func argStrings(a []any) []string {
	var out []string
	for _, v := range a {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
