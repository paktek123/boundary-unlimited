// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package accessrequest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/perms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeSource struct {
	reqs  []Request
	err   error
	panic bool
}

func (f fakeSource) OverlayRequests(context.Context, string, string) ([]Request, error) {
	if f.panic {
		panic("boom")
	}
	return f.reqs, f.err
}

type mergeClock struct{ t time.Time }

func (c mergeClock) Now() time.Time { return c.t }

type panicClock struct{}

func (panicClock) Now() time.Time { panic("boom") }

var baseGrants = []perms.GrantTuple{{RoleId: "r_1", RoleScopeId: "o_1", GrantScopeId: "o_1", Grant: "ids=*;type=*;actions=read"}}

func TestMergeOverlay(t *testing.T) {
	ctx := context.Background()
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	const g = "ids=*;type=target;actions=read"
	req := func() Request { return approved("ar_1", g) }

	tests := []struct {
		name     string
		src      GrantOverlaySource
		clock    Clock
		wantOver int
		wantErr  bool
	}{
		{"active", fakeSource{reqs: []Request{req()}}, mergeClock{t0.Add(time.Minute)}, 1, false},
		{"one tick before approval", fakeSource{reqs: []Request{req()}}, mergeClock{t0.Add(-time.Nanosecond)}, 0, false},
		{"expiry instant", fakeSource{reqs: []Request{req()}}, mergeClock{t0.Add(time.Hour)}, 0, false},
		{"last tick before expiry", fakeSource{reqs: []Request{req()}}, mergeClock{t0.Add(time.Hour - time.Nanosecond)}, 1, false},
		{"source error", fakeSource{reqs: []Request{req()}, err: errors.New("db down")}, mergeClock{t0.Add(time.Minute)}, 0, true},
		{"source panic", fakeSource{panic: true}, mergeClock{t0.Add(time.Minute)}, 0, true},
		{"zero clock", fakeSource{reqs: []Request{req()}}, mergeClock{}, 0, true},
		{"panic clock", fakeSource{reqs: []Request{req()}}, panicClock{}, 0, true},
		{"nil source", nil, mergeClock{t0}, 0, true},
		{"nil clock", fakeSource{}, nil, 0, true},
		{"wide grant dropped", fakeSource{reqs: []Request{approved("ar_2", "ids=*;type=*;actions=*")}}, mergeClock{t0.Add(time.Minute)}, 0, false},
		{"star grant dropped", fakeSource{reqs: []Request{approved("ar_2", "*")}}, mergeClock{t0.Add(time.Minute)}, 0, false},
		{"unparsable grant", fakeSource{reqs: []Request{approved("ar_3", "not a grant")}}, mergeClock{t0.Add(time.Minute)}, 0, false},
		{"malformed record", fakeSource{reqs: []Request{{Id: "ar_4", State: StateApproved}}}, mergeClock{t0.Add(time.Minute)}, 0, false},
		{"other user", fakeSource{reqs: []Request{func() Request { r := req(); r.RequesterId = "u_other"; return r }()}}, mergeClock{t0.Add(time.Minute)}, 0, false},
		{"other scope", fakeSource{reqs: []Request{func() Request { r := req(); r.ScopeId = "p_other"; return r }()}}, mergeClock{t0.Add(time.Minute)}, 0, false},
		{"pending", fakeSource{reqs: []Request{func() Request { r := req(); r.State = StatePending; return r }()}}, mergeClock{t0.Add(time.Minute)}, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := MergeOverlay(ctx, baseGrants, "u_1", "p_1234567890", tt.src, tt.clock)
			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrOverlayUnavailable)
			} else {
				require.NoError(t, err)
			}
			require.GreaterOrEqual(t, len(res.Grants), 1)
			assert.Equal(t, baseGrants[0], res.Grants[0], "base grants unchanged")
			assert.Len(t, res.Grants, 1+tt.wantOver)
			assert.Len(t, res.Events, tt.wantOver)
			if tt.wantOver == 1 {
				assert.Equal(t, "p_1234567890", res.Grants[1].GrantScopeId)
				assert.Equal(t, g, res.Grants[1].Grant)
			}
		})
	}
}

func TestMergeOverlay_WildcardReported(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	res, err := MergeOverlay(context.Background(), nil, "u_1", "p_1234567890",
		fakeSource{reqs: []Request{approved("ar_2", "ids=*;type=*;actions=*")}}, mergeClock{t0.Add(time.Minute)})
	require.NoError(t, err)
	require.Len(t, res.Dropped, 1)
	assert.Equal(t, ReasonWildcardGrant, res.Dropped[0].Reason)
	assert.Empty(t, res.Grants)
}

func TestMergeOverlay_BaseNotAliased(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	base := make([]perms.GrantTuple, 1, 8)
	base[0] = baseGrants[0]
	res, err := MergeOverlay(context.Background(), base, "u_1", "p_1234567890",
		fakeSource{reqs: []Request{approved("ar_1", "ids=*;type=target;actions=read")}}, mergeClock{t0.Add(time.Minute)})
	require.NoError(t, err)
	require.Len(t, res.Grants, 2)
	assert.Len(t, base, 1)
	assert.Equal(t, perms.GrantTuple{}, base[:2][1], "caller's backing array untouched")
}

func TestMergeOverlay_EventsHaveNoCredentials(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	r := approved("ar_1", "ids=*;type=target;actions=read")
	r.Justification = "CANARY-password=hunter2-AKIAIOSFODNN7EXAMPLE"
	res, err := MergeOverlay(context.Background(), nil, "u_1", "p_1234567890",
		fakeSource{reqs: []Request{r}}, mergeClock{t0.Add(time.Minute)})
	require.NoError(t, err)
	require.Len(t, res.Events, 1)
	assert.NotContains(t, res.Events[0].Grants, "CANARY")
	assert.NotContains(t, res.Events[0].RequestId, "CANARY")
	assert.Equal(t, EventOverlayAuthorized, res.Events[0].Type)
	for _, d := range res.Dropped {
		assert.NotContains(t, d.Reason, "CANARY")
	}
}

func TestRepositorySource(t *testing.T) {
	ctx := context.Background()
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	repo := NewMemRepository()
	r := approved("ar_1", "ids=*;type=target;actions=read")
	r.Version = 0
	_, err := repo.Create(ctx, r)
	require.NoError(t, err)
	res, err := MergeOverlay(ctx, baseGrants, "u_1", "p_1234567890", RepositorySource{Repo: repo}, mergeClock{t0.Add(time.Minute)})
	require.NoError(t, err)
	assert.Len(t, res.Grants, 2)
	_, err = MergeOverlay(ctx, baseGrants, "u_1", "p_1234567890", RepositorySource{}, mergeClock{t0})
	require.ErrorIs(t, err, ErrOverlayUnavailable)
}
