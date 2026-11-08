// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package accessrequest

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func approved(id string, grants ...string) Request {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	return Request{
		Id: id, RequesterId: "u_1", ScopeId: "p_1234567890", Grants: grants,
		State: StateApproved, DecidedAt: t0, DecidedBy: "u_2", ExpiresAt: t0.Add(time.Hour),
	}
}

func TestEffectiveGrants(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	const g = "ids=*;type=target;actions=read"
	tests := []struct {
		name string
		mod  func(*Request)
		now  time.Time
		want int
	}{
		{"active", nil, t0.Add(time.Minute), 1},
		{"at approval instant", nil, t0, 1},
		{"before approval", nil, t0.Add(-time.Nanosecond), 0},
		{"last tick before expiry", nil, t0.Add(time.Hour - time.Nanosecond), 1},
		{"expiry instant is expired", nil, t0.Add(time.Hour), 0},
		{"after expiry", nil, t0.Add(2 * time.Hour), 0},
		{"pending", func(r *Request) { r.State = StatePending }, t0.Add(time.Minute), 0},
		{"denied", func(r *Request) { r.State = StateDenied }, t0.Add(time.Minute), 0},
		{"cancelled", func(r *Request) { r.State = StateCancelled }, t0.Add(time.Minute), 0},
		{"revoked", func(r *Request) { r.State = StateRevoked }, t0.Add(time.Minute), 0},
		{"expired state", func(r *Request) { r.State = StateExpired }, t0.Add(time.Minute), 0},
		{"unknown state", func(r *Request) { r.State = "weird" }, t0.Add(time.Minute), 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := approved("ar_1", g)
			if tt.mod != nil {
				tt.mod(&r)
			}
			got, _ := EffectiveGrants(context.Background(), []Request{r}, tt.now)
			require.Len(t, got, tt.want)
			if tt.want == 1 {
				assert.Equal(t, g, got[0].Grant)
				assert.Equal(t, "ar_1", got[0].RequestId)
				assert.Equal(t, "p_1234567890", got[0].ScopeId)
				assert.Equal(t, t0, got[0].NotBefore)
				assert.Equal(t, t0.Add(time.Hour), got[0].NotAfter)
			}
		})
	}
}

func TestEffectiveGrantsDropsInvalidAndMalformed(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	now := t0.Add(time.Minute)
	const secret = "not-a-grant-with-secret-123"
	mixed := approved("ar_mixed", "ids=*;type=target;actions=read", secret)

	noExpiry := approved("ar_noexp", "ids=*;type=target;actions=read")
	noExpiry.ExpiresAt = time.Time{}
	noDecided := approved("ar_nodec", "ids=*;type=target;actions=read")
	noDecided.DecidedAt = time.Time{}
	backwards := approved("ar_back", "ids=*;type=target;actions=read")
	backwards.ExpiresAt = backwards.DecidedAt
	noGrants := approved("ar_none")
	noScope := approved("ar_noscope", "ids=*;type=target;actions=read")
	noScope.ScopeId = ""

	got, dropped := EffectiveGrants(context.Background(), []Request{mixed, noExpiry, noDecided, backwards, noGrants, noScope}, now)
	require.Len(t, got, 1)
	assert.Equal(t, "ids=*;type=target;actions=read", got[0].Grant)

	ids := map[string]Dropped{}
	for _, d := range dropped {
		ids[d.RequestId] = d
		assert.NotContains(t, d.Reason, secret)
	}
	assert.Equal(t, Dropped{RequestId: "ar_mixed", GrantIndex: 1, Reason: ReasonInvalidGrant}, ids["ar_mixed"])
	for _, id := range []string{"ar_noexp", "ar_nodec", "ar_back", "ar_none", "ar_noscope"} {
		assert.Equal(t, Dropped{RequestId: id, GrantIndex: -1, Reason: ReasonMalformedRequest}, ids[id], id)
	}
}

func TestEffectiveGrantsNeverWidens(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	in := []string{"ids=ttcp_1;actions=read", "ids=ttcp_2;actions=authorize-session"}
	r := approved("ar_1", in...)
	got, dropped := EffectiveGrants(context.Background(), []Request{r}, t0.Add(time.Second))
	assert.Empty(t, dropped)
	require.Len(t, got, 2)
	assert.Equal(t, in[0], got[0].Grant)
	assert.Equal(t, in[1], got[1].Grant)
	// The input is not modified.
	assert.Equal(t, in, r.Grants)
}

func TestEffectiveGrantsEmpty(t *testing.T) {
	got, dropped := EffectiveGrants(context.Background(), nil, time.Now())
	assert.Empty(t, got)
	assert.Empty(t, dropped)
}
