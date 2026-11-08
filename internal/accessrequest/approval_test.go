// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package accessrequest

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func approvalFixture() (Request, ApproverContext, time.Time) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	req := Request{
		Id: "ar_1", RequesterId: "u_req", ScopeId: "p_1",
		Grants:   []string{"ids=ttcp_1;actions=authorize-session", "ids=ttcp_2;actions=read"},
		Duration: time.Hour, State: StatePending, CreatedAt: t0,
	}
	ap := ApproverContext{
		Id: "u_app", CanApprove: true,
		Grants: []string{"ids=ttcp_1;actions=authorize-session", "ids=ttcp_2;actions=read", "ids=ttcp_3;actions=read"},
	}
	return req, ap, t0.Add(time.Minute)
}

func TestValidateApproval(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Request, *ApproverContext)
		policy ApprovalPolicy
		want   error
	}{
		{"ok", func(*Request, *ApproverContext) {}, DefaultApprovalPolicy(), nil},
		{"ok segment order and case", func(r *Request, _ *ApproverContext) {
			r.Grants = []string{"Actions=authorize-session; IDS=ttcp_1"}
		}, DefaultApprovalPolicy(), nil},
		{"self approval", func(_ *Request, a *ApproverContext) { a.Id = "u_req" }, DefaultApprovalPolicy(), ErrSelfApproval},
		{"missing approver id", func(_ *Request, a *ApproverContext) { a.Id = "" }, DefaultApprovalPolicy(), ErrInvalidInput},
		{"no approve action", func(_ *Request, a *ApproverContext) { a.CanApprove = false }, DefaultApprovalPolicy(), ErrApproverNotAuthorized},
		{"missing one grant", func(r *Request, _ *ApproverContext) {
			r.Grants = append(r.Grants, "ids=ttcp_9;actions=read")
		}, DefaultApprovalPolicy(), ErrGrantsNotHeld},
		{"approver has no grants", func(_ *Request, a *ApproverContext) { a.Grants = nil }, DefaultApprovalPolicy(), ErrGrantsNotHeld},
		{"no grants requested", func(r *Request, _ *ApproverContext) { r.Grants = nil }, DefaultApprovalPolicy(), ErrInvalidInput},
		{"empty grant", func(r *Request, _ *ApproverContext) { r.Grants = []string{"  "} }, DefaultApprovalPolicy(), ErrInvalidInput},
		{"ttl over policy", func(r *Request, _ *ApproverContext) { r.Duration = 2 * time.Hour }, ApprovalPolicy{MaxTTL: time.Hour}, ErrDurationTooLong},
		{"zero policy ttl", func(*Request, *ApproverContext) {}, ApprovalPolicy{}, ErrInvalidPolicy},
		{"negative policy ttl", func(*Request, *ApproverContext) {}, ApprovalPolicy{MaxTTL: -1}, ErrInvalidPolicy},
		{"zero duration", func(r *Request, _ *ApproverContext) { r.Duration = 0 }, DefaultApprovalPolicy(), ErrInvalidInput},
		{"bare star", func(r *Request, _ *ApproverContext) { r.Grants = []string{"*"} }, DefaultApprovalPolicy(), ErrWildcardGrant},
		{"ids and actions star", func(r *Request, _ *ApproverContext) { r.Grants = []string{"id=*;actions=*"} }, DefaultApprovalPolicy(), ErrWildcardGrant},
		{"ids/type/actions star", func(r *Request, _ *ApproverContext) {
			r.Grants = []string{"ids=*;type=*;actions=*"}
		}, DefaultApprovalPolicy(), ErrWildcardGrant},
		{"wildcard held exactly", func(r *Request, a *ApproverContext) {
			r.Grants = []string{"id=*;actions=*"}
			a.Grants = []string{" ID=*; actions=* "}
		}, DefaultApprovalPolicy(), nil},
		{"hash mismatch", func(r *Request, _ *ApproverContext) { r.GrantHash = "deadbeef" }, DefaultApprovalPolicy(), ErrGrantsChanged},
		{"state is not checked here, Approve checks it", func(r *Request, _ *ApproverContext) { r.State = StateApproved }, DefaultApprovalPolicy(), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, ap, now := approvalFixture()
			tt.mutate(&req, &ap)
			err := ValidateApproval(req, ap, now, tt.policy)
			if tt.want == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tt.want)
			for _, g := range req.Grants {
				assert.NotContains(t, err.Error(), g, "errors must not contain grants")
			}
		})
	}
}

func TestRecordApprovalAndVerify(t *testing.T) {
	req, ap, now := approvalFixture()
	out, err := RecordApproval(req, ap, now, DefaultApprovalPolicy())
	require.NoError(t, err)
	assert.Equal(t, StateApproved, out.State)
	assert.Equal(t, GrantHash(req.Grants), out.GrantHash)
	assert.Empty(t, req.GrantHash, "input unchanged")
	require.NoError(t, VerifyApprovedGrants(out))

	// Tampering with grants after approval fails verification.
	out.Grants = append(append([]string(nil), out.Grants...), "ids=*;actions=*")
	assert.ErrorIs(t, VerifyApprovedGrants(out), ErrGrantsChanged)

	// Approved without a hash fails closed.
	nohash, err := Approve(req, "u_app", now)
	require.NoError(t, err)
	assert.ErrorIs(t, VerifyApprovedGrants(nohash), ErrGrantsChanged)
	assert.Error(t, VerifyApprovedGrants(req), "pending request")

	// Errors leave the request unchanged.
	ap.CanApprove = false
	same, err := RecordApproval(req, ap, now, DefaultApprovalPolicy())
	require.ErrorIs(t, err, ErrApproverNotAuthorized)
	assert.Equal(t, req, same)

	// Policy TTL is authoritative even if an option loosens it.
	req.Duration = 3 * time.Hour
	ap.CanApprove = true
	_, err = RecordApproval(req, ap, now, ApprovalPolicy{MaxTTL: time.Hour}, WithMaxDuration(10*time.Hour))
	assert.ErrorIs(t, err, ErrDurationTooLong)
}

func TestGrantHash(t *testing.T) {
	a := GrantHash([]string{"ids=a;actions=read", "ids=b;actions=read"})
	assert.Len(t, a, 64)
	assert.Equal(t, a, GrantHash([]string{"IDS=b;actions=read", " actions=read;ids=a ", "ids=a;actions=read"}), "order, case, spacing, duplicates")
	assert.NotEqual(t, a, GrantHash([]string{"ids=a;actions=read"}))
	assert.NotEqual(t, a, GrantHash([]string{"ids=a;actions=read", "ids=b;actions=update"}))
	assert.NotEqual(t, GrantHash([]string{"a", "b"}), GrantHash([]string{"a\n1:b"}), "length prefixed")
	assert.False(t, strings.Contains(a, "ids"))
}
