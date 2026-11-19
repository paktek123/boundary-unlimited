// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package accessrequests

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/accessrequest"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/accessrequests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const grantA = "ids=ttcp_1;actions=read"

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC) }

type ctxKey struct{}

// actorsByCtx resolves the actor stored in the context; none means unauthenticated.
type actorsByCtx struct{}

func (actorsByCtx) Actor(ctx context.Context, _ string) (accessrequest.Actor, error) {
	a, ok := ctx.Value(ctxKey{}).(accessrequest.Actor)
	if !ok {
		return accessrequest.Actor{}, errors.New("no actor")
	}
	return a, nil
}

func as(a accessrequest.Actor) context.Context {
	return context.WithValue(context.Background(), ctxKey{}, a)
}

var (
	requester = accessrequest.Actor{Id: "u_req"}
	other     = accessrequest.Actor{Id: "u_other"}
	approver  = accessrequest.Actor{Id: "u_app", CanApprove: true, Grants: []string{grantA}}
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	repo := accessrequest.NewMemRepository()
	n := 0
	core, err := accessrequest.NewService(accessrequest.ServiceConfig{
		Repo: repo, Policy: accessrequest.DefaultApprovalPolicy(), Audit: &accessrequest.RecordingEmitter{},
		Clock: fixedClock{}, NewId: func() (string, error) { n++; return fmt.Sprintf("ar_%d", n), nil },
	})
	require.NoError(t, err)
	s, err := NewService(core, repo, actorsByCtx{})
	require.NoError(t, err)
	return s
}

func create(t *testing.T, s *Service) *pb.AccessRequest {
	t.Helper()
	resp, err := s.CreateAccessRequest(as(requester), &pbs.CreateAccessRequestRequest{Item: &pb.AccessRequest{
		ScopeId: "o_1", Grants: []string{grantA}, Justification: "why", DurationSeconds: 3600,
		RequesterId: "u_spoofed",
	}})
	require.NoError(t, err)
	return resp.Item
}

func code(err error) codes.Code { return status.Code(err) }

func TestNewService_FailsClosed(t *testing.T) {
	_, err := NewService(nil, nil, nil)
	require.Error(t, err)
}

func TestCreateIgnoresClientRequesterAndNeedsAuth(t *testing.T) {
	s := newTestService(t)
	it := create(t, s)
	assert.Equal(t, requester.Id, it.RequesterId)
	assert.Equal(t, "pending", it.State)
	_, err := s.CreateAccessRequest(context.Background(), &pbs.CreateAccessRequestRequest{Item: &pb.AccessRequest{ScopeId: "o_1"}})
	assert.Equal(t, codes.Unauthenticated, code(err))
}

func TestGetVisibility(t *testing.T) {
	s := newTestService(t)
	it := create(t, s)
	_, err := s.GetAccessRequest(as(requester), &pbs.GetAccessRequestRequest{Id: it.Id})
	require.NoError(t, err)
	_, err = s.GetAccessRequest(as(approver), &pbs.GetAccessRequestRequest{Id: it.Id})
	require.NoError(t, err)
	_, err = s.GetAccessRequest(as(other), &pbs.GetAccessRequestRequest{Id: it.Id})
	assert.Equal(t, codes.NotFound, code(err))
	_, err = s.GetAccessRequest(context.Background(), &pbs.GetAccessRequestRequest{Id: it.Id})
	assert.Equal(t, codes.Unauthenticated, code(err))
}

func TestListOnlyVisible(t *testing.T) {
	s := newTestService(t)
	create(t, s)
	resp, err := s.ListAccessRequests(as(other), &pbs.ListAccessRequestsRequest{ScopeId: "o_1"})
	require.NoError(t, err)
	assert.Empty(t, resp.Items)
	resp, err = s.ListAccessRequests(as(requester), &pbs.ListAccessRequestsRequest{ScopeId: "o_1"})
	require.NoError(t, err)
	assert.Len(t, resp.Items, 1)
	resp, err = s.ListAccessRequests(as(approver), &pbs.ListAccessRequestsRequest{ScopeId: "o_1"})
	require.NoError(t, err)
	assert.Len(t, resp.Items, 1)
	_, err = s.ListAccessRequests(as(approver), &pbs.ListAccessRequestsRequest{ScopeId: "o_1", Recursive: true})
	assert.Equal(t, codes.InvalidArgument, code(err))
}

func TestApproveRules(t *testing.T) {
	s := newTestService(t)
	it := create(t, s)
	// the requester cannot approve their own request even holding the right
	selfApprover := accessrequest.Actor{Id: requester.Id, CanApprove: true, Grants: []string{grantA}}
	_, err := s.ApproveAccessRequest(as(selfApprover), &pbs.ApproveAccessRequestRequest{Id: it.Id, Version: it.Version})
	assert.Equal(t, codes.PermissionDenied, code(err))
	// an unrelated user cannot even see it
	_, err = s.ApproveAccessRequest(as(other), &pbs.ApproveAccessRequestRequest{Id: it.Id, Version: it.Version})
	assert.Equal(t, codes.NotFound, code(err))
	// the version is required and must match
	_, err = s.ApproveAccessRequest(as(approver), &pbs.ApproveAccessRequestRequest{Id: it.Id})
	assert.Equal(t, codes.Aborted, code(err))
	_, err = s.ApproveAccessRequest(as(approver), &pbs.ApproveAccessRequestRequest{Id: it.Id, Version: it.Version + 5})
	assert.Equal(t, codes.Aborted, code(err))
	resp, err := s.ApproveAccessRequest(as(approver), &pbs.ApproveAccessRequestRequest{Id: it.Id, Version: it.Version})
	require.NoError(t, err)
	assert.Equal(t, "approved", resp.Item.State)
	assert.Equal(t, approver.Id, resp.Item.DecidedBy)
}

func TestDenyAndCancel(t *testing.T) {
	s := newTestService(t)
	a := create(t, s)
	resp, err := s.DenyAccessRequest(as(approver), &pbs.DenyAccessRequestRequest{Id: a.Id, Version: a.Version})
	require.NoError(t, err)
	assert.Equal(t, "denied", resp.Item.State)

	b := create(t, s)
	_, err = s.CancelAccessRequest(as(approver), &pbs.CancelAccessRequestRequest{Id: b.Id, Version: b.Version})
	assert.Equal(t, codes.PermissionDenied, code(err))
	cr, err := s.CancelAccessRequest(as(requester), &pbs.CancelAccessRequestRequest{Id: b.Id, Version: b.Version})
	require.NoError(t, err)
	assert.Equal(t, "cancelled", cr.Item.State)
}

func TestRevokeUnsupported(t *testing.T) {
	s := newTestService(t)
	_, err := s.RevokeAccessRequest(as(approver), &pbs.RevokeAccessRequestRequest{Id: "ar_1", Version: 1})
	assert.Equal(t, codes.Unimplemented, code(err))
}

func TestUnauthenticatedCannotProbeIds(t *testing.T) {
	s := newTestService(t)
	it := create(t, s)
	for _, id := range []string{it.Id, "ar_missing"} {
		_, err := s.GetAccessRequest(context.Background(), &pbs.GetAccessRequestRequest{Id: id})
		assert.Equal(t, codes.Unauthenticated, code(err), id)
		_, err = s.ApproveAccessRequest(context.Background(), &pbs.ApproveAccessRequestRequest{Id: id, Version: 1})
		assert.Equal(t, codes.Unauthenticated, code(err), id)
	}
	_, err := s.ListAccessRequests(context.Background(), &pbs.ListAccessRequestsRequest{ScopeId: "o_1"})
	assert.Equal(t, codes.Unauthenticated, code(err))
}

func TestDecisionsByInvisibleActorAreNotFound(t *testing.T) {
	s := newTestService(t)
	it := create(t, s)
	_, err := s.DenyAccessRequest(as(other), &pbs.DenyAccessRequestRequest{Id: it.Id, Version: it.Version})
	assert.Equal(t, codes.NotFound, code(err))
	_, err = s.CancelAccessRequest(as(other), &pbs.CancelAccessRequestRequest{Id: it.Id, Version: it.Version})
	assert.Equal(t, codes.NotFound, code(err))
}

func TestApproveAlreadyDecided(t *testing.T) {
	s := newTestService(t)
	it := create(t, s)
	resp, err := s.DenyAccessRequest(as(approver), &pbs.DenyAccessRequestRequest{Id: it.Id, Version: it.Version})
	require.NoError(t, err)
	_, err = s.ApproveAccessRequest(as(approver), &pbs.ApproveAccessRequestRequest{Id: it.Id, Version: resp.Item.Version})
	assert.Equal(t, codes.InvalidArgument, code(err))
}

func TestMapErr(t *testing.T) {
	tests := []struct {
		err  error
		want codes.Code
	}{
		{accessrequest.ErrNotFound, codes.NotFound},
		{accessrequest.ErrVersionConflict, codes.Aborted},
		{accessrequest.ErrSelfApproval, codes.PermissionDenied},
		{accessrequest.ErrNotRequester, codes.PermissionDenied},
		{accessrequest.ErrApproverNotAuthorized, codes.PermissionDenied},
		{accessrequest.ErrGrantsNotHeld, codes.PermissionDenied},
		{accessrequest.ErrWildcardGrant, codes.PermissionDenied},
		{accessrequest.ErrGrantsChanged, codes.PermissionDenied},
		{accessrequest.ErrInvalidInput, codes.InvalidArgument},
		{accessrequest.ErrInvalidState, codes.InvalidArgument},
		{accessrequest.ErrInvalidTransition, codes.InvalidArgument},
		{accessrequest.ErrDurationTooLong, codes.InvalidArgument},
		{accessrequest.ErrPendingExpired, codes.InvalidArgument},
		{errors.New("boom"), codes.Internal},
	}
	for _, tc := range tests {
		t.Run(tc.err.Error(), func(t *testing.T) {
			assert.Equal(t, tc.want, code(mapErr(fmt.Errorf("wrapped: %w", tc.err))))
		})
	}
}
