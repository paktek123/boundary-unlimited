// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

// Package accessrequests adapts accessrequest.Service to the generated
// AccessRequestServiceServer. It is NOT registered in the controller: nothing
// outside tests can reach it, so no endpoint accepts access requests yet.
package accessrequests

import (
	"context"
	"errors"
	"time"

	"github.com/hashicorp/boundary/internal/accessrequest"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/accessrequests"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ActorResolver resolves the authenticated caller and whether it may approve
// in scopeId. Implementations must derive both from the authenticated
// request, never from request fields. An error means unauthenticated.
type ActorResolver interface {
	Actor(ctx context.Context, scopeId string) (accessrequest.Actor, error)
}

// Service implements pbs.AccessRequestServiceServer.
type Service struct {
	pbs.UnimplementedAccessRequestServiceServer
	svc    *accessrequest.Service
	repo   accessrequest.Repository
	actors ActorResolver
}

var _ pbs.AccessRequestServiceServer = (*Service)(nil)

// NewService requires every dependency (fail closed).
func NewService(svc *accessrequest.Service, repo accessrequest.Repository, actors ActorResolver) (*Service, error) {
	if svc == nil || repo == nil || actors == nil {
		return nil, errors.New("accessrequests: service, repository and actor resolver are required")
	}
	return &Service{svc: svc, repo: repo, actors: actors}, nil
}

func mapErr(err error) error {
	switch {
	case errors.Is(err, accessrequest.ErrNotFound):
		return status.Error(codes.NotFound, "access request not found")
	case errors.Is(err, accessrequest.ErrVersionConflict):
		return status.Error(codes.Aborted, "version conflict")
	case errors.Is(err, accessrequest.ErrSelfApproval), errors.Is(err, accessrequest.ErrNotRequester),
		errors.Is(err, accessrequest.ErrApproverNotAuthorized), errors.Is(err, accessrequest.ErrGrantsNotHeld),
		errors.Is(err, accessrequest.ErrWildcardGrant), errors.Is(err, accessrequest.ErrGrantsChanged):
		return status.Error(codes.PermissionDenied, "forbidden")
	case errors.Is(err, accessrequest.ErrInvalidInput), errors.Is(err, accessrequest.ErrInvalidState),
		errors.Is(err, accessrequest.ErrInvalidTransition), errors.Is(err, accessrequest.ErrDurationTooLong),
		errors.Is(err, accessrequest.ErrPendingExpired):
		return status.Error(codes.InvalidArgument, "invalid request")
	default:
		return status.Error(codes.Internal, "internal error")
	}
}

// visible reports whether the actor may see r: the requester or an approver
// of its scope. Anything else looks like not found.
func visible(a accessrequest.Actor, r accessrequest.Request) bool {
	return a.Id != "" && (r.RequesterId == a.Id || a.CanApprove)
}

func toPB(r accessrequest.Request) *pb.AccessRequest {
	out := &pb.AccessRequest{
		Id: r.Id, ScopeId: r.ScopeId, RequesterId: r.RequesterId,
		Grants: append([]string(nil), r.Grants...), Justification: r.Justification,
		DurationSeconds: uint32(r.Duration / time.Second), State: string(r.State),
		DecidedBy: r.DecidedBy, Version: r.Version,
		CreatedTime: timestamppb.New(r.CreatedAt),
	}
	if !r.DecidedAt.IsZero() {
		out.DecidedTime = timestamppb.New(r.DecidedAt)
	}
	if !r.ExpiresAt.IsZero() {
		out.ExpirationTime = timestamppb.New(r.ExpiresAt)
	}
	return out
}

// load fetches a request and checks visibility and the optimistic version.
// Invisible requests are reported as not found.
func (s *Service) load(ctx context.Context, id string, version uint32, checkVersion bool) (accessrequest.Actor, accessrequest.Request, error) {
	r, err := s.repo.Get(ctx, id)
	if err != nil {
		return accessrequest.Actor{}, r, mapErr(err)
	}
	a, err := s.actors.Actor(ctx, r.ScopeId)
	if err != nil {
		return a, r, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	if !visible(a, r) {
		return a, r, status.Error(codes.NotFound, "access request not found")
	}
	if checkVersion && (version == 0 || version != r.Version) {
		return a, r, status.Error(codes.Aborted, "version conflict")
	}
	return a, r, nil
}

// GetAccessRequest implements pbs.AccessRequestServiceServer.
func (s *Service) GetAccessRequest(ctx context.Context, req *pbs.GetAccessRequestRequest) (*pbs.GetAccessRequestResponse, error) {
	_, r, err := s.load(ctx, req.GetId(), 0, false)
	if err != nil {
		return nil, err
	}
	return &pbs.GetAccessRequestResponse{Item: toPB(r)}, nil
}

// ListAccessRequests lists the requests of one scope the caller may see.
func (s *Service) ListAccessRequests(ctx context.Context, req *pbs.ListAccessRequestsRequest) (*pbs.ListAccessRequestsResponse, error) {
	if req.GetScopeId() == "" || req.GetRecursive() {
		return nil, status.Error(codes.InvalidArgument, "a single scope id is required")
	}
	a, err := s.actors.Actor(ctx, req.GetScopeId())
	if err != nil || a.Id == "" {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	f := accessrequest.ListFilter{ScopeId: req.GetScopeId()}
	if !a.CanApprove {
		f.RequesterId = a.Id
	}
	rs, err := s.repo.List(ctx, f)
	if err != nil {
		return nil, mapErr(err)
	}
	out := &pbs.ListAccessRequestsResponse{ResponseType: "complete"}
	for _, r := range rs {
		if visible(a, r) {
			out.Items = append(out.Items, toPB(r))
		}
	}
	return out, nil
}

// CreateAccessRequest creates a pending request for the authenticated caller;
// the requester is never taken from the message.
func (s *Service) CreateAccessRequest(ctx context.Context, req *pbs.CreateAccessRequestRequest) (*pbs.CreateAccessRequestResponse, error) {
	it := req.GetItem()
	if it == nil || it.GetScopeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "item with scope_id is required")
	}
	a, err := s.actors.Actor(ctx, it.GetScopeId())
	if err != nil || a.Id == "" {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	r, err := s.svc.Create(ctx, a, it.GetScopeId(), it.GetGrants(), it.GetJustification(),
		time.Duration(it.GetDurationSeconds())*time.Second)
	if err != nil {
		return nil, mapErr(err)
	}
	return &pbs.CreateAccessRequestResponse{Item: toPB(r)}, nil
}

// ApproveAccessRequest implements pbs.AccessRequestServiceServer.
func (s *Service) ApproveAccessRequest(ctx context.Context, req *pbs.ApproveAccessRequestRequest) (*pbs.ApproveAccessRequestResponse, error) {
	a, _, err := s.load(ctx, req.GetId(), req.GetVersion(), true)
	if err != nil {
		return nil, err
	}
	r, err := s.svc.Approve(ctx, a, req.GetId())
	if err != nil {
		return nil, mapErr(err)
	}
	return &pbs.ApproveAccessRequestResponse{Item: toPB(r)}, nil
}

// DenyAccessRequest implements pbs.AccessRequestServiceServer.
func (s *Service) DenyAccessRequest(ctx context.Context, req *pbs.DenyAccessRequestRequest) (*pbs.DenyAccessRequestResponse, error) {
	a, _, err := s.load(ctx, req.GetId(), req.GetVersion(), true)
	if err != nil {
		return nil, err
	}
	r, err := s.svc.Deny(ctx, a, req.GetId())
	if err != nil {
		return nil, mapErr(err)
	}
	return &pbs.DenyAccessRequestResponse{Item: toPB(r)}, nil
}

// CancelAccessRequest implements pbs.AccessRequestServiceServer.
func (s *Service) CancelAccessRequest(ctx context.Context, req *pbs.CancelAccessRequestRequest) (*pbs.CancelAccessRequestResponse, error) {
	a, _, err := s.load(ctx, req.GetId(), req.GetVersion(), true)
	if err != nil {
		return nil, err
	}
	r, err := s.svc.Cancel(ctx, a, req.GetId())
	if err != nil {
		return nil, mapErr(err)
	}
	return &pbs.CancelAccessRequestResponse{Item: toPB(r)}, nil
}

// RevokeAccessRequest is not supported: the service has no revoke operation
// yet, so it is refused rather than accepted without effect.
func (s *Service) RevokeAccessRequest(context.Context, *pbs.RevokeAccessRequestRequest) (*pbs.RevokeAccessRequestResponse, error) {
	return nil, status.Error(codes.Unimplemented, "revoking an access request is not yet supported")
}
