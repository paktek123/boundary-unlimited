// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package runbooks

import (
	"context"
	"errors"

	"github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/runbook"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/runbooks"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CallerResolver resolves the authenticated caller and its grants from the
// request context only, never from request fields. An error means
// unauthenticated.
type CallerResolver interface {
	Caller(ctx context.Context) (Caller, error)
}

// GRPCService adapts Service to services.RunbookServiceServer for the read and
// delete operations. Create and update stay Unimplemented until the source of
// the script body is decided (issue #279). It is NOT registered in the
// controller.
type GRPCService struct {
	services.UnimplementedRunbookServiceServer
	svc     *Service
	callers CallerResolver
}

var _ services.RunbookServiceServer = (*GRPCService)(nil)

// NewGRPCService requires both dependencies (fail closed).
func NewGRPCService(svc *Service, callers CallerResolver) (*GRPCService, error) {
	if svc == nil || callers == nil {
		return nil, errors.New("runbooks: service and caller resolver are required")
	}
	return &GRPCService{svc: svc, callers: callers}, nil
}

func grpcErr(err error) error {
	switch {
	case errors.Is(err, ErrForbidden), errors.Is(err, ErrNotFound):
		// Not found is reported as forbidden so existence is not leaked.
		return status.Error(codes.PermissionDenied, "forbidden")
	case errors.Is(err, ErrInvalid):
		return status.Error(codes.InvalidArgument, "invalid request")
	case errors.Is(err, ErrConflict):
		return status.Error(codes.Aborted, "conflict")
	default:
		return status.Error(codes.Internal, "internal error")
	}
}

func (g *GRPCService) caller(ctx context.Context) (Caller, error) {
	c, err := g.callers.Caller(ctx)
	if err != nil {
		return Caller{}, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	return c, nil
}

// toPB converts a stored definition. The script body is never part of a
// StoredDefinition, so it cannot be returned.
func toPB(d runbook.StoredDefinition) *pb.Runbook {
	out := &pb.Runbook{
		Id: d.Id, ScopeId: d.ScopeId, Name: d.Name, Description: d.Description,
		Interpreter: d.Interpreter, CommitSha: d.SourceCommitSHA, ScriptPath: d.ScriptPath,
		ScriptSha256: d.ScriptSHA256, Version: d.Version,
		Selector: &pb.RunbookTargetSelector{
			AllTargets: d.Selector.AllTargets, TargetIds: append([]string(nil), d.Selector.TargetIDs...),
			ScopeIds: append([]string(nil), d.Selector.ScopeIDs...),
		},
	}
	for _, p := range d.Parameters {
		out.Parameters = append(out.Parameters, &pb.RunbookParameter{
			Name: p.Name, Type: string(p.Type), Regex: p.Regex,
			AllowedValues: append([]string(nil), p.AllowedValues...), Min: p.Min, Max: p.Max,
			MaxLength: uint32(max(p.MaxLength, 0)), Required: p.Required,
			Default: p.Default, HasDefault: p.HasDefault,
		})
	}
	return out
}

// GetRunbook implements services.RunbookServiceServer.
func (g *GRPCService) GetRunbook(ctx context.Context, req *services.GetRunbookRequest) (*services.GetRunbookResponse, error) {
	c, err := g.caller(ctx)
	if err != nil {
		return nil, err
	}
	d, err := g.svc.Get(ctx, c, req.GetId())
	if err != nil {
		return nil, grpcErr(err)
	}
	return &services.GetRunbookResponse{Item: toPB(d)}, nil
}

// ListRunbooks lists one scope; recursive listing is not supported.
func (g *GRPCService) ListRunbooks(ctx context.Context, req *services.ListRunbooksRequest) (*services.ListRunbooksResponse, error) {
	if req.GetScopeId() == "" || req.GetRecursive() {
		return nil, status.Error(codes.InvalidArgument, "a single scope id is required")
	}
	c, err := g.caller(ctx)
	if err != nil {
		return nil, err
	}
	ds, err := g.svc.List(ctx, c, req.GetScopeId())
	if err != nil {
		return nil, grpcErr(err)
	}
	out := &services.ListRunbooksResponse{ResponseType: "complete"}
	for _, d := range ds {
		out.Items = append(out.Items, toPB(d))
	}
	return out, nil
}

// DeleteRunbook implements services.RunbookServiceServer.
func (g *GRPCService) DeleteRunbook(ctx context.Context, req *services.DeleteRunbookRequest) (*services.DeleteRunbookResponse, error) {
	c, err := g.caller(ctx)
	if err != nil {
		return nil, err
	}
	if err := g.svc.Delete(ctx, c, req.GetId()); err != nil {
		return nil, grpcErr(err)
	}
	return &services.DeleteRunbookResponse{}, nil
}
